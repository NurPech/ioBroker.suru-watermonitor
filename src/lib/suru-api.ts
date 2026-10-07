/**
 * Async client for the SURU WaterMonitor cloud API.
 *
 * Auth is AWS Cognito USER_SRP_AUTH (no client secret) -> JWT access token, sent as
 * `Authorization: Bearer <access_token>` to the API Gateway (like the Android app).
 */
import { AWSSRP, type ChallengeParameters } from './aws-srp';
import { API_BASE, COGNITO_CLIENT_ID, COGNITO_IDP_URL, COGNITO_POOL_ID } from './constants';

const AMZ_JSON = 'application/x-amz-json-1.1';

export class SuruError extends Error {}
/** Invalid credentials or auth flow failure. */
export class SuruAuthError extends SuruError {}
/** Non-auth API error. */
export class SuruApiError extends SuruError {}

export interface SuruDevice {
    id?: string;
    meterType?: string;
}

export interface SuruUnitDetail {
    id?: string;
    serialNumber?: string;
    address?: { streetName?: string; streetNumber?: string };
    devices?: SuruDevice[];
    waterProperties?: { waterHardness?: number; phValue?: number };
}

export interface SuruReading {
    reading?: number;
    measuredAt?: string;
}

export interface SuruConsumption {
    values?: (number | null)[];
}

export interface SuruIncidents {
    basicAlarm?: { active?: boolean };
    incidents?: Record<string, { state?: string } | undefined>;
}

type Fetch = typeof fetch;

export class SuruWaterApi {
    private accessToken: string | null = null;
    private expiresAt = 0;

    public constructor(
        private readonly email: string,
        private readonly password: string,
        private readonly fetchFn: Fetch = fetch,
    ) {}

    // -- Cognito auth -------------------------------------------------------

    private async cognito<T>(target: string, body: unknown): Promise<T> {
        let resp: Response;
        try {
            resp = await this.fetchFn(COGNITO_IDP_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': AMZ_JSON,
                    'X-Amz-Target': `AWSCognitoIdentityProviderService.${target}`,
                },
                body: JSON.stringify(body),
            });
        } catch (err) {
            throw new SuruApiError(`Cognito request failed: ${(err as Error).message}`);
        }
        const payload = (await resp.json().catch(() => null)) as Record<string, string> | null;
        if (resp.status !== 200) {
            const errType = payload?.__type ?? '';
            const msg = payload?.message ?? JSON.stringify(payload);
            if (['NotAuthorized', 'UserNotFound', 'InvalidParameter'].some(t => errType.includes(t))) {
                throw new SuruAuthError(`${errType}: ${msg}`);
            }
            throw new SuruApiError(`${errType}: ${msg}`);
        }
        return payload as T;
    }

    /** Full SRP login -> access token. */
    public async login(): Promise<void> {
        const srp = new AWSSRP(this.email, this.password, COGNITO_POOL_ID);
        const init = await this.cognito<{ ChallengeName?: string; ChallengeParameters: ChallengeParameters }>(
            'InitiateAuth',
            {
                AuthFlow: 'USER_SRP_AUTH',
                ClientId: COGNITO_CLIENT_ID,
                AuthParameters: srp.getAuthParameters(),
            },
        );
        if (init.ChallengeName !== 'PASSWORD_VERIFIER') {
            throw new SuruAuthError(`Unexpected challenge: ${init.ChallengeName}`);
        }
        const result = await this.cognito<{ AuthenticationResult?: { AccessToken?: string; ExpiresIn?: number } }>(
            'RespondToAuthChallenge',
            {
                ChallengeName: 'PASSWORD_VERIFIER',
                ClientId: COGNITO_CLIENT_ID,
                ChallengeResponses: srp.processChallenge(init.ChallengeParameters),
            },
        );
        const auth = result.AuthenticationResult ?? {};
        if (!auth.AccessToken) {
            throw new SuruAuthError('No AccessToken in Cognito response');
        }
        this.accessToken = auth.AccessToken;
        this.expiresAt = Date.now() + (auth.ExpiresIn ?? 3600) * 1000;
    }

    private async token(): Promise<string> {
        // Access tokens live ~1h. The pool rejects refresh-token rotation, so we
        // just repeat the (cheap) SRP login when the token is about to expire.
        if (!this.accessToken || Date.now() >= this.expiresAt - 60_000) {
            await this.login();
        }
        return this.accessToken as string;
    }

    // -- API ----------------------------------------------------------------

    private async get<T>(path: string, params?: Record<string, string>): Promise<T> {
        const token = await this.token();
        const url = new URL(`${API_BASE}/${path.replace(/^\//, '')}`);
        for (const [k, v] of Object.entries(params ?? {})) {
            url.searchParams.set(k, v);
        }
        let resp: Response;
        try {
            resp = await this.fetchFn(url, {
                headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
            });
        } catch (err) {
            throw new SuruApiError(`GET ${path} failed: ${(err as Error).message}`);
        }
        if (resp.status === 401) {
            this.accessToken = null;
            throw new SuruAuthError('API returned 401 (token rejected)');
        }
        const text = await resp.text();
        if (resp.status !== 200) {
            throw new SuruApiError(`GET ${path} -> HTTP ${resp.status}: ${text.slice(0, 200)}`);
        }
        return (text ? JSON.parse(text) : {}) as T;
    }

    public async getUnits(): Promise<{ id?: string }[]> {
        const data = await this.get<{ units?: { id?: string }[] }>('units');
        return data.units ?? [];
    }

    public getUnit(unitId: string): Promise<SuruUnitDetail> {
        return this.get(`units/${unitId}`);
    }

    public getReading(unitId: string): Promise<SuruReading> {
        // `date` is mandatory (API returns HTTP 400 without it).
        const now = `${new Date().toISOString().slice(0, 19)}Z`;
        return this.get(`units/${unitId}/reading`, { date: now });
    }

    public getConsumption(unitId: string, range = 'day'): Promise<SuruConsumption> {
        const start = new Date();
        start.setUTCHours(0, 0, 0, 0);
        return this.get(`units/${unitId}/consumption`, {
            range,
            startDate: `${start.toISOString().slice(0, 19)}Z`,
        });
    }

    public getIncidents(unitId: string, deviceId?: string): Promise<SuruIncidents> {
        return this.get(`units/${unitId}/incidents`, deviceId ? { deviceId } : undefined);
    }
}
