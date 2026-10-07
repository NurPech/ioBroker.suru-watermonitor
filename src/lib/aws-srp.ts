/**
 * Self-contained AWS Cognito SRP (USER_SRP_AUTH) helper.
 *
 * Pure crypto math only - no network. The HTTP InitiateAuth /
 * RespondToAuthChallenge calls live in suru-api.ts.
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';

// RFC 3526 3072-bit MODP group - the N/g pair AWS Cognito uses for SRP.
const N_HEX =
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
    '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';
const G_HEX = '2';
const INFO_BITS = Buffer.from('Caldera Derived Key', 'utf8');

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function hashSha256(buf: Buffer): string {
    return createHash('sha256').update(buf).digest('hex');
}

function hexHash(hex: string): string {
    return hashSha256(Buffer.from(hex, 'hex'));
}

function hexToLong(hex: string): bigint {
    return BigInt(`0x${hex}`);
}

function longToHex(num: bigint): string {
    return num.toString(16);
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    let b = ((base % mod) + mod) % mod;
    let e = exp;
    while (e > 0n) {
        if (e & 1n) {
            result = (result * b) % mod;
        }
        e >>= 1n;
        b = (b * b) % mod;
    }
    return result;
}

/**
 * Pad a hex string so that it is interpreted as a positive, signed big-endian number.
 *
 * @param value Number or hex string
 */
export function padHex(value: bigint | string): string {
    let hex = typeof value === 'string' ? value : longToHex(value);
    if (hex.length % 2 === 1) {
        hex = `0${hex}`;
    } else if ('89ABCDEFabcdef'.includes(hex[0])) {
        hex = `00${hex}`;
    }
    return hex;
}

function computeHkdf(ikm: Buffer, salt: Buffer): Buffer {
    const prk = createHmac('sha256', salt).update(ikm).digest();
    const info = Buffer.concat([INFO_BITS, Buffer.from([1])]);
    return createHmac('sha256', prk).update(info).digest().subarray(0, 16);
}

function calculateU(bigA: bigint, bigB: bigint): bigint {
    return hexToLong(hexHash(padHex(bigA) + padHex(bigB)));
}

/**
 * Locale-independent 'Wed Jun 25 12:00:00 UTC 2026' (day NOT zero-padded).
 *
 * @param now Date (interpreted as UTC)
 */
export function formatTimestamp(now: Date): string {
    const p = (n: number): string => String(n).padStart(2, '0');
    return (
        `${WEEKDAYS[now.getUTCDay()]} ${MONTHS[now.getUTCMonth()]} ${now.getUTCDate()} ` +
        `${p(now.getUTCHours())}:${p(now.getUTCMinutes())}:${p(now.getUTCSeconds())} UTC ${now.getUTCFullYear()}`
    );
}

/** Parameters of the PASSWORD_VERIFIER challenge returned by InitiateAuth. */
export interface ChallengeParameters {
    /** User id to use for SRP (may differ from the login name) */
    USER_ID_FOR_SRP: string;
    /** Salt (hex) */
    SALT: string;
    /** Server public value B (hex) */
    SRP_B: string;
    /** Opaque secret block (base64) */
    SECRET_BLOCK: string;
}

/** Minimal Cognito SRP client (no MFA, no device tracking, no client secret). */
export class AWSSRP {
    public readonly bigN = hexToLong(N_HEX);
    public readonly g = hexToLong(G_HEX);
    public readonly k = hexToLong(hexHash(`00${N_HEX}0${G_HEX}`));
    public smallA: bigint;
    public largeA: bigint;

    /**
     * @param username Login name (e-mail)
     * @param password Password
     * @param poolId Cognito user pool id, e.g. `eu-central-1_xxxx`
     */
    public constructor(
        private readonly username: string,
        private readonly password: string,
        private readonly poolId: string,
    ) {
        this.smallA = hexToLong(randomBytes(128).toString('hex')) % this.bigN;
        this.largeA = this.calculateA();
    }

    /** Recompute A after smallA was replaced (used by tests). */
    public calculateA(): bigint {
        const bigA = modPow(this.g, this.smallA, this.bigN);
        if (bigA % this.bigN === 0n) {
            throw new Error('Safety check for A failed');
        }
        this.largeA = bigA;
        return bigA;
    }

    /** AuthParameters for the InitiateAuth (USER_SRP_AUTH) call. */
    public getAuthParameters(): { USERNAME: string; SRP_A: string } {
        return { USERNAME: this.username, SRP_A: longToHex(this.largeA) };
    }

    /**
     * Derive the HKDF key used to sign the challenge response.
     *
     * @param username User id for SRP
     * @param password Password
     * @param serverB Server public value B
     * @param salt Salt (hex)
     */
    public getPasswordAuthenticationKey(username: string, password: string, serverB: bigint, salt: string): Buffer {
        const u = calculateU(this.largeA, serverB);
        if (u === 0n) {
            throw new Error('U cannot be zero');
        }
        const poolName = this.poolId.split('_')[1];
        const usernamePasswordHash = hashSha256(Buffer.from(`${poolName}${username}:${password}`, 'utf8'));
        const x = hexToLong(hexHash(padHex(salt) + usernamePasswordHash));
        const gModPowX = modPow(this.g, x, this.bigN);
        const base = serverB - this.k * gModPowX;
        const s = modPow(base, this.smallA + u * x, this.bigN);
        return computeHkdf(Buffer.from(padHex(s), 'hex'), Buffer.from(padHex(longToHex(u)), 'hex'));
    }

    /**
     * Build ChallengeResponses for the PASSWORD_VERIFIER challenge.
     *
     * @param challenge Challenge parameters from InitiateAuth
     * @param now Timestamp override (tests)
     */
    public processChallenge(challenge: ChallengeParameters, now: Date = new Date()): Record<string, string> {
        const userId = challenge.USER_ID_FOR_SRP;
        const timestamp = formatTimestamp(now);
        const hkdf = this.getPasswordAuthenticationKey(
            userId,
            this.password,
            hexToLong(challenge.SRP_B),
            challenge.SALT,
        );
        const secretBlock = Buffer.from(challenge.SECRET_BLOCK, 'base64');
        const msg = Buffer.concat([
            Buffer.from(this.poolId.split('_')[1], 'utf8'),
            Buffer.from(userId, 'utf8'),
            secretBlock,
            Buffer.from(timestamp, 'utf8'),
        ]);
        const signature = createHmac('sha256', hkdf).update(msg).digest('base64');
        return {
            TIMESTAMP: timestamp,
            USERNAME: userId,
            PASSWORD_CLAIM_SECRET_BLOCK: challenge.SECRET_BLOCK,
            PASSWORD_CLAIM_SIGNATURE: signature,
        };
    }
}
