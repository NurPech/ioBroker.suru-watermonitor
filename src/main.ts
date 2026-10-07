/*
 * Created with @iobroker/create-adapter v3.1.5
 */

import * as utils from '@iobroker/adapter-core';
import { DEFAULT_SCAN_INTERVAL_MINUTES, MAX_SCAN_INTERVAL_MINUTES, MIN_SCAN_INTERVAL_MINUTES } from './lib/constants';
import { SuruApiError, SuruAuthError, SuruWaterApi, type SuruIncidents } from './lib/suru-api';

const ACTIVE_STATES = new Set(['OPEN', 'CONFIRMED']);
const INCIDENT_KEYS = ['highFlow', 'continuousWaterFlow', 'temperature', 'lowFlow'];

type StateDef = Pick<ioBroker.StateCommon, 'name' | 'type' | 'role' | 'unit'>;

const STATES: Record<string, StateDef> = {
    meterReading: { name: 'Meter reading', type: 'number', role: 'value.volume', unit: 'm³' },
    consumptionToday: { name: 'Consumption today', type: 'number', role: 'value', unit: 'l' },
    waterHardness: { name: 'Water hardness', type: 'number', role: 'value', unit: '°dH' },
    phValue: { name: 'pH value', type: 'number', role: 'value' },
    lastMeasured: { name: 'Last measured', type: 'number', role: 'date' },
    alarm: { name: 'Alarm active', type: 'boolean', role: 'indicator.alarm' },
    activeIncidents: { name: 'Active incidents', type: 'string', role: 'json' },
};

function activeIncidents(incidents: SuruIncidents | null): string[] {
    const map = incidents?.incidents ?? {};
    return INCIDENT_KEYS.filter(key => ACTIVE_STATES.has(map[key]?.state ?? ''));
}

class SuruWatermonitor extends utils.Adapter {
    private api: SuruWaterApi | null = null;
    private pollRunning = false;

    public constructor(options: Partial<utils.AdapterOptions> = {}) {
        super({
            ...options,
            name: 'suru-watermonitor',
        });
        this.on('ready', this.onReady.bind(this));
        this.on('unload', this.onUnload.bind(this));
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    private async onReady(): Promise<void> {
        await this.setState('info.connection', false, true);

        if (!this.config.email || !this.config.password) {
            this.log.error('E-mail and password must be configured');
            return;
        }

        const minutes = Math.min(
            Math.max(Number(this.config.interval) || DEFAULT_SCAN_INTERVAL_MINUTES, MIN_SCAN_INTERVAL_MINUTES),
            MAX_SCAN_INTERVAL_MINUTES,
        );
        this.api = new SuruWaterApi(this.config.email, this.config.password);

        await this.poll();
        this.setInterval(() => void this.poll(), minutes * 60_000);
    }

    /** Fetch all units and write their states. Never throws. */
    private async poll(): Promise<void> {
        if (!this.api || this.pollRunning) {
            return;
        }
        this.pollRunning = true;
        try {
            const units = await this.api.getUnits();
            for (const unit of units) {
                if (unit.id) {
                    await this.updateUnit(this.api, unit.id);
                }
            }
            await this.setState('info.connection', true, true);
        } catch (err) {
            await this.setState('info.connection', false, true);
            if (err instanceof SuruAuthError) {
                this.log.error(`Authentication failed, check e-mail and password: ${err.message}`);
            } else if (err instanceof SuruApiError) {
                this.log.warn(`Update failed: ${err.message}`);
            } else {
                this.log.error(`Unexpected error: ${(err as Error).message}`);
            }
        } finally {
            this.pollRunning = false;
        }
    }

    private async updateUnit(api: SuruWaterApi, unitId: string): Promise<void> {
        const detail = await api.getUnit(unitId);
        const reading = await api.getReading(unitId);
        const consumption = await api.getConsumption(unitId, 'day');
        const values = (consumption.values ?? []).filter((v): v is number => v !== null && v !== undefined);

        const deviceId = detail.devices?.[0]?.id;
        let incidents: SuruIncidents | null = null;
        try {
            incidents = await api.getIncidents(unitId, deviceId);
        } catch (err) {
            if (!(err instanceof SuruApiError)) {
                throw err;
            }
            this.log.debug(`Incidents unavailable for ${unitId}: ${err.message}`);
        }

        const address = detail.address ?? {};
        const label = [address.streetName, address.streetNumber].filter(Boolean).join(' ');
        const channel = unitId.replace(this.FORBIDDEN_CHARS, '_');
        await this.extendObject(channel, {
            type: 'device',
            common: { name: `SURU WaterMonitor ${label}`.trim() },
            native: { id: unitId, serialNumber: detail.serialNumber, meterType: detail.devices?.[0]?.meterType },
        });

        const measuredAt = reading.measuredAt ? Date.parse(reading.measuredAt) : NaN;
        const alarm = incidents ? !!incidents.basicAlarm?.active || activeIncidents(incidents).length > 0 : null;

        const newValues: Record<string, ioBroker.StateValue> = {
            meterReading: reading.reading ?? null,
            consumptionToday: values.length ? values.reduce((a, b) => a + b, 0) : null,
            waterHardness: detail.waterProperties?.waterHardness ?? null,
            phValue: detail.waterProperties?.phValue ?? null,
            lastMeasured: Number.isNaN(measuredAt) ? null : measuredAt,
            alarm,
            activeIncidents: incidents ? JSON.stringify(activeIncidents(incidents)) : null,
        };

        for (const [key, def] of Object.entries(STATES)) {
            const id = `${channel}.${key}`;
            await this.extendObject(id, {
                type: 'state',
                common: { ...def, read: true, write: false },
                native: {},
            });
            await this.setState(id, newValues[key], true);
        }
    }

    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     *
     * @param callback - Callback function
     */
    private onUnload(callback: () => void): void {
        try {
            // timers created with this.setInterval are cleared by adapter-core
            callback();
        } catch (error) {
            this.log.error(`Error during unloading: ${(error as Error).message}`);
            callback();
        }
    }
}
if (require.main !== module) {
    // Export the constructor in compact mode
    module.exports = (options: Partial<utils.AdapterOptions> | undefined) => new SuruWatermonitor(options);
} else {
    // otherwise start the instance directly
    (() => new SuruWatermonitor())();
}
