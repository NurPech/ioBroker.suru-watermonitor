import 'mocha';
import { expect } from 'chai';
import { AWSSRP, formatTimestamp, padHex } from './aws-srp';

const POOL = 'eu-central-1_8hkX7Bvjh';
const CHALLENGE = {
    USER_ID_FOR_SRP: 'uid-1',
    SALT: 'a1b2c3d4',
    SRP_B: 'ff'.repeat(64),
    SECRET_BLOCK: 'c2VjcmV0',
};

function fixedSrp(password: string): AWSSRP {
    const srp = new AWSSRP('u@example.com', password, POOL);
    srp.smallA = 0x12345n;
    srp.calculateA();
    return srp;
}

describe('aws-srp', () => {
    it('formats timestamps locale-independent with unpadded day', () => {
        expect(formatTimestamp(new Date(Date.UTC(2025, 0, 5, 3, 4, 9)))).to.equal('Sun Jan 5 03:04:09 UTC 2025');
        expect(formatTimestamp(new Date(Date.UTC(2026, 5, 25, 12, 0, 1)))).to.equal('Thu Jun 25 12:00:01 UTC 2026');
    });

    it('pads hex like the reference implementation', () => {
        expect(padHex('abc')).to.equal('0abc');
        expect(padHex('ab')).to.equal('00ab');
        expect(padHex('7f')).to.equal('7f');
    });

    it('builds auth parameters', () => {
        const params = new AWSSRP('u@example.com', 'pw', POOL).getAuthParameters();
        expect(params.USERNAME).to.equal('u@example.com');
        expect(params.SRP_A.length).to.be.greaterThan(100);
    });

    it('builds a deterministic challenge response that depends on the password', () => {
        const now = new Date(Date.UTC(2026, 5, 25, 12, 0, 1));
        const res = fixedSrp('Secret1!').processChallenge(CHALLENGE, now);
        expect(res.USERNAME).to.equal('uid-1');
        expect(res.PASSWORD_CLAIM_SECRET_BLOCK).to.equal('c2VjcmV0');
        expect(res.TIMESTAMP).to.equal('Thu Jun 25 12:00:01 UTC 2026');
        expect(fixedSrp('Secret1!').processChallenge(CHALLENGE, now)).to.deep.equal(res);
        expect(fixedSrp('Other1!').processChallenge(CHALLENGE, now).PASSWORD_CLAIM_SIGNATURE).to.not.equal(
            res.PASSWORD_CLAIM_SIGNATURE,
        );
    });
});
