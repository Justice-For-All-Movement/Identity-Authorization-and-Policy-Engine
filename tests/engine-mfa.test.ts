// Two-factor sign-in (TOTP, RFC 6238) on real PostgreSQL.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hotp, base32Decode, totp, verifyTotp, STEP_SECONDS } from '../src/engine/mfa.ts';
import { code, needsPg, PASSWORD, withWorld } from './engine-fixture.ts';

test('RFC 6238 reference values (SHA-1, 8-digit vectors truncated to 6) and replay protection', () => {
  // RFC 6238 appendix B key "12345678901234567890"; 6-digit codes are the last six digits of the published 8-digit ones.
  const key = Buffer.from('12345678901234567890');
  assert.equal(hotp(key, Math.floor(59 / STEP_SECONDS)), '287082');
  assert.equal(hotp(key, Math.floor(1111111109 / STEP_SECONDS)), '081804');
  assert.equal(hotp(key, Math.floor(2000000000 / STEP_SECONDS)), '279037');
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // base32 of the same key
  assert.deepEqual(base32Decode(secret), key);
  const at = new Date(1111111109 * 1000), c = totp(secret, at);
  assert.equal(c, '081804');
  const step = verifyTotp(secret, c, at, 0);
  assert.ok(step !== null);
  assert.equal(verifyTotp(secret, c, at, step), null, 'a used step is refused');
  assert.equal(verifyTotp(secret, '000000', at, 0), null);
  assert.equal(verifyTotp(secret, 'abc', at, 0), null);
});

test('enrol, confirm, sign in with a code; replay refused; recovery code works once; disable; admin reset', needsPg, async () => {
  let now = Date.now() - 150_000; // advanced by steps below, never past real time (tokens must not be issued in the future)
  const at = () => new Date(now);
  await withWorld(async ({ engine, ctx, owner, admin, user }) => {
    const bea = await user('bea@example.org', ['investigator']);
    const me = await ctx(bea.session, 'research');
    // Accounts without two-factor sign in exactly as before.
    await engine.login({ login: 'bea@example.org', password: PASSWORD });
    assert.deepEqual(await engine.mfaStatus(me), { enabled: false, pending: false, recoveryCodesLeft: 0 });

    const { secret, otpauthUri } = await engine.beginMfaEnrollment(me);
    assert.match(otpauthUri, /^otpauth:\/\/totp\/.*bea%40example\.org\?secret=[A-Z2-7]+&issuer=/);
    assert.deepEqual(await engine.mfaStatus(me), { enabled: false, pending: true, recoveryCodesLeft: 0 });
    // Pending enrolment does not change sign-in.
    await engine.login({ login: 'bea@example.org', password: PASSWORD });
    await assert.rejects(engine.confirmMfaEnrollment(me, { code: '000000' }), code('unauthenticated'));
    const { recoveryCodes } = await engine.confirmMfaEnrollment(me, { code: totp(secret, at()) });
    assert.equal(recoveryCodes.length, 10);
    await assert.rejects(engine.beginMfaEnrollment(me), code('invalid_state'));

    // Password alone is no longer enough; a wrong password still says nothing about two-factor.
    await assert.rejects(engine.login({ login: 'bea@example.org', password: PASSWORD }), code('invalid_mfa_required'));
    await assert.rejects(engine.login({ login: 'bea@example.org', password: 'wrong password!' }), code('unauthenticated'));
    await assert.rejects(engine.login({ login: 'bea@example.org', password: PASSWORD, code: '123456' }), code('unauthenticated'));
    now += STEP_SECONDS * 1000;
    const c1 = totp(secret, at());
    const s1 = await engine.login({ login: 'bea@example.org', password: PASSWORD, code: c1 });
    assert.ok(s1.refreshToken);
    await assert.rejects(engine.login({ login: 'bea@example.org', password: PASSWORD, code: c1 }), code('unauthenticated'), 'the same code cannot be used twice');

    const rc = recoveryCodes[0] as string;
    await engine.login({ login: 'bea@example.org', password: PASSWORD, recoveryCode: rc.toUpperCase() });
    await assert.rejects(engine.login({ login: 'bea@example.org', password: PASSWORD, recoveryCode: rc }), code('unauthenticated'), 'a recovery code works once');
    assert.equal((await engine.mfaStatus(me)).recoveryCodesLeft, 9);

    // Only the account holder manages their own enrolment; agents cannot.
    await assert.rejects(engine.beginMfaEnrollment({ ...me, actor: { ...me.actor, kind: 'agent' } }), code('forbidden'));
    await assert.rejects(engine.disableMfa(me, { code: '000000' }), code('unauthenticated'));
    now += STEP_SECONDS * 1000;
    await engine.disableMfa(me, { code: totp(secret, at()) });
    await engine.login({ login: 'bea@example.org', password: PASSWORD });

    // Lost device: an administrator resets it; a non-administrator cannot.
    const again = await engine.beginMfaEnrollment(me);
    await engine.confirmMfaEnrollment(me, { code: totp(again.secret, at()) });
    await assert.rejects(engine.resetMfa(me, bea.id), code('forbidden'));
    await assert.rejects(engine.resetMfa(await admin(), 'no-such-actor'), code('not_found'));
    await engine.resetMfa(await admin(), bea.id);
    await engine.login({ login: 'bea@example.org', password: PASSWORD });
    assert.ok(owner.refreshToken);
  }, { clock: () => new Date(now) });
});
