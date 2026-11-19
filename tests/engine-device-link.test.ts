// Signing another device in with a one-time link (shown as a QR code). Real PostgreSQL.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { code, needsPg, PASSWORD, withWorld } from './engine-fixture.ts';

test('device link: one use, two minutes, a separate session, ends with the creating session, never another person', needsPg, async () => {
  let now = Date.now() - 600_000;
  await withWorld(async ({ engine, user }) => {
    const computer = await engine.login({ login: 'ada@example.org', password: PASSWORD });
    const link = await engine.createDeviceLink(computer.refreshToken);
    assert.match(link.token, /^[0-9a-f-]{36}\.[A-Za-z0-9_-]+$/);
    assert.equal(Date.parse(link.expiresAt) - now, 120_000);
    const phone = await engine.redeemDeviceLink(link.token);
    assert.notEqual(phone.sessionId, computer.sessionId, 'the phone gets its own session');
    assert.equal(phone.actorId, computer.actorId);
    await engine.issueAccessToken({ refreshToken: phone.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    await assert.rejects(engine.redeemDeviceLink(link.token), code('unauthenticated'), 'single use');
    await engine.logout(phone.refreshToken);
    await engine.sessionDirectory(computer.refreshToken); // signing the phone out leaves the computer signed in

    // Expiry.
    const late = await engine.createDeviceLink(computer.refreshToken);
    now += 121_000;
    await assert.rejects(engine.redeemDeviceLink(late.token), code('unauthenticated'), 'expired');
    // A tampered secret, garbage, and a link whose creating session has ended are refused.
    const fresh = await engine.createDeviceLink(computer.refreshToken);
    await assert.rejects(engine.redeemDeviceLink(`${fresh.token.split('.')[0]}.wrong`), code('unauthenticated'));
    await assert.rejects(engine.redeemDeviceLink('nonsense'), code('unauthenticated'));
    await engine.logout(computer.refreshToken);
    await assert.rejects(engine.redeemDeviceLink(fresh.token), code('unauthenticated'), 'signing out the computer voids its pending links');
    await assert.rejects(engine.createDeviceLink(computer.refreshToken), code('unauthenticated'));
    // Another person's link signs in only that person.
    const bea = await user('bea@example.org', ['investigator']);
    const theirs = await engine.redeemDeviceLink((await engine.createDeviceLink(bea.session.refreshToken)).token);
    assert.equal(theirs.actorId, bea.id);
  }, { clock: () => new Date(now) });
});
