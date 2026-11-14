// Refresh-token rotation and reuse detection on real PostgreSQL.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { code, needsPg, PASSWORD, withWorld } from './engine-fixture.ts';

test('rotation issues a new refresh token, retires the old one, and a later reuse ends the session', needsPg, async () => {
  let now = Date.parse('2026-06-01T10:00:00Z');
  await withWorld(async ({ engine }) => {
    const first = await engine.login({ login: 'ada@example.org', password: PASSWORD });
    const second = await engine.rotateSession(first.refreshToken);
    assert.equal(second.sessionId, first.sessionId, 'same session');
    assert.notEqual(second.refreshToken, first.refreshToken);
    assert.equal(second.expiresAt, first.expiresAt, 'rotation does not extend the absolute session lifetime');
    // The new token works; within the grace window the old one is refused without ending the session.
    await engine.issueAccessToken({ refreshToken: second.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    await assert.rejects(engine.issueAccessToken({ refreshToken: first.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' }), code('unauthenticated'));
    await engine.sessionDirectory(second.refreshToken);
    // After the grace window, presenting the retired token is treated as theft: the session ends for everyone.
    now += 60_000;
    await assert.rejects(engine.sessionDirectory(first.refreshToken), code('unauthenticated'));
    await assert.rejects(engine.sessionDirectory(second.refreshToken), code('unauthenticated'), 'the legitimate holder is signed out too');
    await assert.rejects(engine.rotateSession(second.refreshToken), code('unauthenticated'));
  }, { clock: () => new Date(now) });
});

test('chained rotations keep working; a rotated token cannot be rotated twice; logout still ends the session', needsPg, async () => {
  await withWorld(async ({ engine }) => {
    let s = await engine.login({ login: 'ada@example.org', password: PASSWORD });
    for (let i = 0; i < 3; i++) {
      const next = await engine.rotateSession(s.refreshToken);
      await assert.rejects(engine.rotateSession(s.refreshToken), code('unauthenticated'), 'the same token cannot mint two successors');
      s = next;
    }
    await engine.issueAccessToken({ refreshToken: s.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    await engine.logout(s.refreshToken);
    await assert.rejects(engine.sessionDirectory(s.refreshToken), code('unauthenticated'));
  });
});

test('a session that is never rotated behaves exactly as before', needsPg, async () => {
  await withWorld(async ({ engine }) => {
    const s = await engine.login({ login: 'ada@example.org', password: PASSWORD });
    for (let i = 0; i < 3; i++) await engine.issueAccessToken({ refreshToken: s.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    await engine.sessionDirectory(s.refreshToken);
  });
});
