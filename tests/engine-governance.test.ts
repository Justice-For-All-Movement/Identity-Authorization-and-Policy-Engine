// Policy inspector views, redacted projections, rate limits, invitations, password reset, required two-factor
// sign-in and database row policies, on real PostgreSQL. Fictional people and organizations only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { totp } from '../src/engine/mfa.ts';
import { portsFromEnv } from '../src/engine/serve.ts';
import { SECRET_TABLES, TENANT_SETTING } from '../src/engine/index.ts';
import type { PasswordResetMessage } from '../src/engine/index.ts';
import { code, needsPg, PASSWORD, withWorld } from './engine-fixture.ts';

const NEW_PASSWORD = 'a different long passphrase';
const waitFor = async <T>(read: () => T | undefined, timeoutMs = 5000): Promise<T> => {
  const until = Date.now() + timeoutMs;
  for (;;) { const v = read(); if (v !== undefined) return v; if (Date.now() > until) throw new Error('timed out'); await new Promise((r) => setTimeout(r, 20)); }
};

test('who can access, revocation impact and field-level redacted projections', needsPg, async () => {
  await withWorld(async ({ engine, ctx, admin, user, ownerId, sql }) => {
    const ivy = await user('ivy@example.org', ['investigator']);
    const cal = await user('cal@example.org', ['correspondent']);
    const pia = await user('pia@example.org', ['participant_support']);
    const a = await admin();
    // Who can read evidence for research: investigator, correspondent (read role) and owner; not participant support.
    const who = await engine.whoCanAccess(a, { capability: 'evidence:read', purpose: 'research' });
    const ids = who.allowed.map((h) => h.actorId).sort();
    assert.deepEqual(ids, [ivy.id, cal.id, ownerId].sort());
    assert.equal(who.evaluated, 4); assert.equal(who.deniedCount, 1); assert.equal(who.truncated, false);
    assert.deepEqual((await engine.whoCanAccess(a, { capability: 'evidence:write', purpose: 'research' })).allowed.map((h) => h.actorId).sort(), [ivy.id, ownerId].sort());
    assert.equal(who.allowed.find((h) => h.actorId === ivy.id)?.via?.kind, 'role');
    // Sensitive: nobody holds intake:disclose_identity for research (the purpose excludes it), only support for its purpose.
    assert.deepEqual((await engine.whoCanAccess(a, { capability: 'intake:disclose_identity', purpose: 'research' })).allowed, []);
    assert.deepEqual((await engine.whoCanAccess(a, { capability: 'intake:disclose_identity', purpose: 'participant_support' })).allowed.map((h) => h.actorId), [pia.id]);
    // A non-administrator sees only its own project; another project is indistinguishable from a missing one.
    const ivyCtx = await ctx(ivy.session, 'research');
    assert.equal((await engine.whoCanAccess(ivyCtx, { capability: 'evidence:read' })).allowed.length, 3);
    await assert.rejects(engine.whoCanAccess(ivyCtx, { capability: 'evidence:read', projectId: 'elsewhere' }), code('not_found'));
    await assert.rejects(engine.whoCanAccess(ivyCtx, { capability: 'evidence:*' }), code('invalid_input'));
    await assert.rejects(engine.whoCanAccess(await ctx(cal.session, 'correspondence', { capabilities: ['correspondence:send'] }), { capability: 'evidence:read' }), code('forbidden'));

    // Revocation impact: read-only, nothing changes.
    const pvBefore = (await engine.getOrganization(a)).policyVersion;
    const roleImpact = await engine.revocationImpact(a, { role: 'investigator' }) as { holders: { actorId: string; loses: string[] }[] };
    assert.deepEqual(roleImpact.holders.map((x) => x.actorId), [ivy.id]);
    assert.ok(roleImpact.holders[0]?.loses.includes('evidence:*'));
    const actorImpact = await engine.revocationImpact(a, { actorId: cal.id }) as { activeSessions: number; revokeAndDisable: { accountDisabled: boolean } };
    assert.equal(actorImpact.activeSessions, 1); assert.equal(actorImpact.revokeAndDisable.accountDisabled, true);
    const grant = await engine.createGrant(a, { actorId: cal.id, capability: 'evidence:export', purpose: 'correspondence', reason: 'one export', expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    assert.deepEqual(await engine.revocationImpact(a, { grantId: grant.id }), { kind: 'grant', grantId: grant.id, actorId: cal.id, capability: 'evidence:export', purpose: 'correspondence', active: true, granteeRetainsByRole: false });
    await assert.rejects(engine.revocationImpact(a, { role: 'investigator', actorId: cal.id }), code('invalid_input'));
    await assert.rejects(engine.revocationImpact(a, { role: 'no_such_role' }), code('not_found'));
    // The owner's sessions are not visible to a non-administrator.
    assert.equal((await engine.revocationImpact(ivyCtx, { actorId: ivy.id }) as { activeSessions: number | null }).activeSessions, null);
    assert.equal((await engine.getOrganization(a)).policyVersion, (BigInt(pvBefore) + 1n).toString(), 'only the grant changed the policy version');

    // Redacted projection for the caller (token-bound) and a preview for another actor.
    const record = { title: 'Water permit timeline', narrative: 'Three filings, two missing.', reporterName: 'R. Example', internalNote: 'x' };
    const fields = { title: null, narrative: 'evidence:read', reporterName: 'intake:disclose_identity' };
    const mine = await engine.redact(ivyCtx, { record, fields });
    assert.deepEqual(mine.projection, { title: 'Water permit timeline', narrative: 'Three filings, two missing.' });
    assert.deepEqual(mine.withheld.map((w) => [w.field, w.reason]), [['reporterName', 'not_in_token'], ['internalNote', 'unclassified']]);
    const audited = await sql.query<{ action: string }>(`select action from e01_identity._audit where actor_id=$1 and action='access.denied'`, [ivy.id]);
    assert.equal(audited.length, 1, 'a withheld protected identity is an audited denial');
    const included = await engine.redact(ivyCtx, { record, fields, unclassified: 'include' });
    assert.equal(included.projection.internalNote, 'x');
    const preview = await engine.redact(a, { record, fields, actorId: pia.id, purpose: 'participant_support' });
    assert.deepEqual(Object.keys(preview.projection).sort(), ['reporterName', 'title']);
    await assert.rejects(engine.redact(await ctx(cal.session, 'correspondence', { capabilities: ['correspondence:send'] }), { record, fields, actorId: pia.id }), code('forbidden'));
    await assert.rejects(engine.redact(ivyCtx, { record, fields: { title: 'evidence:*' } }), code('invalid_input'));
    await assert.rejects(engine.redact(ivyCtx, { record: [] as never, fields }), code('invalid_input'));
  });
});

test('rate limits: atomic fixed windows per organization, subject and key', needsPg, async () => {
  let now = Date.now() - 120_000;
  await withWorld(async ({ engine, ctx, admin, user }) => {
    const ivy = await user('ivy@example.org', ['investigator']);
    const me = await ctx(ivy.session, 'research');
    const take = () => engine.consumeRateLimit(me, { key: 'correspondence:send', limit: 3, windowSeconds: 60 });
    assert.deepEqual([(await take()).remaining, (await take()).remaining, (await take()).remaining], [2, 1, 0]);
    const over = await take();
    assert.equal(over.allowed, false); assert.equal(over.used, 3);
    assert.equal((await engine.rateLimitStatus(me, { key: 'correspondence:send' }))?.used, 3);
    now += 61_000;
    assert.equal((await take()).allowed, true, 'a new window starts');
    // Concurrent consumers never exceed the limit.
    const results = await Promise.all(Array.from({ length: 12 }, () => engine.consumeRateLimit(me, { key: 'burst', limit: 5, windowSeconds: 60 })));
    assert.equal(results.filter((r) => r.allowed).length, 5);
    // Metering someone else needs a service identity or an administrator.
    await assert.rejects(engine.consumeRateLimit(me, { key: 'burst', limit: 5, windowSeconds: 60, subject: 'someone-else' }), code('forbidden'));
    const byAdmin = await engine.consumeRateLimit(await admin(), { key: 'burst', limit: 5, windowSeconds: 60, subject: ivy.id });
    assert.equal(byAdmin.allowed, false, 'the administrator meters the same bucket');
    for (const bad of [{ key: 'Bad Key', limit: 1, windowSeconds: 1 }, { key: 'k', limit: 0, windowSeconds: 1 }, { key: 'k', limit: 1, windowSeconds: 90000 }, { key: 'k', limit: 2, windowSeconds: 1, cost: 3 }])
      await assert.rejects(engine.consumeRateLimit(me, bad), code('invalid_input'));
  }, { clock: () => new Date(now) });
});

test('invitations: single use, current inviter authority, new or existing accounts', needsPg, async () => {
  await withWorld(async ({ engine, ctx, admin, owner, user }) => {
    const a = await admin();
    const { invitation, token } = await engine.createInvitation(a, { roles: ['investigator'], displayName: 'Nia Example' });
    assert.equal(invitation.state, 'pending');
    assert.doesNotMatch(JSON.stringify(await engine.listInvitations(a)), new RegExp(token));
    const joined = await engine.acceptInvitation({ token, login: 'nia@example.org', password: PASSWORD });
    assert.deepEqual([joined.tenantId, joined.projectId, joined.roles], ['org-a', 'main', ['investigator']]);
    assert.ok(joined.session !== null);
    const nia = await ctx(joined.session, 'research');
    assert.ok(nia.capabilities.includes('evidence:*'));
    await assert.rejects(engine.acceptInvitation({ token, login: 'again@example.org', password: PASSWORD }), code('unauthenticated'));
    assert.equal((await engine.listInvitations(a, { includeClosed: true }))[0]?.state, 'accepted');
    // Revoked and unknown tokens fail the same way.
    const second = await engine.createInvitation(a, { roles: ['editor'] });
    await engine.revokeInvitation(a, second.invitation.id);
    await assert.rejects(engine.acceptInvitation({ token: second.token, login: 'x1@example.org', password: PASSWORD }), code('unauthenticated'));
    await assert.rejects(engine.acceptInvitation({ token: 'not-a-token', login: 'x2@example.org', password: PASSWORD }), code('unauthenticated'));
    // An existing person joins another project with the same identity.
    await engine.createProject(a, { id: 'second', name: 'Second' });
    const cross = await engine.createInvitation(a, { projectId: 'second', roles: ['reviewer'] });
    const existing = await engine.acceptInvitation({ token: cross.token, refreshToken: joined.session.refreshToken });
    assert.equal(existing.actorId, joined.actorId); assert.equal(existing.session, null);
    assert.ok((await ctx(joined.session, 'workspace', { projectId: 'second' })).capabilities.includes('identity:read'));
    // Administrative roles: only an owner may invite; a non-owner administrator cannot.
    const adm = await user('adm@example.org', ['admin']);
    const admCtx = await ctx(adm.session, 'administration');
    await assert.rejects(engine.createInvitation(admCtx, { roles: ['admin'] }), code('forbidden'));
    await assert.rejects(engine.createInvitation(admCtx, { roles: ['agent_researcher'] }), code('invalid_input'));
    // The inviter's authority is re-checked at acceptance: a removed administrator's invitation fails.
    const pending = await engine.createInvitation(admCtx, { roles: ['producer'] });
    await engine.removeMember(await admin(), { actorId: adm.id });
    await assert.rejects(engine.acceptInvitation({ token: pending.token, login: 'late@example.org', password: PASSWORD }), code('forbidden'));
    await assert.rejects(engine.login({ login: 'late@example.org', password: PASSWORD }), code('unauthenticated'), 'nothing was created');
    await assert.rejects(engine.createInvitation(a, { roles: ['investigator'], expiresInSeconds: 10 }), code('invalid_input'));
    void owner;
  });
});

test('password reset through the delivery port: no enumeration, single use, sessions end, second factor kept', needsPg, async () => {
  const sent: PasswordResetMessage[] = [];
  let now = Date.now() - 2_400_000;
  await withWorld(async ({ engine, ctx, user }) => {
    const ivy = await user('ivy@example.org', ['investigator']);
    const bea = await user('bea@example.org', ['investigator']);
    assert.deepEqual(await engine.requestPasswordReset({ login: 'nobody@example.org' }), { accepted: true });
    assert.deepEqual(await engine.requestPasswordReset({ login: 'ivy@example.org' }), { accepted: true });
    const msg = await waitFor(() => sent.find((m) => m.login === 'ivy@example.org'));
    assert.equal(sent.length, 1, 'unknown logins deliver nothing');
    assert.equal(msg.actorId, ivy.id);
    await assert.rejects(engine.completePasswordReset({ token: msg.token, newPassword: 'short' }), code('invalid_input'));
    await engine.completePasswordReset({ token: msg.token, newPassword: NEW_PASSWORD });
    await assert.rejects(engine.completePasswordReset({ token: msg.token, newPassword: NEW_PASSWORD }), code('unauthenticated'));
    await assert.rejects(engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' }), code('unauthenticated'), 'existing sessions ended');
    await assert.rejects(engine.login({ login: 'ivy@example.org', password: PASSWORD }), code('unauthenticated'));
    await engine.login({ login: 'ivy@example.org', password: NEW_PASSWORD });
    // Expiry after 30 minutes.
    await engine.requestPasswordReset({ login: 'ivy@example.org' });
    const second = await waitFor(() => sent[1]);
    now += 31 * 60_000;
    await assert.rejects(engine.completePasswordReset({ token: second.token, newPassword: PASSWORD }), code('unauthenticated'));
    // Three requests an hour per login; further requests are accepted silently and deliver nothing.
    await engine.requestPasswordReset({ login: 'ivy@example.org' });
    await waitFor(() => sent[2]);
    assert.deepEqual(await engine.requestPasswordReset({ login: 'ivy@example.org' }), { accepted: true });
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(sent.length, 3);
    // With two-factor sign-in on, a reset also needs a current code.
    const me = await ctx(bea.session, 'research');
    const { secret } = await engine.beginMfaEnrollment(me);
    await engine.confirmMfaEnrollment(me, { code: totp(secret, new Date(now)) });
    now += 30_000;
    await engine.requestPasswordReset({ login: 'bea@example.org' });
    const third = await waitFor(() => sent[3]);
    await assert.rejects(engine.completePasswordReset({ token: third.token, newPassword: NEW_PASSWORD }), code('invalid_mfa_required'));
    await assert.rejects(engine.completePasswordReset({ token: third.token, newPassword: NEW_PASSWORD, code: '000000' }), code('unauthenticated'));
    await engine.completePasswordReset({ token: third.token, newPassword: NEW_PASSWORD, code: totp(secret, new Date(now)) });
    await assert.rejects(engine.login({ login: 'bea@example.org', password: NEW_PASSWORD }), code('invalid_mfa_required'));
  }, { clock: () => new Date(now), accessTokenTtlSeconds: 3600 }, { passwordResetDelivery: async (m) => { sent.push(m); } });
  // Without a delivery port the feature is unavailable rather than silently doing nothing.
  await withWorld(async ({ engine }) => { await assert.rejects(engine.requestPasswordReset({ login: 'ada@example.org' }), code('unavailable')); });
});

test('organization policy requiring two-factor sign-in: tokens carry nothing until enrolment', needsPg, async () => {
  let now = Date.now() - 300_000;
  await withWorld(async ({ engine, ctx, admin, user }) => {
    const ivy = await user('ivy@example.org', ['investigator']);
    await assert.rejects(engine.updateOrganization(await admin(), { policyConfig: { requireMfa: 'yes' } as never }), code('invalid_input'));
    await engine.updateOrganization(await admin(), { policyConfig: { requireMfa: true } });
    const restricted = await engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    assert.deepEqual(restricted.capabilities, []); assert.equal(restricted.restriction, 'mfa_enrollment_required');
    const me = await ctx(ivy.session, 'research');
    assert.equal((await engine.authorize(me, { capability: 'evidence:read' })).allowed, false);
    const { secret } = await engine.beginMfaEnrollment(me);
    await engine.confirmMfaEnrollment(me, { code: totp(secret, new Date(now)) });
    const full = await engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    assert.ok(full.capabilities.includes('evidence:*')); assert.equal(full.restriction, undefined);
  }, { clock: () => new Date(now) });
});

test('database row policies isolate organizations for every role other than the owning service', needsPg, async () => {
  await withWorld(async ({ engine, admin, sql }) => {
    await engine.createOrganization(await admin(), { id: 'org-b', name: 'Birch Group', owner: { login: 'bo@example.org', password: PASSWORD, displayName: 'Bo Example' } });
    const role = `e01_rls_probe_${Math.random().toString(36).slice(2, 10)}`;
    await sql.query(`create role ${role} nologin`);
    try {
      await sql.query(`grant usage on schema e01_identity to ${role}; grant select, insert on all tables in schema e01_identity to ${role}`);
      const asReader = (tenant: string | null, statement: string): Promise<Record<string, unknown>[]> => sql.tx(async (tx) => {
        if (tenant !== null) await tx.query(`select set_config('${TENANT_SETTING}', $1, true)`, [tenant]);
        await tx.query(`set local role ${role}`);
        return tx.query(statement);
      });
      // The owning service still sees both organizations.
      assert.equal((await sql.query(`select id from e01_identity.organizations`)).length, 2);
      // Unscoped: nothing at all.
      for (const t of ['organizations', 'projects', 'memberships', 'roles', 'actors', '_audit', '_events'])
        assert.equal((await asReader(null, `select 1 from e01_identity.${t}`)).length, 0, t);
      // Scoped: only that organization's rows.
      assert.deepEqual((await asReader('org-b', `select id from e01_identity.organizations`)).map((r) => r.id), ['org-b']);
      assert.deepEqual([...new Set((await asReader('org-b', `select tenant_id from e01_identity.memberships`)).map((r) => r.tenant_id))], ['org-b']);
      assert.ok((await asReader('org-a', `select tenant_id from e01_identity._audit`)).every((r) => r.tenant_id === 'org-a'));
      assert.deepEqual((await asReader('org-b', `select display_name from e01_identity.actors`)).map((r) => r.display_name), ['Bo Example']);
      // Credentials, sessions, keys and sealed secrets are never visible, scoped or not.
      for (const t of SECRET_TABLES) assert.equal((await asReader('org-a', `select 1 from e01_identity.${t}`)).length, 0, t);
      // Writes into another organization are refused by the policy's check.
      await assert.rejects(asReader('org-a', `insert into e01_identity.purposes (tenant_id, name, capabilities, updated_at, updated_by) values ('org-b', 'x', '{}', now(), 'probe')`), /row-level security/);
    } finally {
      await sql.query(`drop owned by ${role}`); await sql.query(`drop role ${role}`);
    }
  });
});

test('password-reset webhook port: configuration is validated and deliveries are signed', async () => {
  for (const env of [{ IDENTITY_PASSWORD_RESET_WEBHOOK_URL: 'https://mailer.example.org/hook' }, { IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET: 'x'.repeat(40) },
    { IDENTITY_PASSWORD_RESET_WEBHOOK_URL: 'http://mailer.example.org/hook', IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET: 'x'.repeat(40) },
    { IDENTITY_PASSWORD_RESET_WEBHOOK_URL: 'https://mailer.example.org/hook', IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET: 'short' }])
    assert.throws(() => portsFromEnv(env));
  assert.deepEqual(portsFromEnv({}), {});
  const secret = 'webhook-fixture-secret-0123456789abcdef';
  const received: { headers: Record<string, unknown>; body: string }[] = [];
  let status = 204;
  const server = createServer((req, res) => { let body = ''; req.on('data', (c) => { body += c; }); req.on('end', () => { received.push({ headers: req.headers, body }); res.writeHead(status).end(); }); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  try {
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`;
    const deliver = portsFromEnv({ IDENTITY_PASSWORD_RESET_WEBHOOK_URL: url, IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET: secret }).passwordResetDelivery;
    assert.ok(deliver !== undefined);
    const message: PasswordResetMessage = { type: 'password_reset', actorId: 'a1', login: 'ivy@example.org', token: 't0k3n', expiresAt: new Date().toISOString() };
    await deliver(message, AbortSignal.timeout(5000));
    const got = received[0];
    assert.ok(got !== undefined);
    assert.deepEqual(JSON.parse(got.body), message);
    const expected = createHmac('sha256', secret).update(`${String(got.headers['x-e01-timestamp'])}.${got.body}`).digest('hex');
    assert.equal(got.headers['x-e01-signature'], `sha256=${expected}`);
    status = 500;
    await assert.rejects(deliver(message, AbortSignal.timeout(5000)), /500/);
  } finally { await new Promise<void>((r) => server.close(() => r())); }
});
