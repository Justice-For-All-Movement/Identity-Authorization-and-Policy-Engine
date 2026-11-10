import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { createTokenVerifier, hasCapability, withDisposableDatabase } from '../src/service-kit.ts';
import { start } from '../src/engine/serve.ts';
import { ADMIN_URL, PASSWORD, needsPg, settled } from './engine-fixture.ts';

test('HTTP API end to end with the standalone server', needsPg, async () => {
  await withDisposableDatabase(pg, ADMIN_URL, async (url) => {
    const served = await start({ DATABASE_URL: url, PORT: '0', IDENTITY_KEY_ENCRYPTION_KEY: 'http-fixture-key-encryption-key-0123456789', IDENTITY_BOOTSTRAP_TOKEN: 'http-bootstrap-token', IDENTITY_REVOCATION_CACHE_MS: '0', IDENTITY_ISSUER: 'identity.test' });
    const base = `http://127.0.0.1:${served.port}`;
    const call = async (method: string, path: string, body?: unknown, token?: string): Promise<{ status: number; json: any; text: string }> => {
      const res = await fetch(`${base}${path}`, { method, headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(token === undefined ? {} : { authorization: `Bearer ${token}` }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      const text = await res.text();
      let json: unknown = null; try { json = JSON.parse(text); } catch { /* not JSON */ }
      return { status: res.status, json, text };
    };
    try {
      assert.equal((await call('GET', '/healthz')).status, 200);
      assert.equal((await call('GET', '/v1/manifest')).json.id, 'E01');
      assert.deepEqual((await call('GET', '/v1/bootstrap')).json, { bootstrapped: false });
      // bootstrap: token required, then exactly once
      const boot = { login: 'ada@example.org', password: PASSWORD, displayName: 'Ada Example', organization: { id: 'org-a', name: 'Alder Collective', project: { id: 'main', name: 'Main' } } };
      assert.equal((await call('POST', '/v1/bootstrap', boot)).status, 403);
      assert.equal((await call('POST', '/v1/bootstrap', { ...boot, bootstrapToken: 'wrong' })).status, 403);
      const booted = await call('POST', '/v1/bootstrap', { ...boot, bootstrapToken: 'http-bootstrap-token' });
      assert.equal(booted.status, 200); assert.equal(booted.json.organization.id, 'org-a');
      assert.equal((await call('POST', '/v1/bootstrap', { ...boot, login: 'eve@example.org', bootstrapToken: 'http-bootstrap-token' })).status, 409);
      assert.deepEqual((await call('GET', '/v1/bootstrap')).json, { bootstrapped: true });
      // sign in, discover, exchange for a scoped access token
      const bad = await call('POST', '/v1/sessions', { login: 'ada@example.org', password: 'definitely not right' });
      assert.equal(bad.status, 401); assert.doesNotMatch(bad.text, /scrypt|password_hash|stack/);
      assert.equal((await call('POST', '/v1/sessions', 'not an object' as never)).status, 400);
      const session = (await call('POST', '/v1/sessions', { login: 'ada@example.org', password: PASSWORD })).json;
      const dir = (await call('POST', '/v1/sessions/directory', { refreshToken: session.refreshToken })).json;
      assert.equal(dir.organizations[0].organization.id, 'org-a');
      const tokenFor = async (refreshToken: string, purpose: string, tenantId = 'org-a') => (await call('POST', '/v1/tokens', { refreshToken, tenantId, projectId: 'main', purpose })).json.token as string;
      const admin = await tokenFor(session.refreshToken, 'administration');
      assert.equal((await call('POST', '/v1/tokens', { refreshToken: 'nope', tenantId: 'org-a', projectId: 'main', purpose: 'research' })).status, 401);
      // every protected route needs a bearer token
      for (const path of ['/v1/whoami', '/v1/members', '/v1/roles', '/v1/organization', '/v1/audit', '/v1/events', '/v1/search?q=a', '/v1/capability-grants', '/v1/export', '/v1/sessions'])
        assert.equal((await call('GET', path)).status, 401, path);
      assert.equal((await call('GET', '/v1/whoami', undefined, `${admin}x`)).status, 401);
      const me = (await call('GET', '/v1/whoami', undefined, admin)).json;
      assert.equal(me.actor.login, 'ada@example.org'); assert.equal(me.purpose, 'administration');
      // other engines verify our tokens offline with the published keys
      const keys = (await call('GET', '/v1/keys')).json;
      assert.equal(keys.issuer, 'identity.test');
      const offline = await createTokenVerifier({ publicKeys: keys.keys, issuer: keys.issuer })(admin, { requestId: 'offline' });
      assert.equal(offline.tenantId, 'org-a'); assert.ok(hasCapability(offline, 'identity:read') && offline.capabilities.includes('identity:admin'));
      assert.doesNotMatch(JSON.stringify(keys), /PRIVATE|"d":/);
      // directory administration
      const ivy = await call('POST', '/v1/users', { login: 'ivy@example.org', password: PASSWORD, displayName: 'Ivy Example', roles: ['investigator'] }, admin);
      assert.equal(ivy.status, 200);
      assert.equal((await call('POST', '/v1/users', { login: 'ivy@example.org', password: PASSWORD, displayName: 'Again' }, admin)).status, 409);
      assert.deepEqual((await call('GET', '/v1/members', undefined, admin)).json.map((m: any) => m.actor.login).sort(), ['ada@example.org', 'ivy@example.org']);
      assert.ok((await call('GET', '/v1/roles', undefined, admin)).json.some((r: any) => r.name === 'release_manager'));
      const ivySession = (await call('POST', '/v1/sessions', { login: 'ivy@example.org', password: PASSWORD })).json;
      const research = await tokenFor(ivySession.refreshToken, 'research');
      // decisions: POST /v1/policy/evaluate and GET /v1/access/explain
      assert.equal((await call('POST', '/v1/policy/evaluate', { capability: 'evidence:write' }, research)).json.allowed, true);
      const deniedSend = (await call('POST', '/v1/policy/evaluate', { capability: 'correspondence:send' }, research)).json;
      assert.equal(deniedSend.allowed, false); assert.equal(deniedSend.reason, 'not_in_token');
      const explained = (await call('GET', `/v1/access/explain?actorId=${ivy.json.id}&capability=release:publish&purpose=release`, undefined, admin)).json;
      assert.equal(explained.allowed, false); assert.ok(explained.trail.length >= 3);
      // non-administrators cannot administer
      assert.equal((await call('POST', '/v1/users', { login: 'x@example.org', password: PASSWORD, displayName: 'X' }, research)).status, 403);
      assert.equal((await call('PUT', '/v1/members', { actorId: ivy.json.id, roles: ['owner'], projectId: '*' }, research)).status, 403);
      assert.equal((await call('POST', '/v1/capability-grants', { actorId: ivy.json.id, capability: 'release:publish', purpose: 'release', reason: 'self', expiresAt: new Date(Date.now() + 60000).toISOString() }, research)).status, 403);
      assert.equal((await call('GET', '/v1/events', undefined, admin)).status, 403);
      // grants: POST /v1/capability-grants, POST /v1/grants/{id}/revoke
      const grant = await call('POST', '/v1/capability-grants', { actorId: ivy.json.id, capability: 'correspondence:send', purpose: 'correspondence', reason: 'Follow-up letters', bounds: { maxUses: 5 }, expiresAt: new Date(Date.now() + 3600000).toISOString() }, admin);
      assert.equal(grant.status, 200);
      const corr = await tokenFor(ivySession.refreshToken, 'correspondence');
      assert.equal((await call('POST', '/v1/policy/evaluate', { capability: 'correspondence:send' }, corr)).json.reason, 'grant');
      assert.equal((await call('POST', `/v1/grants/${grant.json.id}/use`, { useKey: 'letter-1' }, corr)).json.remainingUses, 4);
      assert.equal((await call('POST', `/v1/grants/${grant.json.id}/revoke`, { reason: 'No longer needed' }, admin)).json.state, 'revoked');
      assert.equal((await call('GET', '/v1/whoami', undefined, corr)).status, 401, 'the grantee token dies with the grant');
      assert.equal((await call('POST', '/v1/policy/evaluate', { capability: 'correspondence:send' }, await tokenFor(ivySession.refreshToken, 'correspondence'))).json.allowed, false);
      // standard surface: search, inspect, audit; unknown or foreign refs are 404 without detail
      assert.equal((await call('GET', '/v1/search?q=Ivy', undefined, admin)).json[0].ref, `E01:actor:${ivy.json.id}`);
      assert.equal((await call('GET', `/v1/inspect?ref=E01:actor:${ivy.json.id}`, undefined, admin)).json.title, 'Ivy Example');
      const missing = await call('GET', '/v1/inspect?ref=E01:actor:nobody', undefined, admin);
      assert.equal(missing.status, 404); assert.deepEqual(Object.keys(missing.json.error).sort(), ['code', 'message', 'requestId']);
      assert.ok((await call('GET', '/v1/audit?limit=500', undefined, admin)).json.some((a: any) => a.action === 'grant.revoked'));
      // service identity: client credentials, event feed, bounded agent token
      const svc = (await call('POST', '/v1/services', { name: 'Orchestrator', roles: ['service_orchestrator'], projectId: '*' }, admin)).json;
      const svcToken = (await call('POST', '/v1/tokens/service', { serviceId: svc.service.id, secret: svc.secret, projectId: 'main', purpose: 'operations' })).json.token as string;
      assert.equal((await call('POST', '/v1/tokens/service', { serviceId: svc.service.id, secret: 'wrong', projectId: 'main', purpose: 'operations' })).status, 401);
      const events = await settled(async () => (await call('GET', '/v1/events?limit=1000', undefined, svcToken)).json as { type: string }[], 'grant.revoked') as any[];
      assert.ok(events.some((e: any) => e.type === 'grant.revoked') && events.every((e: any) => e.tenantId === 'org-a'));
      assert.deepEqual((await call('POST', '/v1/upstream-changes', { eventId: 'x', kind: 'source_corrected', refs: [], reason: 'r' }, svcToken)).json, { affected: [] });
      const agent = (await call('POST', '/v1/agents', { name: 'Research agent', roles: ['agent_researcher'] }, admin)).json;
      const agentToken = await call('POST', `/v1/agents/${agent.id}/tokens`, { purpose: 'research', capabilities: ['evidence:read'], ttlSeconds: 60 }, svcToken);
      assert.deepEqual(agentToken.json.capabilities, ['evidence:read']);
      assert.equal((await call('POST', `/v1/agents/${agent.id}/tokens`, { purpose: 'research', capabilities: ['identity:admin'] }, svcToken)).status, 403);
      assert.equal((await call('GET', '/v1/members', undefined, agentToken.json.token)).status, 403, 'an agent token without identity:read cannot read the directory');
      assert.equal((await call('POST', `/v1/agents/${agent.id}/tokens`, { purpose: 'research', capabilities: ['evidence:read'] }, agentToken.json.token)).status, 403);
      // second organization: isolated over HTTP
      const orgB = await call('POST', '/v1/organizations', { id: 'org-b', name: 'Birch Assembly', owner: { login: 'bea@example.org', password: PASSWORD, displayName: 'Bea Birch' } }, admin);
      assert.equal(orgB.status, 200);
      const bea = (await call('POST', '/v1/sessions', { login: 'bea@example.org', password: PASSWORD })).json;
      const adminB = await tokenFor(bea.refreshToken, 'administration', 'org-b');
      assert.equal((await call('POST', '/v1/tokens', { refreshToken: bea.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' })).status, 403);
      assert.deepEqual((await call('GET', '/v1/members', undefined, adminB)).json.map((m: any) => m.actor.login), ['bea@example.org']);
      assert.deepEqual((await call('GET', '/v1/search?q=Ivy', undefined, adminB)).json, []);
      assert.equal((await call('GET', `/v1/inspect?ref=E01:actor:${ivy.json.id}`, undefined, adminB)).status, 404);
      assert.equal((await call('GET', `/v1/actors/${ivy.json.id}`, undefined, adminB)).status, 404);
      assert.equal((await call('POST', `/v1/grants/${grant.json.id}/revoke`, { reason: 'x' }, adminB)).status, 404);
      assert.equal((await call('POST', `/v1/actors/${ivy.json.id}/revoke`, { reason: 'x', disable: true }, adminB)).status, 404);
      assert.equal((await call('POST', '/v1/keys/rotate', {}, adminB)).status, 403);
      assert.deepEqual((await call('GET', '/v1/counts', undefined, adminB)).json.members, 1);
      // key rotation over HTTP: old token keeps working, both keys are published
      const rotated = await call('POST', '/v1/keys/rotate', {}, admin);
      assert.equal(rotated.status, 200);
      assert.equal((await call('GET', '/v1/whoami', undefined, admin)).status, 200);
      assert.equal(Object.keys((await call('GET', '/v1/keys')).json.keys).length, 2);
      // revocation over HTTP: token, then session
      assert.equal((await call('GET', '/v1/whoami', undefined, research)).status, 401, 'the earlier research token ended when the grant change revoked the grantee tokens');
      const research1 = await tokenFor(ivySession.refreshToken, 'research');
      assert.equal((await call('POST', '/v1/tokens/revoke', { tokenId: (await call('GET', '/v1/whoami', undefined, research1)).json.tokenId }, research1)).status, 200);
      assert.equal((await call('GET', '/v1/whoami', undefined, research1)).status, 401);
      const research2 = await tokenFor(ivySession.refreshToken, 'research');
      assert.equal((await call('POST', `/v1/sessions/${ivySession.sessionId}/revoke`, { reason: 'lost device' }, admin)).status, 200);
      assert.equal((await call('GET', '/v1/whoami', undefined, research2)).status, 401);
      assert.equal((await call('POST', '/v1/tokens', { refreshToken: ivySession.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' })).status, 401);
      // logout
      assert.equal((await call('POST', '/v1/sessions/logout', { refreshToken: bea.refreshToken })).status, 200);
      assert.equal((await call('GET', '/v1/whoami', undefined, adminB)).status, 401);
      // unknown routes and malformed JSON
      assert.equal((await call('GET', '/v1/nope', undefined, admin)).status, 404);
      const malformed = await fetch(`${base}/v1/sessions`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' });
      assert.equal(malformed.status, 400);
    } finally { await served.close(); }
  });
});

test('the server refuses to start without a database and bootstrap over HTTP is disabled without a bootstrap token', needsPg, async () => {
  await assert.rejects(start({}), /DATABASE_URL is required/);
  await withDisposableDatabase(pg, ADMIN_URL, async (url) => {
    const served = await start({ DATABASE_URL: url, PORT: '0' });
    try {
      const res = await fetch(`http://127.0.0.1:${served.port}/v1/bootstrap`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ login: 'ada@example.org', password: PASSWORD, displayName: 'Ada', organization: { name: 'Alder' }, bootstrapToken: 'anything' }) });
      assert.equal(res.status, 403);
      assert.match(JSON.stringify(await (await fetch(`http://127.0.0.1:${served.port}/healthz`)).json()), /IDENTITY_KEY_ENCRYPTION_KEY not configured/);
    } finally { await served.close(); }
  });
});
