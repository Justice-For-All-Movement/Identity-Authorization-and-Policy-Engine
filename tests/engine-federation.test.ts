import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createSign, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import { hasCapability } from '../src/service-kit.ts';
import { tokenHash } from '../src/index.ts';
import { guardUrl } from '../src/engine/oidc.ts';
import { PASSWORD, code, needsPg, withWorld } from './engine-fixture.ts';

const ISSUER = 'https://issuer.example.org/';
const CLIENT = { id: 'accountability-client', secret: 'fixture-client-secret' };
const REDIRECT = 'https://app.example.org/auth/callback';

type FakeIssuer = { base: string; close(): Promise<void>; subject: string; mode: 'ok' | 'bad_nonce' | 'bad_audience' | 'expired' | 'wrong_key' | 'alg_none' | 'wrong_issuer' | 'old_auth'; tokenRequests: number; pkceFailures: number };
/** A local OpenID Provider over HTTP: discovery, authorization endpoint, token endpoint (PKCE S256 + client secret) and JWKS. */
async function fakeIssuer(): Promise<FakeIssuer> {
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const codes = new Map<string, { challenge: string; nonce: string; redirect: string }>();
  const state: FakeIssuer = { base: '', subject: 'subject-ada', mode: 'ok', tokenRequests: 0, pkceFailures: 0, close: async () => {} };
  const b64 = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString('base64url');
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', state.base);
    const json = (status: number, body: unknown): void => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (url.pathname === '/.well-known/openid-configuration') return json(200, { issuer: ISSUER, authorization_endpoint: `${state.base}/authorize`, token_endpoint: `${state.base}/token`, jwks_uri: `${state.base}/jwks` });
    if (url.pathname === '/jwks') return json(200, { keys: [{ ...key.publicKey.export({ format: 'jwk' }), kid: 'fake-1', use: 'sig', alg: 'RS256' }] });
    if (url.pathname === '/authorize') {
      const p = url.searchParams;
      if (p.get('client_id') !== CLIENT.id || p.get('response_type') !== 'code' || p.get('code_challenge_method') !== 'S256' || !p.get('scope')?.split(' ').includes('openid')) return json(400, { error: 'invalid_request' });
      const authCode = randomBytes(16).toString('hex');
      codes.set(authCode, { challenge: p.get('code_challenge') ?? '', nonce: p.get('nonce') ?? '', redirect: p.get('redirect_uri') ?? '' });
      res.writeHead(302, { location: `${p.get('redirect_uri')}?code=${authCode}&state=${encodeURIComponent(p.get('state') ?? '')}` }); return res.end();
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        state.tokenRequests++;
        const form = new URLSearchParams(Buffer.concat(chunks).toString());
        const basic = Buffer.from(String(req.headers.authorization ?? '').replace(/^Basic /, ''), 'base64').toString();
        const entry = codes.get(form.get('code') ?? ''); codes.delete(form.get('code') ?? '');
        if (basic !== `${CLIENT.id}:${CLIENT.secret}` || entry === undefined || form.get('grant_type') !== 'authorization_code' || form.get('redirect_uri') !== entry.redirect) return json(400, { error: 'invalid_grant' });
        if (createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url') !== entry.challenge) { state.pkceFailures++; return json(400, { error: 'invalid_grant' }); }
        const now = Math.floor(Date.now() / 1000);
        const claims = { iss: state.mode === 'wrong_issuer' ? 'https://evil.example.org/' : ISSUER, sub: state.subject, aud: state.mode === 'bad_audience' ? 'someone-else' : CLIENT.id, iat: now, exp: state.mode === 'expired' ? now - 10 : now + 300,
          auth_time: state.mode === 'old_auth' ? now - 7200 : now, nonce: state.mode === 'bad_nonce' ? 'not-the-nonce' : entry.nonce, email: 'ada@issuer.example.org', roles: ['owner'], tenant: 'org-b' };
        const head = b64(state.mode === 'alg_none' ? { alg: 'none', typ: 'JWT' } : { alg: 'RS256', typ: 'JWT', kid: 'fake-1' });
        const signer = createSign('RSA-SHA256').update(`${head}.${b64(claims)}`);
        const sig = state.mode === 'alg_none' ? '' : signer.sign(state.mode === 'wrong_key' ? other.privateKey : key.privateKey).toString('base64url');
        json(200, { access_token: 'opaque', token_type: 'Bearer', id_token: `${head}.${b64(claims)}.${sig}` });
      });
      return;
    }
    json(404, { error: 'not_found' });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  state.base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  state.close = () => new Promise<void>((r) => server.close(() => r()));
  return state;
}
/** Plays the browser: follows the authorization redirect and returns the code and state delivered to the redirect URI. */
async function browser(authorizationUrl: string): Promise<{ code: string; state: string }> {
  const res = await fetch(authorizationUrl, { redirect: 'manual' });
  assert.equal(res.status, 302);
  const back = new URL(res.headers.get('location')!);
  assert.equal(`${back.origin}${back.pathname}`, REDIRECT);
  return { code: back.searchParams.get('code')!, state: back.searchParams.get('state')! };
}

test('SSRF guard: provider endpoints must be public HTTPS', async () => {
  const strict = { fetch, allowLoopbackHttp: false };
  for (const url of ['http://issuer.example.org/', 'https://127.0.0.1/x', 'https://10.0.0.8/', 'https://192.168.1.1/', 'https://169.254.169.254/latest/meta-data', 'https://[::1]/', 'https://localhost/', 'file:///etc/passwd', 'https://user:pw@issuer.example.org/', 'not a url'])
    await assert.rejects(guardUrl(url, strict), code('provider_unavailable'), url);
  await guardUrl('http://127.0.0.1:9/x', { fetch, allowLoopbackHttp: true });
  await assert.rejects(guardUrl('http://10.0.0.8/', { fetch, allowLoopbackHttp: true }), code('provider_unavailable'));
});

test('OIDC authorization-code + PKCE sign-in against a local issuer, mapped to an existing actor', needsPg, async () => {
  const idp = await fakeIssuer();
  try {
    await withWorld(async (w) => {
      const admin = await w.admin();
      const discoveryUrl = `${idp.base}/.well-known/openid-configuration`;
      await assert.rejects(w.engine.configureOidcProvider(admin, { id: 'main-idp', issuer: 'http://issuer.example.org/', clientId: CLIENT.id, redirectUris: [REDIRECT] }), code('invalid_input'));
      await assert.rejects(w.engine.configureOidcProvider(admin, { id: 'main-idp', issuer: ISSUER, clientId: CLIENT.id, redirectUris: ['http://app.example.org/cb'] }), code('invalid_input'));
      const provider = await w.engine.configureOidcProvider(admin, { id: 'main-idp', issuer: ISSUER, clientId: CLIENT.id, clientSecret: CLIENT.secret, scopes: ['openid', 'email'], redirectUris: [REDIRECT], discoveryUrl });
      assert.equal(provider.hasClientSecret, true);
      assert.ok(!JSON.stringify(await w.engine.listOidcProviders(admin)).includes(CLIENT.secret));
      const sealed = (await w.sql.query<{ client_secret_sealed: string }>('select client_secret_sealed from e01_identity.oidc_providers'))[0]!.client_secret_sealed;
      assert.ok(!sealed.includes(CLIENT.secret));
      const ivy = await w.user('ivy@example.org', ['investigator']);
      const start = () => w.engine.startOidcLogin({ tenantId: 'org-a', providerId: 'main-idp', redirectUri: REDIRECT });
      await assert.rejects(w.engine.startOidcLogin({ tenantId: 'org-a', providerId: 'main-idp', redirectUri: 'https://evil.example.org/cb' }), code('invalid_input'));
      await assert.rejects(w.engine.startOidcLogin({ tenantId: 'org-a', providerId: 'nope', redirectUri: REDIRECT }), code('not_found'));
      await assert.rejects(w.engine.startOidcLogin({ tenantId: 'org-zzz', providerId: 'main-idp', redirectUri: REDIRECT }), code('not_found'));
      const s1 = await start();
      const authUrl = new URL(s1.authorizationUrl);
      assert.equal(authUrl.origin, idp.base); assert.equal(authUrl.searchParams.get('code_challenge_method'), 'S256'); assert.equal(authUrl.searchParams.get('scope'), 'openid email');
      assert.ok(!(await w.sql.query<{ verifier_sealed: string; state_hash: string }>('select * from e01_identity.oidc_states')).some((r) => r.state_hash === s1.state), 'state is stored hashed');
      // unmapped subject: verified by the issuer but not accepted locally (no automatic provisioning)
      idp.subject = 'subject-ivy';
      await assert.rejects(w.engine.completeOidcLogin(await browser(s1.authorizationUrl)), code('unauthenticated'));
      // map issuer+subject+client to the existing actor
      await assert.rejects(w.engine.mapExternalActor(await w.ctx(ivy.session, 'research'), { provider: 'oidc', issuer: ISSUER, subject: 'subject-ivy', audience: CLIENT.id, actorId: ivy.id }), code('forbidden'));
      await assert.rejects(w.engine.mapExternalActor(admin, { provider: 'oidc', issuer: ISSUER, subject: 'subject-ivy', audience: CLIENT.id, actorId: 'no-such-actor' }), code('not_found'));
      const mapping = await w.engine.mapExternalActor(admin, { provider: 'oidc', issuer: ISSUER, subject: 'subject-ivy', audience: CLIENT.id, actorId: ivy.id });
      await assert.rejects(w.engine.mapExternalActor(admin, { provider: 'oidc', issuer: ISSUER, subject: 'subject-ivy', audience: CLIENT.id, actorId: w.ownerId }), code('conflict'));
      assert.deepEqual(await w.engine.resolveExternalActor(admin, { provider: 'oidc', issuer: ISSUER, subject: 'subject-ivy', audience: CLIENT.id }), { actorId: ivy.id, kind: 'human', status: 'active' });
      assert.equal(await w.engine.resolveExternalActor(admin, { provider: 'oidc', issuer: ISSUER, subject: 'someone-else', audience: CLIENT.id }), null);
      const s2 = await start();
      const cb = await browser(s2.authorizationUrl);
      const before = idp.tokenRequests;
      const session = await w.engine.completeOidcLogin(cb);
      assert.equal(idp.tokenRequests, before + 1); assert.equal(idp.pkceFailures, 0, 'the issuer verified our PKCE verifier');
      assert.equal(session.actorId, ivy.id); assert.equal(session.boundTenantId, 'org-a');
      // the federated session yields local roles only: claims in the id token (roles, tenant) supply nothing
      const ctx = await w.ctx(session, 'research');
      assert.equal(ctx.actor.id, ivy.id); assert.deepEqual(ctx.actor.roles, ['investigator']); assert.ok(!hasCapability(ctx, 'identity:admin'));
      // state and code are single-use
      await assert.rejects(w.engine.completeOidcLogin(cb), code('unauthenticated'));
      await assert.rejects(w.engine.completeOidcLogin({ state: 'made-up-state', code: 'x' }), code('unauthenticated'));
      // the session is bound to the provider's organization
      const b = await w.engine.createOrganization(admin, { id: 'org-b', name: 'Birch', owner: { login: 'bea@example.org', password: PASSWORD, displayName: 'Bea' } });
      const bea = await w.engine.login({ login: 'bea@example.org', password: PASSWORD });
      const adminB = await w.ctx(bea, 'administration', { tenantId: b.organization.id });
      await w.engine.setMembership(adminB, { login: 'ivy@example.org', roles: ['investigator'] });
      await assert.rejects(w.engine.issueAccessToken({ refreshToken: session.refreshToken, tenantId: 'org-b', projectId: 'main', purpose: 'research' }), code('forbidden'));
      assert.deepEqual((await w.engine.sessionDirectory(session.refreshToken)).organizations.map((o) => o.organization.id), ['org-a']);
      // organization B cannot federate into A's actors: mapping requires membership in B, and B's sessions stay in B
      await assert.rejects(w.engine.mapExternalActor(adminB, { provider: 'oidc', issuer: ISSUER, subject: 'attacker', audience: CLIENT.id, actorId: w.ownerId }), code('not_found'));
      // every tampered issuer response is rejected
      for (const mode of ['bad_nonce', 'bad_audience', 'expired', 'wrong_key', 'alg_none', 'wrong_issuer', 'old_auth'] as const) {
        idp.mode = mode;
        await assert.rejects(w.engine.completeOidcLogin(await browser((await start()).authorizationUrl)), code('unauthenticated'), mode);
      }
      idp.mode = 'ok';
      // a code obtained in one flow cannot be redeemed with another flow's state (PKCE binds them)
      const [f1, f2] = [await start(), await start()];
      const c1 = await browser(f1.authorizationUrl);
      await assert.rejects(w.engine.completeOidcLogin({ state: f2.state, code: c1.code }), code('unauthenticated'));
      assert.equal(idp.pkceFailures, 1);
      // expired state
      const f3 = await start();
      await w.sql.query(`update e01_identity.oidc_states set expires_at = now() - interval '1 second' where consumed_at is null`);
      await assert.rejects(w.engine.completeOidcLogin(await browser(f3.authorizationUrl)), code('unauthenticated'));
      // removing the mapping ends federated sessions and future sign-ins
      const live = await w.engine.issueAccessToken({ refreshToken: session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
      await w.engine.removeActorMapping(admin, mapping.id);
      await assert.rejects(w.engine.verifier()(live.token, { requestId: 'r' }), code('unauthenticated'));
      await assert.rejects(w.engine.sessionDirectory(session.refreshToken), code('unauthenticated'));
      await assert.rejects(w.engine.completeOidcLogin(await browser((await start()).authorizationUrl)), code('unauthenticated'));
      // the password session of the same actor is unaffected
      await w.ctx(ivy.session, 'research');
      // federating an administrator identity is an owner decision
      const al = await w.user('al@example.org', ['admin'], '*');
      await assert.rejects(w.engine.mapExternalActor(await w.ctx(al.session, 'administration'), { provider: 'oidc', issuer: ISSUER, subject: 'subject-ada', audience: CLIENT.id, actorId: w.ownerId }), code('forbidden'));
      assert.ok((await w.engine.audit(admin, { limit: 1000 })).some((a) => a.action === 'session.federated'));
    }, { oidcAllowInsecureLoopback: true });
    // without the loopback allowance the same provider is refused before any request is made
    await withWorld(async (w) => {
      const admin = await w.admin();
      await assert.rejects(w.engine.configureOidcProvider(admin, { id: 'idp', issuer: ISSUER, clientId: CLIENT.id, redirectUris: [REDIRECT], discoveryUrl: `${idp.base}/.well-known/openid-configuration` }), code('invalid_input'));
      await w.engine.configureOidcProvider(admin, { id: 'idp', issuer: ISSUER, clientId: CLIENT.id, redirectUris: [REDIRECT] });
      await w.sql.query(`update e01_identity.oidc_providers set discovery_url=$1`, [`${idp.base}/.well-known/openid-configuration`]);
      await assert.rejects(w.engine.startOidcLogin({ tenantId: 'org-a', providerId: 'idp', redirectUri: REDIRECT }), code('provider_unavailable'));
    });
  } finally { await idp.close(); }
});

test('intake identity boundary federates through the existing adapter into one mapped service identity', needsPg, async () => {
  const credential = 'intake-managed-credential-0123456789abcdef';
  let granted = ['cases:read', 'participants:read'];
  let version = '1.4.0';
  const seen: string[] = [];
  const intake = createServer((req, res) => {
    seen.push(String(req.headers.authorization));
    if (req.url !== '/api/v1/capabilities' || req.headers.authorization !== `Bearer ${credential}`) { res.writeHead(401, { 'content-type': 'application/json' }); return res.end('{}'); }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ data: { schemaVersion: 1, apiVersion: 'v1', engine: { service: 'secure-intake-case-workflow-engine', version }, authentication: { scheme: 'bearer', tenantSource: 'api_client', grantedScopes: granted } } }));
  });
  await new Promise<void>((r) => intake.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(intake.address() as { port: number }).port}`;
  const origin = 'https://intake.example.org/';
  // The adapter insists on an HTTPS origin; the controlled transport carries those requests to the local server.
  const intakeTransport = (url: string, options: RequestInit) => fetch(url.replace('https://intake.example.org', base), options);
  let reads = 0;
  try {
    await withWorld(async (w) => {
      const admin = await w.admin();
      const input = { connectionId: 'intake-main', origin, credentialFingerprint: tokenHash(credential), requiredScopes: ['cases:read'], supportedVersions: ['1.4.0'], localRoles: ['viewer' as const] };
      await assert.rejects(w.engine.registerIntakeConnection(admin, { ...input, origin: 'http://intake.example.org/' }), code('invalid_input'));
      await assert.rejects(w.engine.registerIntakeConnection(admin, { ...input, roles: ['owner'] }), code('invalid_input'));
      const conn = await w.engine.registerIntakeConnection(admin, input);
      await assert.rejects(w.engine.registerIntakeConnection(admin, input), code('conflict'));
      assert.equal(conn.verifiedAt, null);
      // one internal service identity, one mapping: the intake identity is federated, not duplicated
      assert.deepEqual(await w.engine.resolveExternalActor(admin, { provider: 'intake', issuer: origin, subject: 'intake-main' }), { actorId: conn.actorId, kind: 'service', status: 'active' });
      assert.deepEqual((await w.engine.listServiceIdentities(admin)).map((s) => s.id), [conn.actorId]);
      assert.equal((await w.sql.query(`select 1 from e01_identity.actors where id=$1 and secret_hash is null`, [conn.actorId])).length, 1, 'no local secret exists for the federated identity');
      // unverified connections get no token
      await assert.rejects(w.engine.issueIntakeServiceToken(admin, { connectionId: 'intake-main', purpose: 'operations' }), code('forbidden'));
      const verified = await w.engine.verifyIntakeConnection(admin, 'intake-main');
      assert.equal(verified.status, 'verified'); assert.equal(verified.connection.upstreamVersion, '1.4.0'); assert.equal(reads, 1);
      const token = await w.engine.issueIntakeServiceToken(admin, { connectionId: 'intake-main', purpose: 'operations' });
      const ctx = await w.engine.verifier()(token.token, { requestId: 'r' });
      assert.equal(ctx.actor.id, conn.actorId); assert.equal(ctx.actor.kind, 'service'); assert.deepEqual(ctx.actor.roles, ['service_connector']);
      assert.ok(hasCapability(ctx, 'intake:read'));
      for (const cap of ['intake:disclose_identity', 'intake:contact', 'identity:admin', 'evidence:read']) assert.ok(!hasCapability(ctx, cap), cap);
      assert.ok(!JSON.stringify([token, verified, await w.engine.listIntakeConnections(admin), await w.engine.audit(admin, { limit: 1000 })]).includes(credential), 'the managed credential never leaves the port');
      // upstream loses a required scope / changes version / credential mismatch → failed, and no further tokens
      granted = ['participants:read'];
      assert.deepEqual([(await w.engine.verifyIntakeConnection(admin, 'intake-main')).status, (await w.engine.verifyIntakeConnection(admin, 'intake-main')).reason], ['failed', 'insufficient_upstream_scope']);
      await assert.rejects(w.engine.issueIntakeServiceToken(admin, { connectionId: 'intake-main', purpose: 'operations' }), code('forbidden'));
      granted = ['cases:read']; version = '9.9.9';
      assert.equal((await w.engine.verifyIntakeConnection(admin, 'intake-main')).reason, 'incompatible_upstream');
      version = '1.4.0';
      assert.equal((await w.engine.verifyIntakeConnection(admin, 'intake-main')).status, 'verified');
      // stale verification
      await w.sql.query(`update e01_identity.intake_connections set verified_at = now() - interval '16 minutes'`);
      await assert.rejects(w.engine.issueIntakeServiceToken(admin, { connectionId: 'intake-main', purpose: 'operations' }), code('forbidden'));
      // an intake user maps onto an existing human instead of becoming a second identity
      const pat = await w.user('pat@example.org', ['participant_support']);
      await w.engine.mapExternalActor(admin, { provider: 'intake', issuer: origin, subject: 'intake-user-7781', actorId: pat.id });
      assert.equal((await w.engine.resolveExternalActor(await w.ctx(pat.session, 'participant_support'), { provider: 'intake', issuer: origin, subject: 'intake-user-7781' }))?.actorId, pat.id);
      assert.deepEqual((await w.engine.listActorMappings(admin, { provider: 'intake' })).map((m) => m.subject).sort(), ['intake-main', 'intake-user-7781']);
      // another organization cannot see or use the connection
      const b = await w.engine.createOrganization(admin, { id: 'org-b', name: 'Birch', owner: { login: 'bea@example.org', password: PASSWORD, displayName: 'Bea' } });
      const adminB = await w.ctx(await w.engine.login({ login: 'bea@example.org', password: PASSWORD }), 'administration', { tenantId: b.organization.id });
      assert.deepEqual(await w.engine.listIntakeConnections(adminB), []);
      await assert.rejects(w.engine.verifyIntakeConnection(adminB, 'intake-main'), code('not_found'));
      assert.equal(await w.engine.resolveExternalActor(adminB, { provider: 'intake', issuer: origin, subject: 'intake-main' }), null);
    }, {}, { intakeCredentials: async () => { reads++; return credential; }, intakeTransport: intakeTransport as never });
    // wrong credential in the host's store, and no credential port at all
    await withWorld(async (w) => {
      const admin = await w.admin();
      await w.engine.registerIntakeConnection(admin, { connectionId: 'c1', origin, credentialFingerprint: tokenHash(credential), requiredScopes: [], supportedVersions: ['1.4.0'] });
      const r = await w.engine.verifyIntakeConnection(admin, 'c1');
      assert.deepEqual([r.status, r.reason], ['failed', 'credential_mismatch']);
    }, {}, { intakeCredentials: async () => 'a-different-credential-0123456789abcdef', intakeTransport: intakeTransport as never });
    await withWorld(async (w) => {
      const admin = await w.admin();
      await w.engine.registerIntakeConnection(admin, { connectionId: 'c1', origin, credentialFingerprint: tokenHash(credential), requiredScopes: [], supportedVersions: ['1.4.0'] });
      const r = await w.engine.verifyIntakeConnection(admin, 'c1');
      assert.equal(r.status, 'unavailable'); assert.match(r.reason, /credential port/);
      await assert.rejects(w.engine.issueIntakeServiceToken(admin, { connectionId: 'c1', purpose: 'operations' }), code('forbidden'));
    });
    assert.ok(seen.every((a) => a === `Bearer ${credential}`), 'a mismatched credential is never sent upstream');
  } finally { await new Promise<void>((r) => intake.close(() => r())); }
});
