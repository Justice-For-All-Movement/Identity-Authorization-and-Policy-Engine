#!/usr/bin/env node
// Opt-in acceptance check of a running E01 deployment (standalone server or an embedding host's mount point).
//
//   IDENTITY_LIVE_BASE_URL=https://host/path node scripts/live-verify.mjs
//
// Without IDENTITY_LIVE_BASE_URL it prints a skip notice and exits 0. Public checks are read-only apart from one
// failed sign-in for a random, nonexistent login. With IDENTITY_LIVE_LOGIN and IDENTITY_LIVE_PASSWORD (and
// IDENTITY_LIVE_TOTP_SECRET when that account uses two-factor sign-in) it also signs in, takes a read-only
// `workspace` token, checks decisions, revokes that token and signs out again. It never prints tokens or secrets.
// Optional: IDENTITY_LIVE_TENANT_ID / IDENTITY_LIVE_PROJECT_ID (default: the first the account can enter),
// IDENTITY_LIVE_EXPECT_ISSUER, IDENTITY_LIVE_ALLOW_HTTP=true (loopback hosts only). Exit 1 when any check fails.
import { createHmac, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';

const env = process.env;
const base = (env.IDENTITY_LIVE_BASE_URL ?? '').replace(/\/+$/, '');
if (base === '') {
  console.log(JSON.stringify({ skipped: true, reason: 'IDENTITY_LIVE_BASE_URL is not set; no live deployment was contacted' }));
  process.exit(0);
}
const checks = [];
const record = (name, ok, detail = '') => { checks.push({ name, ok: Boolean(ok), ...(detail === '' ? {} : { detail: String(detail).slice(0, 300) }) }); };
const b64u = (value) => Buffer.from(value).toString('base64url');

async function call(method, path, { body, token } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${base}${path}`, { method, headers, redirect: 'manual', signal: AbortSignal.timeout(60000), ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, json, text };
}
function totp(secretBase32, at = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of secretBase32.replace(/=+$/, '').toUpperCase()) { const v = alphabet.indexOf(ch); if (v < 0) throw new Error('IDENTITY_LIVE_TOTP_SECRET is not base32'); bits += v.toString(2).padStart(5, '0'); }
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const mac = createHmac('sha1', key).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}
function verifyOffline(token, keys, issuer) {
  const [head, body, sig] = String(token).split('.');
  const header = JSON.parse(Buffer.from(head, 'base64url').toString('utf8'));
  const claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  const pem = keys[header.kid];
  const valid = header.alg === 'EdDSA' && pem !== undefined && verify(null, Buffer.from(`${head}.${body}`), createPublicKey(pem), Buffer.from(sig, 'base64url'));
  return { valid, claims, issuerOk: claims.iss === issuer };
}

async function main() {
  const url = new URL(base);
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  record('transport is HTTPS', url.protocol === 'https:' || (loopback && env.IDENTITY_LIVE_ALLOW_HTTP === 'true'), url.protocol);
  if (!checks[0].ok) return;

  const health = await call('GET', '/healthz');
  record('health answers ok', health.status === 200 && health.json?.ok === true && health.json?.detail?.database === 'ok', `status ${health.status}`);
  record('signing keys ready', health.json?.detail?.signing === 'ready' || /no key yet/.test(String(health.json?.detail?.signing)), health.json?.detail?.signing);
  const manifest = await call('GET', '/v1/manifest');
  record('manifest is E01', manifest.status === 200 && manifest.json?.id === 'E01' && Array.isArray(manifest.json?.capabilities) && manifest.json.capabilities.includes('identity:read'), `${manifest.json?.id} ${manifest.json?.version}`);
  const keys = await call('GET', '/v1/keys');
  let keyMap = keys.json?.keys ?? {};
  // A fresh deployment creates its first signing key on first issuance; an empty set is accepted only then.
  const noKeyYet = /no key yet/.test(String(health.json?.detail?.signing));
  let keysOk = keys.status === 200 && typeof keys.json?.issuer === 'string' && (Object.keys(keyMap).length > 0 || noKeyYet) && !/PRIVATE|"d"\s*:/.test(keys.text);
  for (const [kid, pem] of Object.entries(keyMap)) {
    try {
      const jwk = createPublicKey(pem).export({ format: 'jwk' });
      const published = (keys.json?.jwks?.keys ?? []).find((k) => k.kid === kid);
      keysOk &&= jwk.crv === 'Ed25519' && published !== undefined && published.x === jwk.x && published.alg === 'EdDSA';
    } catch { keysOk = false; }
  }
  record('published keys are Ed25519 and consistent (PEM map = JWKS, no private parts)', keysOk, `${Object.keys(keyMap).length} key(s)`);
  if (env.IDENTITY_LIVE_EXPECT_ISSUER) record('issuer matches the expected value', keys.json?.issuer === env.IDENTITY_LIVE_EXPECT_ISSUER, keys.json?.issuer);
  const boot = await call('GET', '/v1/bootstrap');
  record('deployment is bootstrapped', boot.status === 200 && boot.json?.bootstrapped === true);
  const rebootstrap = await call('POST', '/v1/bootstrap', { body: { login: 'nobody@example.invalid', password: 'x'.repeat(20), displayName: 'x', organization: { name: 'x' } } });
  record('bootstrap without the deployment token is refused', rebootstrap.status === 403, `status ${rebootstrap.status}`);
  for (const path of ['/v1/whoami', '/v1/members', '/v1/organization', '/v1/audit', '/v1/export', '/v1/capability-grants']) {
    const r = await call('GET', path);
    record(`unauthenticated ${path} is refused`, r.status === 401, `status ${r.status}`);
  }
  // A token signed by a key the deployment does not hold, reusing a published kid, must be refused.
  const { privateKey } = generateKeyPairSync('ed25519');
  const kid = Object.keys(keyMap)[0] ?? 'none', now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid }));
  const body = b64u(JSON.stringify({ iss: keys.json?.issuer, sub: randomUUID(), kind: 'human', tid: 'forged', pid: 'forged', roles: ['owner'], caps: ['identity:*', 'identity:admin'], cmp: [], purpose: 'administration', pv: '1', iat: now, exp: now + 300, jti: randomUUID() }));
  const forged = `${head}.${body}.${b64u(sign(null, Buffer.from(`${head}.${body}`), privateKey))}`;
  record('forged token is refused', (await call('GET', '/v1/whoami', { token: forged })).status === 401);
  const badLogin = await call('POST', '/v1/sessions', { body: { login: `probe-${randomUUID()}@example.invalid`, password: 'not the password of anyone' } });
  record('unknown login is refused without detail', badLogin.status === 401 && !/stack|scrypt|hash|sql/i.test(badLogin.text), `status ${badLogin.status}`);
  record('unknown refresh token is refused', (await call('POST', '/v1/tokens', { body: { refreshToken: `${randomUUID()}.x`, tenantId: 'x', projectId: 'x', purpose: 'workspace' } })).status === 401);
  const missing = await call('GET', '/v1/no-such-route');
  record('unknown route answers 404 without detail', missing.status === 404 && !/stack/i.test(missing.text), `status ${missing.status}`);

  if (!env.IDENTITY_LIVE_LOGIN || !env.IDENTITY_LIVE_PASSWORD) { record('authenticated checks', true, 'skipped: IDENTITY_LIVE_LOGIN / IDENTITY_LIVE_PASSWORD not set'); return; }
  const credentials = { login: env.IDENTITY_LIVE_LOGIN, password: env.IDENTITY_LIVE_PASSWORD, ...(env.IDENTITY_LIVE_TOTP_SECRET ? { code: totp(env.IDENTITY_LIVE_TOTP_SECRET) } : {}) };
  const session = await call('POST', '/v1/sessions', { body: credentials });
  record('sign-in succeeds', session.status === 200 && typeof session.json?.refreshToken === 'string', `status ${session.status}${session.json?.error ? ` ${session.json.error.code}` : ''}`);
  if (session.status !== 200) return;
  const refreshToken = session.json.refreshToken;
  try {
    const dir = await call('POST', '/v1/sessions/directory', { body: { refreshToken } });
    const org = (dir.json?.organizations ?? []).find((o) => !env.IDENTITY_LIVE_TENANT_ID || o.organization.id === env.IDENTITY_LIVE_TENANT_ID);
    const project = org?.projects.find((p) => !env.IDENTITY_LIVE_PROJECT_ID || p.id === env.IDENTITY_LIVE_PROJECT_ID);
    record('session directory lists an organization and project', project !== undefined);
    if (project === undefined) return;
    const issued = await call('POST', '/v1/tokens', { body: { refreshToken, tenantId: org.organization.id, projectId: project.id, purpose: 'workspace' } });
    record('read-only workspace token is issued', issued.status === 200 && typeof issued.json?.token === 'string', `status ${issued.status}`);
    if (issued.status !== 200) return;
    const token = issued.json.token;
    keyMap = (await call('GET', '/v1/keys')).json?.keys ?? keyMap;
    const offline = verifyOffline(token, keyMap, keys.json?.issuer);
    const lifetime = offline.claims.exp - offline.claims.iat;
    record('token verifies offline against the published keys', offline.valid && offline.issuerOk);
    record('token is short-lived and purpose-bound', lifetime > 0 && lifetime <= 3600 && offline.claims.purpose === 'workspace' && offline.claims.tid === org.organization.id, `${lifetime}s`);
    record('workspace token carries no sensitive action', !(offline.claims.caps ?? []).some((c) => /:(disclose_identity|contact|send|publish|approve|spend|grant|admin|export|withdraw)$/.test(c)));
    const me = await call('GET', '/v1/whoami', { token });
    record('whoami names the signed-in actor', me.status === 200 && me.json?.tenantId === org.organization.id && me.json?.purpose === 'workspace');
    const publish = await call('POST', '/v1/policy/evaluate', { token, body: { capability: 'release:publish' } });
    record('a workspace token cannot publish', publish.status === 200 && publish.json?.allowed === false, publish.json?.reason);
    const other = await call('POST', '/v1/tokens', { body: { refreshToken, tenantId: `not-${org.organization.id}`, projectId: project.id, purpose: 'workspace' } });
    record('no token for an organization the account does not belong to', other.status === 403 || other.status === 401, `status ${other.status}`);
    if ((offline.claims.caps ?? []).some((c) => c === 'identity:read' || c === 'identity:*')) {
      const who = await call('GET', `/v1/access/who?capability=identity:read&purpose=workspace&limit=50`, { token });
      record('who-can-access view answers', who.status === 200 && Array.isArray(who.json?.allowed), `status ${who.status}`);
    }
    const projection = await call('POST', '/v1/projections/redact', { token, body: { record: { title: 'fixture', secret: 'withheld' }, fields: { title: null, secret: 'intake:disclose_identity' } } });
    record('redacted projection withholds a protected field', projection.status === 200 && projection.json?.projection?.title === 'fixture' && projection.json?.projection?.secret === undefined, `status ${projection.status}`);
    const revoke = await call('POST', '/v1/tokens/revoke', { token, body: { tokenId: offline.claims.jti, reason: 'live verification' } });
    record('own token can be revoked', revoke.status === 200, `status ${revoke.status}`);
    let after = 0;
    for (let i = 0; i < 8; i++) { after = (await call('GET', '/v1/whoami', { token })).status; if (after === 401) break; await new Promise((r) => setTimeout(r, 1000)); }
    record('revoked token is refused within the cache window', after === 401, `status ${after}`);
  } finally {
    const out = await call('POST', '/v1/sessions/logout', { body: { refreshToken } });
    record('sign-out succeeds', out.status === 200, `status ${out.status}`);
    record('ended session cannot issue tokens', (await call('POST', '/v1/sessions/directory', { body: { refreshToken } })).status === 401);
  }
}

try { await main(); } catch (error) { record('verification ran to completion', false, error instanceof Error ? error.message : 'unknown error'); }
const failed = checks.filter((c) => !c.ok);
console.log(JSON.stringify({ target: `${new URL(base).protocol}//${new URL(base).host}`, at: new Date().toISOString(), passed: checks.length - failed.length, failed: failed.length, checks }, null, 2));
process.exit(failed.length === 0 ? 0 : 1);
