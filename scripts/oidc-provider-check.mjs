#!/usr/bin/env node
// Opt-in compatibility check of an OpenID Connect provider against what this engine's relying party requires
// (src/engine/oidc.ts): exact issuer in discovery, HTTPS endpoints, authorization code flow with PKCE S256,
// client_secret_basic (or a public client), and at least one signing key in an algorithm the engine verifies.
//
//   IDENTITY_LIVE_OIDC_ISSUER=https://issuer.example node scripts/oidc-provider-check.mjs
//
// Optional IDENTITY_LIVE_OIDC_DISCOVERY_URL when the document is not at <issuer>/.well-known/openid-configuration.
// Read-only: it fetches public metadata and keys only. Without IDENTITY_LIVE_OIDC_ISSUER it skips and exits 0.
// The sign-in itself needs a person at a browser; see docs/OWNER_STEPS.md for that step.
import { createPublicKey } from 'node:crypto';

const issuer = process.env.IDENTITY_LIVE_OIDC_ISSUER ?? '';
if (issuer === '') { console.log(JSON.stringify({ skipped: true, reason: 'IDENTITY_LIVE_OIDC_ISSUER is not set; no provider was contacted' })); process.exit(0); }
const checks = [];
const record = (name, ok, detail = '') => checks.push({ name, ok: Boolean(ok), ...(detail === '' ? {} : { detail: String(detail).slice(0, 300) }) });
const https = (value) => { try { const u = new URL(value); return u.protocol === 'https:' && !u.username && !u.password && !u.hash; } catch { return false; } };
async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json' }, redirect: 'manual', signal: AbortSignal.timeout(10000) });
  const text = await res.text();
  if (text.length > 262144) throw new Error('response larger than the engine accepts (256 kB)');
  return { status: res.status, json: JSON.parse(text) };
}
try {
  record('issuer is an HTTPS URL', https(issuer), issuer);
  const discoveryUrl = process.env.IDENTITY_LIVE_OIDC_DISCOVERY_URL || `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const d = await getJson(discoveryUrl);
  const meta = d.json ?? {};
  record('discovery answers 200 without redirect', d.status === 200, `status ${d.status}`);
  record('discovery names exactly this issuer', meta.issuer === issuer, meta.issuer);
  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) record(`${key} is HTTPS`, https(meta[key]), meta[key]);
  record('authorization code flow is supported', !Array.isArray(meta.response_types_supported) || meta.response_types_supported.includes('code'));
  record('PKCE S256 is supported', Array.isArray(meta.code_challenge_methods_supported) ? meta.code_challenge_methods_supported.includes('S256') : true, meta.code_challenge_methods_supported === undefined ? 'not advertised (most providers accept it)' : meta.code_challenge_methods_supported.join(' '));
  const auth = meta.token_endpoint_auth_methods_supported;
  record('client_secret_basic (or a public client) is supported', auth === undefined || auth.includes('client_secret_basic') || auth.includes('none'), Array.isArray(auth) ? auth.join(' ') : 'default (client_secret_basic)');
  const algs = meta.id_token_signing_alg_values_supported ?? [];
  record('an id-token algorithm the engine verifies is offered', algs.some((a) => ['RS256', 'PS256', 'ES256', 'EdDSA'].includes(a)), algs.join(' '));
  if (https(meta.jwks_uri)) {
    const k = await getJson(meta.jwks_uri);
    const usable = (k.json?.keys ?? []).filter((jwk) => { try { const t = createPublicKey({ key: jwk, format: 'jwk' }).asymmetricKeyType; return (jwk.use === undefined || jwk.use === 'sig') && ['rsa', 'rsa-pss', 'ec', 'ed25519'].includes(t); } catch { return false; } });
    record('JWKS has a usable signing key', k.status === 200 && usable.length > 0, `${usable.length} usable key(s)`);
  }
} catch (error) { record('check ran to completion', false, error instanceof Error ? error.message : 'unknown error'); }
const failed = checks.filter((c) => !c.ok);
console.log(JSON.stringify({ issuer, at: new Date().toISOString(), passed: checks.length - failed.length, failed: failed.length, checks }, null, 2));
process.exit(failed.length === 0 ? 0 : 1);
