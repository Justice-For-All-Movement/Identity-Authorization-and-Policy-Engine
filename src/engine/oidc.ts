// OpenID Connect relying-party protocol: discovery, authorization-code + PKCE (S256), JWKS id-token verification.
import { constants, createHash, createPublicKey, randomBytes, verify as cryptoVerify } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { DomainError, invariant } from '../contracts.ts';

export type OidcClient = Readonly<{ issuer: string; clientId: string; clientSecret: string | null; scopes: readonly string[]; discoveryUrl: string | null }>;
export type OidcMetadata = Readonly<{ issuer: string; authorizationEndpoint: string; tokenEndpoint: string; jwksUri: string }>;
export type OidcIdentity = Readonly<{ issuer: string; subject: string; audience: string; authenticatedAt: Date; expiresAt: Date }>;
export type OidcTransport = Readonly<{ fetch: typeof fetch; allowLoopbackHttp: boolean }>;

const unavailable = (message: string): DomainError => new DomainError('provider_unavailable', message);
const rejected = (): DomainError => new DomainError('unauthenticated', 'Federated sign-in was not accepted');

function privateAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number) as [number, number];
    return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe8') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb') || v.startsWith('::ffff:');
}
/**
 * SSRF guard for administrator-configured provider URLs: HTTPS to public addresses only. Loopback HTTP is accepted
 * solely when the deployment enables it for tests. Resolution is checked before the request (a rebinding window
 * between check and connect remains; deploy behind an egress policy where that matters).
 */
export async function guardUrl(value: string, transport: OidcTransport): Promise<URL> {
  let url: URL;
  try { url = new URL(value); } catch { throw unavailable('Identity provider URL is invalid'); }
  invariant(!url.username && !url.password && !url.hash, 'provider_unavailable', 'Identity provider URL is invalid');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const loopback = host === '127.0.0.1' || host === '::1' || host === 'localhost';
  if (transport.allowLoopbackHttp && loopback && (url.protocol === 'http:' || url.protocol === 'https:')) return url;
  invariant(url.protocol === 'https:', 'provider_unavailable', 'Identity provider endpoints must use HTTPS');
  let addresses: string[];
  try { addresses = isIP(host) !== 0 ? [host] : (await lookup(host, { all: true })).map((a) => a.address); } catch { throw unavailable('Identity provider host cannot be resolved'); }
  invariant(addresses.length > 0 && !addresses.some(privateAddress), 'provider_unavailable', 'Identity provider host resolves to a non-public address');
  return url;
}
async function requestJson(transport: OidcTransport, value: string, init: RequestInit): Promise<{ status: number; body: Record<string, unknown> }> {
  const url = await guardUrl(value, transport);
  let response: Response;
  try { response = await transport.fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(10000) }); } catch { throw unavailable('Identity provider did not respond'); }
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    while (reader !== undefined) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > 262144) { void reader.cancel().catch(() => {}); throw unavailable('Identity provider response is too large'); }
      chunks.push(part.value);
    }
  } catch (error) { if (error instanceof DomainError) throw error; throw unavailable('Identity provider response could not be read'); }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
    invariant(body !== null && typeof body === 'object' && !Array.isArray(body), 'provider_unavailable', 'Identity provider returned an unexpected response');
    return { status: response.status, body: body as Record<string, unknown> };
  } catch { throw unavailable('Identity provider returned an unexpected response'); }
}
export async function discover(client: OidcClient, transport: OidcTransport): Promise<OidcMetadata> {
  const url = client.discoveryUrl ?? `${client.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const { status, body } = await requestJson(transport, url, { method: 'GET', headers: { accept: 'application/json' } });
  invariant(status === 200, 'provider_unavailable', 'Identity provider discovery failed');
  invariant(body.issuer === client.issuer, 'provider_unavailable', 'Discovery document names a different issuer');
  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) invariant(typeof body[key] === 'string', 'provider_unavailable', 'Discovery document is incomplete');
  const meta = { issuer: client.issuer, authorizationEndpoint: body.authorization_endpoint as string, tokenEndpoint: body.token_endpoint as string, jwksUri: body.jwks_uri as string };
  for (const endpoint of [meta.authorizationEndpoint, meta.tokenEndpoint, meta.jwksUri]) await guardUrl(endpoint, transport);
  return meta;
}
export function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(48).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}
export function authorizationUrl(meta: OidcMetadata, client: OidcClient, request: { state: string; nonce: string; challenge: string; redirectUri: string }): string {
  const url = new URL(meta.authorizationEndpoint);
  const scopes = [...new Set(['openid', ...client.scopes])];
  for (const [key, value] of Object.entries({ response_type: 'code', client_id: client.clientId, redirect_uri: request.redirectUri, scope: scopes.join(' '), state: request.state, nonce: request.nonce, code_challenge: request.challenge, code_challenge_method: 'S256' })) url.searchParams.set(key, value);
  return url.toString();
}
const ALGORITHMS: Readonly<Record<string, (data: Buffer, key: ReturnType<typeof createPublicKey>, sig: Buffer) => boolean>> = {
  RS256: (d, key, sig) => key.asymmetricKeyType === 'rsa' && cryptoVerify('sha256', d, key, sig),
  PS256: (d, key, sig) => (key.asymmetricKeyType === 'rsa' || key.asymmetricKeyType === 'rsa-pss') && cryptoVerify('sha256', d, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig),
  ES256: (d, key, sig) => key.asymmetricKeyType === 'ec' && cryptoVerify('sha256', d, { key, dsaEncoding: 'ieee-p1363' }, sig),
  EdDSA: (d, key, sig) => key.asymmetricKeyType === 'ed25519' && cryptoVerify(null, d, key, sig),
};
async function verifyIdToken(idToken: string, meta: OidcMetadata, client: OidcClient, transport: OidcTransport, nonce: string, now: Date): Promise<OidcIdentity> {
  const parts = idToken.split('.');
  if (parts.length !== 3 || idToken.length > 16384) throw rejected();
  const [head, body, sig] = parts as [string, string, string];
  let header: Record<string, unknown>, claims: Record<string, unknown>;
  try { header = JSON.parse(Buffer.from(head, 'base64url').toString('utf8')) as Record<string, unknown>; claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as Record<string, unknown>; } catch { throw rejected(); }
  const check = typeof header.alg === 'string' && Object.hasOwn(ALGORITHMS, header.alg) ? ALGORITHMS[header.alg] : undefined;
  if (check === undefined) throw rejected();
  const jwks = await requestJson(transport, meta.jwksUri, { method: 'GET', headers: { accept: 'application/json' } });
  invariant(jwks.status === 200 && Array.isArray(jwks.body.keys), 'provider_unavailable', 'Identity provider keys are unavailable');
  const candidates = (jwks.body.keys as Record<string, unknown>[]).filter((key) => key !== null && typeof key === 'object' && (header.kid === undefined || key.kid === header.kid) && (key.use === undefined || key.use === 'sig')).slice(0, 8);
  let verified = false;
  for (const jwk of candidates) {
    try { if (check(Buffer.from(`${head}.${body}`), createPublicKey({ key: jwk as never, format: 'jwk' }), Buffer.from(sig, 'base64url'))) { verified = true; break; } } catch { /* try the next key */ }
  }
  if (!verified) throw rejected();
  const seconds = Math.floor(now.getTime() / 1000);
  const audiences = typeof claims.aud === 'string' ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud as unknown[] : [];
  if (claims.iss !== meta.issuer || !audiences.includes(client.clientId) || (audiences.length > 1 && claims.azp !== client.clientId) || (claims.azp !== undefined && claims.azp !== client.clientId)) throw rejected();
  if (typeof claims.exp !== 'number' || claims.exp <= seconds || typeof claims.iat !== 'number' || claims.iat > seconds + 60 || claims.nonce !== nonce) throw rejected();
  if (typeof claims.sub !== 'string' || claims.sub === '' || claims.sub.length > 255) throw rejected();
  const authTime = typeof claims.auth_time === 'number' ? claims.auth_time : claims.iat;
  return { issuer: meta.issuer, subject: claims.sub, audience: client.clientId, authenticatedAt: new Date(Math.min(authTime, seconds) * 1000), expiresAt: new Date(claims.exp * 1000) };
}
/** Redeems the authorization code (PKCE verifier + client authentication) and verifies the returned id token. */
export async function redeem(meta: OidcMetadata, client: OidcClient, transport: OidcTransport, request: { code: string; verifier: string; redirectUri: string; nonce: string; now: Date }): Promise<OidcIdentity> {
  const form = new URLSearchParams({ grant_type: 'authorization_code', code: request.code, redirect_uri: request.redirectUri, client_id: client.clientId, code_verifier: request.verifier });
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  if (client.clientSecret !== null) headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(client.clientId)}:${encodeURIComponent(client.clientSecret)}`).toString('base64')}`;
  const { status, body } = await requestJson(transport, meta.tokenEndpoint, { method: 'POST', headers, body: form.toString() });
  if (status >= 500) throw unavailable('Identity provider token endpoint failed');
  if (status !== 200 || typeof body.id_token !== 'string') throw rejected();
  return verifyIdToken(body.id_token, meta, client, transport, request.nonce, request.now);
}
