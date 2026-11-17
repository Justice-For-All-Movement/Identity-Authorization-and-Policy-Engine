// Standalone server: reads env, runs migrations, serves HTTP and runs periodic maintenance.
import pg from 'pg';
import { createHmac } from 'node:crypto';
import type { Server } from 'node:http';
import { createHttpHandler, pgSql, serve } from '../service-kit.ts';
import type { PgPoolLike } from '../service-kit.ts';
import { createEngine, manifest, migrate, routes } from './index.ts';
import type { EngineConfig, EnginePorts, IdentityEngine, PasswordResetMessage } from './index.ts';

export type Served = Readonly<{ server: Server; engine: IdentityEngine; port: number; close(): Promise<void> }>;
const num = (value: string | undefined): number | undefined => (value === undefined || value === '' || !Number.isFinite(Number(value)) ? undefined : Number(value));

export function configFromEnv(env: Readonly<Record<string, string | undefined>>): EngineConfig {
  const pick = <T,>(key: keyof EngineConfig, value: T | undefined): Partial<EngineConfig> => (value === undefined || value === '' ? {} : { [key]: value });
  return {
    ...pick('issuer', env.IDENTITY_ISSUER), ...pick('keyEncryptionKey', env.IDENTITY_KEY_ENCRYPTION_KEY), ...pick('bootstrapToken', env.IDENTITY_BOOTSTRAP_TOKEN),
    ...pick('accessTokenTtlSeconds', num(env.IDENTITY_ACCESS_TOKEN_TTL_SECONDS)), ...pick('sessionTtlSeconds', num(env.IDENTITY_SESSION_TTL_SECONDS)), ...pick('sessionIdleSeconds', num(env.IDENTITY_SESSION_IDLE_SECONDS)),
    ...pick('revocationCacheMs', num(env.IDENTITY_REVOCATION_CACHE_MS)), ...pick('oidcAllowInsecureLoopback', env.IDENTITY_OIDC_ALLOW_INSECURE_LOOPBACK === 'true' ? true : undefined),
    ...pick('allowOrganizationCreation', env.IDENTITY_ALLOW_ORGANIZATION_CREATION === 'false' ? false : undefined),
  };
}
/**
 * Password-reset delivery for the standalone server: a signed POST to a host-owned mailer or messaging webhook.
 * `IDENTITY_PASSWORD_RESET_WEBHOOK_URL` (HTTPS; plain HTTP only to a loopback host) and
 * `IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET` (≥ 32 characters) are set together or not at all. The body is the
 * message JSON; `x-e01-timestamp` is Unix seconds and `x-e01-signature` is `sha256=` + HMAC-SHA256(secret,
 * `<timestamp>.<body>`) in hex. Any non-2xx answer counts as a failed delivery and the token is discarded.
 */
export function portsFromEnv(env: Readonly<Record<string, string | undefined>>, transport: typeof fetch = fetch): EnginePorts {
  const url = env.IDENTITY_PASSWORD_RESET_WEBHOOK_URL ?? '', secret = env.IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET ?? '';
  if (url === '' && secret === '') return {};
  if (url === '' || secret === '') throw new Error('IDENTITY_PASSWORD_RESET_WEBHOOK_URL and IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET must be set together');
  let target: URL;
  try { target = new URL(url); } catch { throw new Error('IDENTITY_PASSWORD_RESET_WEBHOOK_URL is not a valid URL'); }
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(target.hostname);
  if (target.protocol !== 'https:' && !(target.protocol === 'http:' && loopback)) throw new Error('IDENTITY_PASSWORD_RESET_WEBHOOK_URL must use HTTPS');
  if (target.username !== '' || target.password !== '') throw new Error('IDENTITY_PASSWORD_RESET_WEBHOOK_URL must not contain credentials');
  if (secret.length < 32) throw new Error('IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET must be at least 32 characters');
  return {
    passwordResetDelivery: async (message: PasswordResetMessage, signal: AbortSignal): Promise<void> => {
      const body = JSON.stringify(message), timestamp = String(Math.floor(Date.now() / 1000));
      const signature = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
      const res = await transport(target, { method: 'POST', redirect: 'manual', signal, body, headers: { 'content-type': 'application/json', 'x-e01-timestamp': timestamp, 'x-e01-signature': `sha256=${signature}` } });
      await res.body?.cancel().catch(() => {});
      if (res.status < 200 || res.status > 299) throw new Error(`delivery answered ${res.status}`);
    },
  };
}
export async function start(env: Readonly<Record<string, string | undefined>> = process.env): Promise<Served> {
  if (env.DATABASE_URL === undefined || env.DATABASE_URL === '') throw new Error('DATABASE_URL is required');
  const ports = portsFromEnv(env);
  const pool = new pg.Pool({ connectionString: env.DATABASE_URL, max: num(env.DATABASE_POOL_MAX) ?? 10 });
  const sql = pgSql(pool as unknown as PgPoolLike);
  await migrate(sql);
  const engine = createEngine({ sql, config: configFromEnv(env), ports });
  const log = (line: Record<string, unknown>): void => { process.stderr.write(`${JSON.stringify({ at: new Date().toISOString(), engine: 'E01', ...line })}\n`); };
  const handler = createHttpHandler({ name: manifest.id, version: manifest.version, routes: routes(engine), verify: engine.verifier(), maxBodyBytes: 1024 * 1024, health: engine.health,
    // Only the error class and request coordinates are logged: never bodies, credentials or tokens.
    onError: (error, info) => log({ level: 'error', ...info, error: error instanceof Error ? error.name : 'unknown' }) });
  const server = await serve(handler, num(env.PORT) ?? 8080, env.HOST ?? '127.0.0.1');
  const rotateAfter = (num(env.IDENTITY_KEY_ROTATION_DAYS) ?? 30) * 86400;
  const tick = (): void => { void engine.host.maintenance({ rotateKeysOlderThanSeconds: rotateAfter }).then((r) => { if (r.rotated !== null) log({ level: 'info', event: 'key.rotated', kid: r.rotated }); }, () => log({ level: 'error', event: 'maintenance_failed' })); };
  const timer = setInterval(tick, 5 * 60 * 1000); timer.unref(); tick();
  const address = server.address();
  return { server, engine, port: typeof address === 'object' && address !== null ? address.port : 0, close: async () => { clearInterval(timer); await new Promise<void>((r) => server.close(() => r())); await pool.end(); } };
}
if (import.meta.main) {
  start().then((s) => { process.stderr.write(`${JSON.stringify({ engine: 'E01', listening: s.port })}\n`); for (const sig of ['SIGINT', 'SIGTERM'] as const) process.once(sig, () => { void s.close().then(() => process.exit(0)); }); },
    (error: unknown) => { process.stderr.write(`E01 failed to start: ${error instanceof Error ? error.message : 'unknown error'}\n`); process.exit(1); });
}
