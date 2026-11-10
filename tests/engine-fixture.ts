// Shared fixture for the E01 service-layer tests: real PostgreSQL, fictional people and organizations only.
import assert from 'node:assert/strict';
import pg from 'pg';
import { DomainError } from '../src/contracts.ts';
import { withDisposableDatabase } from '../src/service-kit.ts';
import type { ServiceContext, Sql } from '../src/service-kit.ts';
import { createEngine, migrate } from '../src/engine/index.ts';
import type { EngineConfig, EnginePorts, IdentityEngine, SessionInfo } from '../src/engine/index.ts';

export const ADMIN_URL = process.env.TEST_DATABASE_URL ?? '';
export const needsPg = ADMIN_URL === '' ? { skip: 'TEST_DATABASE_URL is not set; real-PostgreSQL test not executed' } : {};
export const PASSWORD = 'correct horse battery staple';
export const baseConfig: EngineConfig = { keyEncryptionKey: 'fixture-key-encryption-key-0123456789abcdef', scryptN: 1024, revocationCacheMs: 0 };

export const code = (expected: string) => (e: unknown): boolean => { assert.ok(e instanceof DomainError, `expected DomainError ${expected}, got ${String(e)}`); assert.equal(e.code, expected); return true; };
export type World = { sql: Sql; url: string; engine: IdentityEngine; owner: SessionInfo; ownerId: string; orgId: string; ctx: (session: SessionInfo, purpose: string, over?: { tenantId?: string; projectId?: string; capabilities?: readonly string[] }) => Promise<ServiceContext>; admin: () => Promise<ServiceContext>;
  user: (login: string, roles: readonly string[], projectId?: string) => Promise<{ id: string; session: SessionInfo }> };

export function withWorld(fn: (w: World) => Promise<void>, config: EngineConfig = {}, ports: EnginePorts = {}): Promise<void> {
  return withDisposableDatabase(pg, ADMIN_URL, async (url, sql) => {
    await migrate(sql);
    const engine = createEngine({ sql, config: { ...baseConfig, ...config }, ports });
    const boot = await engine.bootstrapFirstAdministrator({ login: 'ada@example.org', password: PASSWORD, displayName: 'Ada Example', organization: { id: 'org-a', name: 'Alder Collective', defaultLocale: 'en', languages: ['en', 'es'], project: { id: 'main', name: 'Main', kind: 'organizational' } } });
    const owner = await engine.login({ login: 'ada@example.org', password: PASSWORD });
    const verify = engine.verifier();
    const ctx: World['ctx'] = async (session, purpose, over = {}) => {
      const t = await engine.issueAccessToken({ refreshToken: session.refreshToken, tenantId: over.tenantId ?? 'org-a', projectId: over.projectId ?? 'main', purpose, ...(over.capabilities === undefined ? {} : { capabilities: over.capabilities }) });
      return verify(t.token, { requestId: 'test' });
    };
    const admin = (): Promise<ServiceContext> => ctx(owner, 'administration');
    const user: World['user'] = async (login, roles, projectId) => {
      const a = await engine.createUser(await admin(), { login, password: PASSWORD, displayName: login.split('@')[0] as string, roles, ...(projectId === undefined ? {} : { projectId }) });
      return { id: a.id, session: await engine.login({ login, password: PASSWORD }) };
    };
    await fn({ sql, url, engine, owner, ownerId: boot.actorId, orgId: 'org-a', ctx, admin, user });
  });
}

/**
 * The kit's event feed withholds rows while any older transaction on the PostgreSQL server is still in flight
 * (gap safety). Other suites share this server, so tests poll the feed until it has settled past the last write.
 */
export async function settled<T extends { type: string }>(read: () => Promise<T[]>, lastType: string, timeoutMs = 30000): Promise<T[]> {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const feed = await read();
    if (feed.some((e) => e.type === lastType) || Date.now() > until) return feed;
    await new Promise((r) => setTimeout(r, 100));
  }
}
