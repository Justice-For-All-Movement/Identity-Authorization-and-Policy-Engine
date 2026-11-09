import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { DomainError } from '../src/contracts.ts';
import * as kit from '../src/service-kit.ts';

const ADMIN = process.env.TEST_DATABASE_URL ?? '';
const needsPg = ADMIN === '' ? { skip: 'TEST_DATABASE_URL is not set; real-PostgreSQL test not executed' } : {};
const ctx = (over: Partial<kit.ServiceContext> = {}): kit.ServiceContext => ({ tenantId: 't1', projectId: 'p1', purpose: 'test', requestId: 'r1', now: new Date().toISOString(), actor: { id: 'u1', kind: 'human', roles: [] }, capabilities: ['demo:read'], compartments: [], ...over });

test('tokens: sign, verify, expiry, tamper, revocation, wildcard denial', async () => {
  const key = kit.generateSigningKey('k1');
  const now = Math.floor(Date.now() / 1000);
  const claims: kit.TokenClaims = { iss: 'iap', sub: 'u1', kind: 'human', tid: 't1', pid: 'p1', roles: ['r'], caps: ['evidence:read'], cmp: ['c1'], purpose: 'research', pv: '3', iat: now, exp: now + 60, jti: 'j1' };
  const token = kit.signAccessToken(claims, key);
  const verify = kit.createTokenVerifier({ publicKeys: { k1: key.publicKeyPem }, issuer: 'iap', isRevoked: async (c) => c.jti === 'revoked' });
  const c = await verify(token, { requestId: 'req' });
  assert.equal(c.tenantId, 't1'); assert.deepEqual(c.capabilities, ['evidence:read']); assert.equal(c.policyVersion, '3');
  const denied = async (t: string) => assert.rejects(verify(t, { requestId: 'x' }), (e: unknown) => e instanceof DomainError && e.code === 'unauthenticated');
  await denied(token.slice(0, -3) + 'AAA');
  await denied(kit.signAccessToken({ ...claims, exp: now - 1 }, key));
  await denied(kit.signAccessToken({ ...claims, jti: 'revoked' }, key));
  await denied(kit.signAccessToken({ ...claims, caps: ['*'] }, key));
  await denied(kit.signAccessToken({ ...claims, iss: 'other' }, key));
  await denied(kit.signAccessToken(claims, kit.generateSigningKey('k1')));
  await denied('garbage');
  assert.throws(() => kit.requireCapability(c, 'evidence:write'), (e: unknown) => e instanceof DomainError && e.code === 'forbidden');
  kit.requireCapability({ ...c, capabilities: ['evidence:*'] }, 'evidence:write');
  for (const action of kit.SENSITIVE_ACTIONS) assert.throws(() => kit.requireCapability({ ...c, capabilities: ['x:*'] }, `x:${action}`), (e: unknown) => e instanceof DomainError && e.code === 'forbidden');
  kit.requireCapability({ ...c, capabilities: ['x:publish'] }, 'x:publish');
  assert.throws(() => kit.requireCapability(undefined as unknown as kit.ServiceContext, 'x:y'), (e: unknown) => e instanceof DomainError && e.code === 'unauthenticated');
});

test('urefs', () => {
  assert.equal(kit.uref('E05', 'evidence_version', 'abc-1', 3), 'E05:evidence_version:abc-1@3');
  assert.deepEqual(kit.parseUref('E07:claim:x'), { engine: 'E07', kind: 'claim', id: 'x' });
  assert.ok(kit.urefMatches('E05:evidence:a', 'E05:evidence:a@2')); assert.ok(!kit.urefMatches('E05:evidence:a@1', 'E05:evidence:a@2'));
  assert.throws(() => kit.parseUref('nope'));
});

test('postgres: migrations, events, idempotency, audit, jobs', needsPg, async () => {
  await kit.withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
    const migrations = [{ id: '001', sql: 'create table {s}.thing (id text primary key)' }];
    assert.deepEqual(await kit.runMigrations(sql, 'demo', migrations), ['001']);
    assert.deepEqual(await kit.runMigrations(sql, 'demo', migrations), []);
    await assert.rejects(kit.runMigrations(sql, 'demo', [{ id: '001', sql: 'select 1' }]), /modified/);

    // events: rollback leaves nothing; nested savepoint rollback keeps outer
    await assert.rejects(sql.tx(async (tx) => { await kit.emitEvent(tx, 'demo', ctx(), 'x.y', 'E01:thing:1', {}); throw new Error('boom'); }));
    await sql.tx(async (tx) => {
      await kit.emitEvent(tx, 'demo', ctx(), 'a.created', 'E01:thing:1', { n: 1 });
      await assert.rejects(tx.tx(async (inner) => { await kit.emitEvent(inner, 'demo', ctx(), 'a.bad', 'E01:thing:1', {}); throw new Error('inner'); }));
      await kit.emitEvent(tx, 'demo', ctx({ tenantId: 't2' }), 'a.created', 'E01:thing:2', { n: 2 });
    });
    const all = await kit.readEvents(sql, 'demo');
    assert.deepEqual(all.map((e) => e.type), ['a.created', 'a.created']);
    assert.equal((await kit.readEvents(sql, 'demo', { tenantId: 't2' })).length, 1);
    assert.equal((await kit.readEvents(sql, 'demo', { after: all[1]!.id })).length, 0);
    // in-flight transaction hides its own and later events from readers (gap safety)
    let release!: () => void; const gate = new Promise<void>((r) => { release = r; });
    const slow = sql.tx(async (tx) => { await kit.emitEvent(tx, 'demo', ctx(), 'slow', 'E01:thing:3', {}); await gate; });
    await new Promise((r) => setTimeout(r, 100));
    await sql.tx((tx) => kit.emitEvent(tx, 'demo', ctx(), 'fast', 'E01:thing:4', {}));
    assert.equal((await kit.readEvents(sql, 'demo', { after: all[1]!.id })).length, 0);
    release(); await slow;
    assert.deepEqual((await kit.readEvents(sql, 'demo', { after: all[1]!.id })).map((e) => e.type), ['slow', 'fast']);

    // idempotency
    let calls = 0;
    const run = (input: unknown) => sql.tx((tx) => kit.idempotent(tx, 'demo', ctx(), 'k1', input, async () => ({ n: ++calls })));
    assert.deepEqual(await run({ a: 1 }), { n: 1 }); assert.deepEqual(await run({ a: 1 }), { n: 1 }); assert.equal(calls, 1);
    await assert.rejects(run({ a: 2 }), (e: unknown) => e instanceof DomainError && e.code === 'idempotency_conflict');

    // audit chain, concurrent appends
    await Promise.all(Array.from({ length: 8 }, (_, i) => sql.tx((tx) => kit.appendAudit(tx, 'demo', ctx(), 'did', `E01:thing:${i}`, { i }))));
    await sql.tx((tx) => kit.appendAudit(tx, 'demo', ctx({ tenantId: 't2' }), 'did', 'E01:thing:z'));
    const chain = await kit.listAudit(sql, 'demo', ctx(), { allProjects: true });
    assert.equal(chain.length, 8); assert.ok(kit.verifyAuditChain(chain));
    assert.ok(!kit.verifyAuditChain(chain.map((r, i) => i === 3 ? { ...r, action: 'tampered' } : r)));
    assert.equal((await kit.listAudit(sql, 'demo', ctx({ tenantId: 't2' }))).length, 1);

    // jobs
    const j1 = await sql.tx((tx) => kit.enqueueJob(tx, 'demo', ctx(), { kind: 'work', payload: { n: 1 }, dedupeKey: 'd1', maxAttempts: 2 }));
    const dup = await sql.tx((tx) => kit.enqueueJob(tx, 'demo', ctx(), { kind: 'work', payload: { n: 1 }, dedupeKey: 'd1' }));
    assert.equal(dup.id, j1.id);
    const [a, b] = await Promise.all([kit.leaseJobs(sql, 'demo', { worker: 'w1', leaseMs: 50 }), kit.leaseJobs(sql, 'demo', { worker: 'w2', leaseMs: 50 })]);
    assert.equal(a.length + b.length, 1, 'only one concurrent worker leases the job');
    const first = (a[0] ?? b[0])!;
    await new Promise((r) => setTimeout(r, 80));
    const again = await kit.leaseJobs(sql, 'demo', { worker: 'w3', leaseMs: 50 });
    assert.equal(again.length, 1); assert.equal(again[0]!.attempts, 2);
    await assert.rejects(kit.completeJob(sql, 'demo', first, { late: true }), (e: unknown) => e instanceof DomainError && e.code === 'lease_lost');
    await new Promise((r) => setTimeout(r, 80));
    assert.equal((await kit.leaseJobs(sql, 'demo', { worker: 'w4' })).length, 0, 'exhausted job is not leased again');
    assert.equal((await kit.getJob(sql, 'demo', ctx(), j1.id))!.state, 'dead');
    assert.equal((await kit.controlJob(sql, 'demo', ctx(), j1.id, 'retry')).state, 'queued');
    await assert.rejects(kit.controlJob(sql, 'demo', ctx({ tenantId: 't2' }), j1.id, 'cancel'), (e: unknown) => e instanceof DomainError && e.code === 'not_found');
    assert.equal((await kit.controlJob(sql, 'demo', ctx(), j1.id, 'pause')).state, 'paused');
    assert.equal(await kit.runJobsOnce(sql, 'demo', { work: async () => ({ ok: true }) }, { worker: 'w5' }), 0);
    await kit.controlJob(sql, 'demo', ctx(), j1.id, 'resume');
    assert.equal(await kit.runJobsOnce(sql, 'demo', { work: async (job) => ({ got: job.payload }) }, { worker: 'w5' }), 1);
    assert.deepEqual((await kit.getJob(sql, 'demo', ctx(), j1.id))!.result, { got: { n: 1 } });
    const j2 = await sql.tx((tx) => kit.enqueueJob(tx, 'demo', ctx(), { kind: 'work', payload: {}, maxAttempts: 1 }));
    await kit.runJobsOnce(sql, 'demo', { work: async () => { throw new Error('provider down'); } }, { worker: 'w5' });
    const dead = (await kit.getJob(sql, 'demo', ctx(), j2.id))!; assert.equal(dead.state, 'dead'); assert.match(dead.lastError!, /provider down/);
    const j3 = await sql.tx((tx) => kit.enqueueJob(tx, 'demo', ctx(), { kind: 'work', payload: {} }));
    const leased = (await kit.leaseJobs(sql, 'demo', { worker: 'w6' }))[0]!;
    await kit.controlJob(sql, 'demo', ctx(), j3.id, 'cancel');
    await assert.rejects(kit.completeJob(sql, 'demo', leased), (e: unknown) => e instanceof DomainError && e.code === 'lease_lost');
  });
});

test('http handler and fs object store', async () => {
  const key = kit.generateSigningKey('k1');
  const now = Math.floor(Date.now() / 1000);
  const token = kit.signAccessToken({ iss: 'iap', sub: 'u1', kind: 'human', tid: 't1', pid: 'p1', roles: [], caps: ['demo:read'], cmp: [], purpose: 'p', pv: '1', iat: now, exp: now + 60, jti: 'j' }, key);
  const handler = kit.createHttpHandler({ name: 'demo', version: '1', verify: kit.createTokenVerifier({ publicKeys: { k1: key.publicKeyPem } }), routes: [
    { method: 'GET', path: '/v1/things/:id', handler: async (r) => { kit.requireCapability(r.ctx, 'demo:read'); if (r.params.id === 'missing') throw new DomainError('scope_denied', 'secret detail'); return { id: r.params.id ?? '', tenant: r.ctx.tenantId }; } },
    { method: 'POST', path: '/v1/things', handler: async (r) => { kit.requireCapability(r.ctx, 'demo:write'); return {}; } },
    { method: 'POST', path: '/v1/echo', handler: async (r) => ({ bytes: r.raw }) },
    { method: 'GET', path: '/v1/crash', handler: async () => { throw new Error('secret internal'); } },
  ] });
  const server = await kit.serve(handler, 0);
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    assert.equal((await fetch(`${base}/healthz`)).status, 200);
    assert.equal((await fetch(`${base}/v1/things/1`)).status, 401);
    const client = kit.engineClient(base, () => token);
    assert.deepEqual(await client.call('GET', '/v1/things/a%20b'), { id: 'a b', tenant: 't1' });
    await assert.rejects(client.call('POST', '/v1/things', {}), (e: unknown) => e instanceof DomainError && e.code === 'forbidden');
    const r404 = await fetch(`${base}/v1/things/missing`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(r404.status, 404); assert.doesNotMatch(await r404.text(), /secret/);
    const r500 = await fetch(`${base}/v1/crash`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(r500.status, 500); assert.doesNotMatch(await r500.text(), /secret/);
    const echoed = await fetch(`${base}/v1/echo`, { method: 'POST', headers: { authorization: `Bearer ${token}` }, body: new Uint8Array([1, 2, 3]) });
    assert.deepEqual([...new Uint8Array(await echoed.arrayBuffer())], [1, 2, 3]);
  } finally { server.close(); }
  const store = new kit.FsObjectStore(await mkdtemp(join(tmpdir(), 'kit-')));
  const info = await store.put('t1/a/b.bin', new Uint8Array([9, 8]));
  assert.equal(info.size, 2); assert.deepEqual([...await store.get('t1/a/b.bin')], [9, 8]);
  assert.deepEqual(await store.list('t1/'), ['t1/a/b.bin']); assert.deepEqual(await store.head('t1/none'), null);
  await assert.rejects(store.get('../etc/passwd')); await assert.rejects(store.get('t1/none'), (e: unknown) => e instanceof DomainError && e.code === 'not_found');
  await store.delete('t1/a/b.bin'); assert.deepEqual(await store.list(''), []);
});
