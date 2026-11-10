import test from 'node:test';
import assert from 'node:assert/strict';
import { SENSITIVE_ACTIONS, hasCapability, signAccessToken, generateSigningKey, verifyAuditChain } from '../src/service-kit.ts';
import type { ServiceContext } from '../src/service-kit.ts';
import { DEFAULT_ROLES, createEngine, migrate } from '../src/engine/index.ts';
import { PASSWORD, baseConfig, code, needsPg, withWorld } from './engine-fixture.ts';

const future = (seconds: number): string => new Date(Date.now() + seconds * 1000).toISOString();

test('default role catalog keeps sensitive actions exact and away from research roles', () => {
  const role = (name: string) => DEFAULT_ROLES.find((r) => r.name === name)!;
  const asCtx = (name: string) => ({ capabilities: role(name).capabilities } as unknown as ServiceContext);
  for (const name of ['investigator', 'agent_researcher', 'agent_drafter', 'agent_producer', 'auditor', 'producer'])
    for (const cap of role(name).capabilities) assert.ok(!SENSITIVE_ACTIONS.includes(cap.split(':')[1]!), `${name} must not hold ${cap}`);
  assert.ok(hasCapability(asCtx('investigator'), 'evidence:write'));
  for (const cap of ['evidence:export', 'correspondence:send', 'correspondence:contact', 'release:publish', 'resources:spend', 'intake:disclose_identity', 'identity:admin', 'identity:grant'])
    assert.ok(!hasCapability(asCtx('investigator'), cap), `investigator must not hold ${cap}`);
  assert.ok(!role('owner').capabilities.some((c) => c.endsWith(':disclose_identity')), 'even the owner needs an explicit grant to disclose identities');
  assert.ok(hasCapability(asCtx('release_manager'), 'release:publish') && !hasCapability(asCtx('release_manager'), 'resources:spend'));
  assert.ok(hasCapability(asCtx('finance'), 'resources:spend') && !hasCapability(asCtx('finance'), 'release:publish'));
  for (const r of DEFAULT_ROLES.filter((x) => x.kinds.includes('agent'))) assert.ok(!r.capabilities.some((c) => c.startsWith('identity:')), 'agent roles carry no identity capabilities');
});

test('bootstrap happens once; password login, lockout, change and reset', needsPg, async () => {
  await withWorld(async (w) => {
    const again = { login: 'eve@example.org', password: PASSWORD, displayName: 'Eve', organization: { name: 'Second' } };
    await assert.rejects(w.engine.bootstrapFirstAdministrator(again), code('conflict'));
    assert.equal(await w.engine.isBootstrapped(), true);
    assert.equal((await w.sql.query(`select 1 from e01_identity.credentials where login='eve@example.org'`)).length, 0);
    // passwords are stored only as scrypt hashes
    const stored = (await w.sql.query<{ password_hash: string }>('select password_hash from e01_identity.credentials'))[0]!.password_hash;
    assert.match(stored, /^scrypt\$1024\$8\$1\$/); assert.ok(!stored.includes(PASSWORD));
    // wrong password and unknown login are indistinguishable
    await assert.rejects(w.engine.login({ login: 'ada@example.org', password: 'wrong password entirely' }), code('unauthenticated'));
    await assert.rejects(w.engine.login({ login: 'nobody@example.org', password: PASSWORD }), code('unauthenticated'));
    // lockout after repeated failures, also with the right password, and for unknown logins alike
    const bo = await w.user('bo@example.org', ['investigator']);
    for (let i = 0; i < 3; i++) await assert.rejects(w.engine.login({ login: 'bo@example.org', password: 'nope nope nope nope' }), code('unauthenticated'));
    await assert.rejects(w.engine.login({ login: 'bo@example.org', password: PASSWORD }), code('rate_limited'));
    for (let i = 0; i < 3; i++) await assert.rejects(w.engine.login({ login: 'ghost@example.org', password: 'nope nope nope nope' }), code('unauthenticated'));
    await assert.rejects(w.engine.login({ login: 'ghost@example.org', password: PASSWORD }), code('rate_limited'));
    await w.sql.query(`update e01_identity.auth_attempts set locked_until = now() - interval '1 second'`);
    const back = await w.engine.login({ login: 'bo@example.org', password: PASSWORD });
    // change password: old sessions end, old password stops working
    const boCtx = await w.ctx(back, 'research');
    await assert.rejects(w.engine.changePassword(boCtx, { currentPassword: 'not the password!!', newPassword: 'a brand new passphrase' }), code('unauthenticated'));
    await assert.rejects(w.engine.changePassword(boCtx, { currentPassword: PASSWORD, newPassword: 'short' }), code('invalid_input'));
    await w.engine.changePassword(boCtx, { currentPassword: PASSWORD, newPassword: 'a brand new passphrase' });
    await assert.rejects(w.engine.issueAccessToken({ refreshToken: back.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' }), code('unauthenticated'));
    await assert.rejects(w.engine.issueAccessToken({ refreshToken: bo.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' }), code('unauthenticated'));
    await assert.rejects(w.engine.login({ login: 'bo@example.org', password: PASSWORD }), code('unauthenticated'));
    const fresh = await w.engine.login({ login: 'bo@example.org', password: 'a brand new passphrase' });
    // administrator reset
    await w.engine.resetPassword(await w.admin(), { actorId: bo.id, newPassword: 'reset by the administrator' });
    await assert.rejects(w.engine.sessionDirectory(fresh.refreshToken), code('unauthenticated'));
    await w.engine.login({ login: 'bo@example.org', password: 'reset by the administrator' });
    await assert.rejects(w.engine.resetPassword(boCtx, { actorId: w.ownerId, newPassword: 'attempted takeover 123' }), code('forbidden'));
  }, { lockout: { maxFailures: 3 } });
});

test('bootstrap token gates bootstrap when configured', needsPg, async () => {
  const { withDisposableDatabase } = await import('../src/service-kit.ts');
  const pg = (await import('pg')).default;
  await withDisposableDatabase(pg, process.env.TEST_DATABASE_URL!, async (_url, sql) => {
    await migrate(sql);
    const engine = createEngine({ sql, config: { ...baseConfig, bootstrapToken: 'one-time-bootstrap-token' } });
    const input = { login: 'ada@example.org', password: PASSWORD, displayName: 'Ada', organization: { name: 'Alder' } };
    await assert.rejects(engine.bootstrapFirstAdministrator(input), code('forbidden'));
    await assert.rejects(engine.bootstrapFirstAdministrator({ ...input, bootstrapToken: 'guess' }), code('forbidden'));
    const [a, b] = await Promise.allSettled([engine.bootstrapFirstAdministrator({ ...input, bootstrapToken: 'one-time-bootstrap-token' }), engine.bootstrapFirstAdministrator({ ...input, login: 'bea@example.org', bootstrapToken: 'one-time-bootstrap-token' })]);
    assert.equal([a, b].filter((r) => r.status === 'fulfilled').length, 1, 'concurrent bootstraps: exactly one wins');
    assert.equal((await sql.query('select 1 from e01_identity.organizations')).length, 1);
    const noKey = createEngine({ sql, config: { scryptN: 1024 } });
    const s = await noKey.login({ login: a.status === 'fulfilled' ? 'ada@example.org' : 'bea@example.org', password: PASSWORD });
    const org = (await noKey.sessionDirectory(s.refreshToken)).organizations[0]!;
    await assert.rejects(noKey.issueAccessToken({ refreshToken: s.refreshToken, tenantId: org.organization.id, projectId: 'main', purpose: 'research' }), code('unavailable'));
  });
});

test('tokens are scoped to one organization, project and purpose; research implies nothing sensitive', needsPg, async () => {
  await withWorld(async (w) => {
    const dir = await w.engine.sessionDirectory(w.owner.refreshToken);
    assert.deepEqual(dir.organizations.map((o) => [o.organization.id, o.projects.map((p) => [p.id, p.roles])]), [['org-a', [['main', ['owner']]]]]);
    assert.ok(dir.organizations[0]!.purposes.includes('research'));
    const research = await w.ctx(w.owner, 'research');
    assert.equal(research.tenantId, 'org-a'); assert.equal(research.projectId, 'main'); assert.equal(research.purpose, 'research'); assert.equal(research.actor.kind, 'human');
    assert.ok(hasCapability(research, 'evidence:write') && hasCapability(research, 'knowledge:read'));
    for (const cap of ['evidence:export', 'correspondence:send', 'correspondence:contact', 'release:publish', 'resources:spend', 'identity:admin', 'identity:grant', 'intake:disclose_identity', 'knowledge:approve'])
      assert.ok(!hasCapability(research, cap), `research purpose must not carry ${cap} even for the owner`);
    const release = await w.ctx(w.owner, 'release');
    assert.ok(hasCapability(release, 'release:publish') && !hasCapability(release, 'evidence:write') && !hasCapability(release, 'resources:spend'));
    // narrowing by request
    const narrow = await w.ctx(w.owner, 'research', { capabilities: ['evidence:read', 'release:publish'] });
    assert.deepEqual(narrow.capabilities, ['evidence:read']);
    // unknown purpose, project, organization: denied
    await assert.rejects(w.ctx(w.owner, 'world_domination'), code('forbidden'));
    await assert.rejects(w.ctx(w.owner, 'research', { projectId: 'nope' }), code('forbidden'));
    await assert.rejects(w.ctx(w.owner, 'research', { tenantId: 'org-zzz' }), code('forbidden'));
    await assert.rejects(w.engine.issueAccessToken({ refreshToken: 'garbage', tenantId: 'org-a', projectId: 'main', purpose: 'research' }), code('unauthenticated'));
    await assert.rejects(w.engine.issueAccessToken({ refreshToken: `${w.owner.sessionId}.wrong`, tenantId: 'org-a', projectId: 'main', purpose: 'research' }), code('unauthenticated'));
    // investigator: research works, authorize explains denials
    const ivy = await w.user('ivy@example.org', ['investigator']);
    const ivyCtx = await w.ctx(ivy.session, 'research');
    const ok = await w.engine.authorize(ivyCtx, { capability: 'evidence:write', resource: 'E05:evidence:abc' });
    assert.equal(ok.allowed, true); assert.equal(ok.reason, 'role'); assert.deepEqual(ok.via, { kind: 'role', roles: ['investigator'] }); assert.equal(ok.policyVersion, ivyCtx.policyVersion);
    for (const cap of ['release:publish', 'correspondence:send', 'intake:disclose_identity', 'resources:spend', 'evidence:export']) {
      const d = await w.engine.authorize(ivyCtx, { capability: cap });
      assert.equal(d.allowed, false, cap); assert.ok(d.trail.length > 0);
    }
    // even a forged context claiming the wildcard cannot pass the current-state check for a sensitive action
    const forged: ServiceContext = { ...ivyCtx, capabilities: ['evidence:*', 'evidence:export', 'release:publish'] };
    assert.equal((await w.engine.authorize(forged, { capability: 'evidence:export' })).reason, 'sensitive_capability_not_granted');
    assert.equal((await w.engine.authorize({ ...ivyCtx, capabilities: ['release:*'] }, { capability: 'release:publish' })).reason, 'not_in_token');
    // the denial of an identity disclosure is audited and emitted
    const events = await w.engine.events({ ...(await w.admin()), capabilities: ['identity:events'] });
    assert.ok(events.some((e) => e.type === 'disclosure.denied' && e.subject === `E01:actor:${ivy.id}`));
    const explained = await w.engine.explain(await w.admin(), ivy.id, 'release:publish', undefined, { purpose: 'release' });
    assert.equal(explained.allowed, false); assert.match(explained.trail.map((s) => s.detail).join(' | '), /No current role names release:publish exactly/);
    const why = await w.engine.explain(await w.admin(), w.ownerId, 'release:publish', undefined, { purpose: 'release' });
    assert.equal(why.allowed, true); assert.deepEqual(why.via, { kind: 'role', roles: ['owner'] });
    assert.equal((await w.engine.explain(ivyCtx, ivy.id, 'evidence:read')).allowed, true);
  });
});

test('fail closed: unknown actor, expired, tampered, revoked, wrong project, missing compartment', needsPg, async () => {
  await withWorld(async (w) => {
    const admin = await w.admin();
    const verify = w.engine.verifier();
    await w.engine.createProject(admin, { id: 'side', name: 'Side project', kind: 'campaign' });
    const ivy = await w.user('ivy@example.org', ['investigator']);
    const ivyCtx = await w.ctx(ivy.session, 'research');
    // unknown actor / foreign tenant / malformed contexts
    for (const bad of [{ ...ivyCtx, actor: { id: 'ghost', kind: 'human' as const, roles: ['owner'] } }, { ...ivyCtx, tenantId: 'org-zzz' }, { ...ivyCtx, projectId: 'side' }, { ...ivyCtx, purpose: 'nonsense' }, { ...ivyCtx, actor: { ...ivyCtx.actor, kind: 'service' as const } }])
      assert.equal((await w.engine.authorize(bad, { capability: 'evidence:read' })).allowed, false);
    for (const bad of [undefined, null, {}, { capabilities: ['evidence:read'] }]) assert.equal((await w.engine.authorize(bad as unknown as ServiceContext, { capability: 'evidence:read' })).allowed, false);
    assert.equal((await w.engine.authorize(ivyCtx, { capability: 'evidence:*' })).reason, 'invalid_capability');
    assert.equal((await w.engine.authorize(ivyCtx, undefined as never)).allowed, false);
    // a storage failure denies rather than allows
    const broken = createEngine({ sql: { query: async () => { throw new Error('database down'); }, tx: async () => { throw new Error('database down'); } }, config: baseConfig });
    assert.deepEqual([(await broken.authorize(ivyCtx, { capability: 'evidence:read' })).allowed, (await broken.authorize(ivyCtx, { capability: 'evidence:read' })).reason], [false, 'authorization_unavailable']);
    await assert.rejects(broken.verifier()('a.b.c', { requestId: 'r' }), code('unauthenticated'));
    // wrong project: no membership there
    await assert.rejects(w.ctx(ivy.session, 'research', { projectId: 'side' }), code('forbidden'));
    // tokens: tampered, foreign key, expired
    const issued = await w.engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research', ttlSeconds: 30 });
    await assert.rejects(verify(issued.token.slice(0, -4) + 'AAAA', { requestId: 'r' }), code('unauthenticated'));
    const [h, b, s] = issued.token.split('.') as [string, string, string];
    const elevated = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(b, 'base64url').toString()), caps: ['release:publish'] })).toString('base64url');
    await assert.rejects(verify(`${h}.${elevated}.${s}`, { requestId: 'r' }), code('unauthenticated'));
    const rogue = generateSigningKey(JSON.parse(Buffer.from(h, 'base64url').toString()).kid as string);
    await assert.rejects(verify(signAccessToken({ ...JSON.parse(Buffer.from(b, 'base64url').toString()), caps: ['identity:admin'] }, rogue), { requestId: 'r' }), code('unauthenticated'));
    await verify(issued.token, { requestId: 'r' });
    await assert.rejects(verify(issued.token, { requestId: 'r', now: new Date(Date.now() + 31000) }), code('unauthenticated'));
    await assert.rejects(w.engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research', ttlSeconds: 86400 }), code('invalid_input'));
    // token revocation by id: verifier and authorize both deny
    await w.engine.revokeToken(ivyCtx, { tokenId: ivyCtx.tokenId! });
    assert.equal((await w.engine.authorize(ivyCtx, { capability: 'evidence:read' })).reason, 'token_revoked');
    const t2 = await w.engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    await assert.rejects(w.engine.revokeToken(ivyCtx, { tokenId: t2.tokenId }), code('forbidden'));
    await w.engine.revokeToken(admin, { tokenId: t2.tokenId, actorId: ivy.id, reason: 'reported lost' });
    await assert.rejects(verify(t2.token, { requestId: 'r' }), code('unauthenticated'));
    // session revocation: its tokens and refresh die
    const t3 = await w.engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    assert.deepEqual((await w.engine.listSessions(admin, { actorId: ivy.id })).map((x) => x.id), [ivy.session.sessionId]);
    await w.engine.revokeSession(admin, { sessionId: ivy.session.sessionId, reason: 'device lost' });
    await assert.rejects(verify(t3.token, { requestId: 'r' }), code('unauthenticated'));
    await assert.rejects(w.engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' }), code('unauthenticated'));
    // session expiry and idle timeout
    const s2 = await w.engine.login({ login: 'ivy@example.org', password: PASSWORD });
    const t4 = await w.engine.issueAccessToken({ refreshToken: s2.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    await w.sql.query(`update e01_identity.sessions set last_used_at = now() - interval '3 hours' where id=$1`, [s2.sessionId]);
    await assert.rejects(w.engine.sessionDirectory(s2.refreshToken), code('unauthenticated'));
    await w.sql.query(`update e01_identity.sessions set last_used_at = now(), expires_at = now() - interval '1 second' where id=$1`, [s2.sessionId]);
    await assert.rejects(verify(t4.token, { requestId: 'r' }), code('unauthenticated'));
    // compartments: not a member → denied; member → allowed after a fresh token; removal bites immediately
    const s3 = await w.engine.login({ login: 'ivy@example.org', password: PASSWORD });
    await w.engine.createCompartment(admin, { id: 'sources', description: 'Protected sources' });
    let c = await w.ctx(s3, 'research');
    assert.deepEqual(c.compartments, []);
    assert.equal((await w.engine.authorize(c, { capability: 'evidence:read', compartment: 'sources' })).reason, 'compartment_denied');
    assert.equal((await w.engine.authorize({ ...c, compartments: ['sources'] }, { capability: 'evidence:read', compartment: 'sources' })).reason, 'compartment_denied');
    assert.deepEqual(await w.engine.listCompartments(c), []);
    assert.equal(await w.engine.inspect(c, 'E01:compartment:sources'), null);
    assert.deepEqual(await w.engine.search(c, { q: 'sources' }), []);
    await w.engine.setCompartmentMember(admin, { compartmentId: 'sources', actorId: ivy.id, member: true });
    c = await w.ctx(s3, 'research');
    assert.deepEqual(c.compartments, ['sources']);
    assert.equal((await w.engine.authorize(c, { capability: 'evidence:read', compartment: 'sources' })).allowed, true);
    assert.equal((await w.engine.authorize(c, { capability: 'evidence:read', resource: 'compartment:sources' })).allowed, true);
    assert.equal((await w.engine.search(c, { q: 'sources' })).length, 1);
    await w.engine.setCompartmentMember(admin, { compartmentId: 'sources', actorId: ivy.id, member: false });
    assert.equal((await w.engine.authorize(c, { capability: 'evidence:read', compartment: 'sources' })).allowed, false);
    // actor revocation with disable: tokens, sessions and login all stop; reinstatement restores
    c = await w.ctx(s3, 'research');
    await w.engine.revokeActor(admin, { actorId: ivy.id, reason: 'left the organization', disable: true });
    assert.equal((await w.engine.authorize(c, { capability: 'evidence:read' })).allowed, false);
    await assert.rejects(w.engine.login({ login: 'ivy@example.org', password: PASSWORD }), code('unauthenticated'));
    await assert.rejects(w.engine.sessionDirectory(s3.refreshToken), code('unauthenticated'));
    await w.engine.reinstateActor(admin, { actorId: ivy.id, reason: 'returned' });
    const s4 = await w.engine.login({ login: 'ivy@example.org', password: PASSWORD });
    assert.equal((await w.engine.authorize(await w.ctx(s4, 'research'), { capability: 'evidence:read' })).allowed, true);
    // the organization cannot lose its last owner
    await assert.rejects(w.engine.revokeActor(admin, { actorId: w.ownerId, reason: 'oops', disable: true }), code('conflict'));
    await assert.rejects(w.engine.removeMember(admin, { actorId: w.ownerId, projectId: '*' }), code('conflict'));
    const chain = await w.engine.audit(await w.ctx(w.owner, 'administration'), { limit: 1000 });
    assert.ok(verifyAuditChain(chain)); assert.ok(chain.some((a) => a.action === 'actor.revoked'));
    assert.doesNotMatch(JSON.stringify(chain), new RegExp(PASSWORD));
  });
});

test('role and membership changes take effect on the next authorize and bump the policy version', needsPg, async () => {
  await withWorld(async (w) => {
    const admin = await w.admin();
    const verify = w.engine.verifier();
    const rae = await w.user('rae@example.org', ['release_manager']);
    const t1 = await w.engine.issueAccessToken({ refreshToken: rae.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'release' });
    const c1 = await verify(t1.token, { requestId: 'r' });
    assert.equal((await w.engine.authorize(c1, { capability: 'release:publish' })).allowed, true);
    const pv0 = BigInt((await w.engine.getOrganization(admin)).policyVersion);
    // role definition change: publish removed from release_manager
    const before = (await w.engine.listRoles(admin)).find((r) => r.name === 'release_manager')!;
    const role = await w.engine.defineRole(admin, { name: 'release_manager', capabilities: before.capabilities.filter((c) => c !== 'release:publish') });
    assert.equal(role.version, 2);
    const pv1 = BigInt((await w.engine.getOrganization(admin)).policyVersion);
    assert.ok(pv1 > pv0);
    const d = await w.engine.authorize(c1, { capability: 'release:publish' });
    assert.equal(d.allowed, false); assert.equal(d.reason, 'stale_policy_version'); assert.equal(d.policyVersion, String(pv1));
    await assert.rejects(verify(t1.token, { requestId: 'r' }), code('unauthenticated'));
    const c2 = await w.ctx(rae.session, 'release');
    assert.ok(!hasCapability(c2, 'release:publish')); assert.equal(c2.policyVersion, String(pv1));
    assert.equal((await w.engine.authorize({ ...c2, capabilities: [...c2.capabilities, 'release:publish'] }, { capability: 'release:publish' })).reason, 'sensitive_capability_not_granted');
    assert.deepEqual((await w.engine.roleHistory(admin, 'release_manager')).map((v) => v.version), [1, 2]);
    // membership change: role swapped
    await w.engine.setMembership(admin, { actorId: rae.id, roles: ['investigator'] });
    assert.equal((await w.engine.authorize(c2, { capability: 'release:read' })).allowed, false);
    const c3 = await w.ctx(rae.session, 'research');
    assert.deepEqual(c3.actor.roles, ['investigator']);
    // membership expiry
    await w.engine.setMembership(admin, { actorId: rae.id, roles: ['investigator'], expiresAt: future(3600) });
    const c4 = await w.ctx(rae.session, 'research');
    await w.sql.query(`update e01_identity.memberships set expires_at = now() - interval '1 second' where actor_id=$1`, [rae.id]);
    assert.equal((await w.engine.authorize(c4, { capability: 'evidence:read' })).reason, 'no_membership');
    await assert.rejects(w.ctx(rae.session, 'research'), code('forbidden'));
    // removal
    await w.engine.setMembership(admin, { actorId: rae.id, roles: ['investigator'] });
    const c5 = await w.ctx(rae.session, 'research');
    await w.engine.removeMember(admin, { actorId: rae.id });
    assert.equal((await w.engine.authorize(c5, { capability: 'evidence:read' })).allowed, false);
    assert.deepEqual((await w.engine.sessionDirectory(rae.session.refreshToken)).organizations, []);
    // events let other engines drop caches
    const feed = await w.engine.events({ ...admin, capabilities: ['identity:events'] }, { limit: 1000 });
    for (const type of ['membership.changed', 'role.changed', 'policy.changed']) assert.ok(feed.some((e) => e.type === type), type);
    assert.ok(feed.every((e) => e.tenantId === 'org-a' && e.engine === 'E01'));
    await assert.rejects(w.engine.events(admin), code('forbidden'));
    // only an owner manages administrative roles; an admin cannot escalate
    const al = await w.user('al@example.org', ['admin'], '*');
    const alCtx = await w.ctx(al.session, 'administration');
    await w.engine.createUser(alCtx, { login: 'new@example.org', password: PASSWORD, displayName: 'New Person', roles: ['investigator'] });
    await assert.rejects(w.engine.setMembership(alCtx, { actorId: al.id, projectId: '*', roles: ['owner'] }), code('forbidden'));
    await assert.rejects(w.engine.createUser(alCtx, { login: 'crony@example.org', password: PASSWORD, displayName: 'Crony', roles: ['admin'] }), code('forbidden'));
    await assert.rejects(w.engine.defineRole(alCtx, { name: 'investigator', capabilities: ['identity:*', 'identity:admin'] }), code('forbidden'));
    await assert.rejects(w.engine.defineRole(alCtx, { name: 'owner', capabilities: ['identity:read'] }), code('invalid_input'));
    await assert.rejects(w.engine.definePurpose(alCtx, { name: 'research', capabilities: ['release:publish'] }), code('forbidden'));
    await assert.rejects(w.engine.setMembership(alCtx, { actorId: rae.id, roles: ['agent_researcher'] }), code('invalid_input'));
    await assert.rejects(w.engine.setMembership(alCtx, { actorId: rae.id, roles: ['no_such_role'] }), code('invalid_input'));
    await assert.rejects(w.engine.defineRole(admin, { name: 'agent_sender', actorKinds: ['agent'], capabilities: ['correspondence:send'] }), code('invalid_input'));
    // non-administrators cannot mutate
    await assert.rejects(w.engine.setMembership(c3, { actorId: rae.id, roles: ['owner'] }), code('forbidden'));
    // a forged admin context for a real non-admin actor fails the current-state check
    await assert.rejects(w.engine.setMembership({ ...c3, capabilities: ['identity:admin'], purpose: 'administration' }, { actorId: rae.id, roles: ['investigator'] }), code('forbidden'));
    // idempotent replay
    const p1 = await w.engine.createProject(admin, { id: 'p-x', name: 'Project X', idempotencyKey: 'k1' });
    assert.deepEqual(await w.engine.createProject(admin, { id: 'p-x', name: 'Project X', idempotencyKey: 'k1' }), p1);
    await assert.rejects(w.engine.createProject(admin, { id: 'p-x', name: 'Different', idempotencyKey: 'k1' }), code('idempotency_conflict'));
    assert.deepEqual(await w.engine.applyUpstreamChange({ ...admin, capabilities: ['identity:events'] }, { eventId: 'e1', kind: 'source_corrected', refs: ['E05:evidence:x'], reason: 'test' }), { affected: [] });
  });
});
