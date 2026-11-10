import test from 'node:test';
import assert from 'node:assert/strict';
import { hasCapability } from '../src/service-kit.ts';
import type { ServiceContext } from '../src/service-kit.ts';
import { createEngine } from '../src/engine/index.ts';
import { PASSWORD, baseConfig, code, needsPg, withWorld } from './engine-fixture.ts';

const future = (seconds: number): string => new Date(Date.now() + seconds * 1000).toISOString();

test('two organizations are isolated through every method, search, count, export, audit and event feed', needsPg, async () => {
  await withWorld(async (w) => {
    const adminA = await w.admin();
    // Organization B with its own owner, created by A's administrator (who gets no access to it).
    const b = await w.engine.createOrganization(adminA, { id: 'org-b', name: 'Birch Assembly', defaultLocale: 'es', project: { id: 'main', name: 'Principal', kind: 'publishing' }, owner: { login: 'bea@example.org', password: PASSWORD, displayName: 'Bea Birch' } });
    assert.equal(b.organization.id, 'org-b');
    const bea = await w.engine.login({ login: 'bea@example.org', password: PASSWORD });
    const adminB = await w.ctx(bea, 'administration', { tenantId: 'org-b' });
    assert.equal(adminB.locale, 'es');
    await assert.rejects(w.ctx(w.owner, 'administration', { tenantId: 'org-b' }), code('forbidden'));
    await assert.rejects(w.ctx(bea, 'administration', { tenantId: 'org-a' }), code('forbidden'));
    assert.deepEqual((await w.engine.sessionDirectory(bea.refreshToken)).organizations.map((o) => o.organization.id), ['org-b']);
    assert.deepEqual((await w.engine.listMyOrganizations(adminA)).map((o) => o.organization.id), ['org-a']);
    // A's data
    const ivy = await w.user('ivy@example.org', ['investigator']);
    await w.engine.createProject(adminA, { id: 'secret-project', name: 'Heron inquiry', kind: 'campaign' });
    await w.engine.createCompartment(adminA, { id: 'heron-sources', description: 'Heron source protection' });
    await w.engine.defineRole(adminA, { name: 'heron_analyst', description: 'Heron analyst', capabilities: ['knowledge:read'] });
    const agentA = await w.engine.createAgent(adminA, { name: 'Heron research agent', roles: ['agent_researcher'] });
    const grantA = await w.engine.createGrant(adminA, { actorId: ivy.id, capability: 'correspondence:send', purpose: 'correspondence', reason: 'Heron outreach', expiresAt: future(3600) });
    const ivyTokenA = await w.engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    // B sees nothing of A through any read
    assert.deepEqual((await w.engine.listProjects(adminB)).map((p) => p.id), ['main']);
    assert.deepEqual((await w.engine.listMembers(adminB)).map((m) => m.actor.login), ['bea@example.org']);
    assert.deepEqual(await w.engine.listAgents(adminB), []);
    assert.deepEqual(await w.engine.listGrants(adminB, { includeInactive: true }), []);
    assert.deepEqual(await w.engine.listCompartments(adminB), []);
    assert.ok(!(await w.engine.listRoles(adminB)).some((r) => r.name === 'heron_analyst'));
    assert.deepEqual(await w.engine.listSessions(adminB, { actorId: ivy.id }), []);
    assert.equal(await w.engine.getActor(adminB, ivy.id), null);
    for (const q of ['Heron', 'ivy', 'heron_analyst', 'outreach', 'Ada', 'secret']) assert.deepEqual(await w.engine.search(adminB, { q }), [], `search ${q}`);
    for (const ref of [`E01:actor:${ivy.id}`, `E01:user:${ivy.id}`, `E01:agent:${agentA.id}`, 'E01:project:secret-project', 'E01:organization:org-a', 'E01:role:heron_analyst', `E01:grant:${grantA.id}`, 'E01:compartment:heron-sources'])
      assert.equal(await w.engine.inspect(adminB, ref), null, ref);
    assert.deepEqual(await w.engine.counts(adminB), { projects: 1, members: 1, agents: 0, services: 0, roles: (await w.engine.listRoles(adminB)).length, activeGrants: 0, compartments: 0 });
    const exported = JSON.stringify(await w.engine.exportDirectory(adminB));
    for (const leak of ['Heron', 'ivy@example.org', 'ada@example.org', 'org-a', ivy.id]) assert.ok(!exported.includes(leak), `export leaks ${leak}`);
    assert.doesNotMatch(exported, /password|scrypt|refresh/i);
    const auditB = JSON.stringify(await w.engine.audit(adminB, { limit: 1000 }));
    const eventsB = JSON.stringify(await w.engine.events({ ...adminB, capabilities: ['identity:events'] }, { limit: 1000 }));
    for (const leak of ['Heron', ivy.id, agentA.id, grantA.id, 'secret-project']) { assert.ok(!auditB.includes(leak)); assert.ok(!eventsB.includes(leak)); }
    assert.equal((await w.engine.explain(adminB, ivy.id, 'evidence:read')).reason, 'no_membership');
    assert.equal((await w.engine.checkGrant(adminB, { actorId: ivy.id, capability: 'correspondence:send', purpose: 'correspondence' })).valid, false);
    // B cannot write into A
    const notFound = code('not_found');
    await assert.rejects(w.engine.revokeGrant({ ...adminB, capabilities: [...adminB.capabilities] }, { grantId: grantA.id, reason: 'x' }), notFound);
    await assert.rejects(w.engine.revokeSession(adminB, { sessionId: ivy.session.sessionId }), notFound);
    await assert.rejects(w.engine.revokeActor(adminB, { actorId: ivy.id, reason: 'x', disable: true }), notFound);
    await assert.rejects(w.engine.resetPassword(adminB, { actorId: ivy.id, newPassword: 'cross tenant takeover' }), notFound);
    await assert.rejects(w.engine.setMembership(adminB, { actorId: agentA.id, roles: ['agent_researcher'] }), notFound);
    await assert.rejects(w.engine.issueAgentToken(adminB, { agentId: agentA.id, purpose: 'research', capabilities: ['evidence:read'] }), code('forbidden'));
    await assert.rejects(w.engine.setCompartmentMember(adminB, { compartmentId: 'heron-sources', actorId: ivy.id, member: true }), notFound);
    await assert.rejects(w.engine.createGrant(adminB, { actorId: ivy.id, capability: 'release:publish', purpose: 'release', reason: 'x', expiresAt: future(60) }), notFound);
    // B revoking A's token id has no effect on A (revocations are per organization)
    await w.engine.revokeToken(adminB, { tokenId: ivyTokenA.tokenId });
    const ivyCtx = await w.engine.verifier()(ivyTokenA.token, { requestId: 'r' });
    assert.equal((await w.engine.authorize(ivyCtx, { capability: 'evidence:read' })).allowed, true);
    // a context for A carrying B's tenant id is denied on current state
    assert.equal((await w.engine.authorize({ ...ivyCtx, tenantId: 'org-b' }, { capability: 'evidence:read' })).allowed, false);
    // A user can belong to both organizations; home-organization administrators then cannot reset the password
    await w.engine.setMembership(adminB, { login: 'ivy@example.org', roles: ['auditor'] });
    assert.deepEqual((await w.engine.sessionDirectory(ivy.session.refreshToken)).organizations.map((o) => o.organization.id), ['org-a', 'org-b']);
    const ivyB = await w.ctx(ivy.session, 'audit', { tenantId: 'org-b' });
    assert.ok(hasCapability(ivyB, 'evidence:read') && !hasCapability(ivyB, 'evidence:write'));
    assert.equal((await w.engine.authorize(ivyCtx, { capability: 'evidence:write' })).allowed, true, 'access in A is untouched by membership in B');
    await assert.rejects(w.engine.resetPassword(adminA, { actorId: ivy.id, newPassword: 'administrator reset 123' }), code('forbidden'));
    // B suspending ivy affects only B
    await w.engine.revokeActor(adminB, { actorId: ivy.id, reason: 'left B', disable: true });
    assert.equal((await w.engine.authorize(ivyB, { capability: 'evidence:read' })).allowed, false);
    assert.equal((await w.engine.authorize(ivyCtx, { capability: 'evidence:read' })).allowed, true);
    // non-admin members see only their own project
    const ivyA = await w.ctx(ivy.session, 'research');
    assert.deepEqual((await w.engine.listProjects(ivyA)).map((p) => p.id), ['main']);
    await assert.rejects(w.engine.listMembers(ivyA, { projectId: 'secret-project' }), notFound);
    assert.equal(await w.engine.inspect(ivyA, 'E01:project:secret-project'), null);
    assert.deepEqual(await w.engine.search(ivyA, { q: 'Heron inquiry' }), []);
    await assert.rejects(w.engine.exportDirectory(ivyA), code('forbidden'));
    await assert.rejects(w.engine.audit({ ...ivyA, capabilities: [] }), code('forbidden'));
  });
});

test('purpose grants: exact, time-bounded, revocable, bounded and never implied by research access', needsPg, async () => {
  await withWorld(async (w) => {
    const admin = await w.admin();
    const ivy = await w.user('ivy@example.org', ['investigator']);
    const verify = w.engine.verifier();
    // validation
    const base = { actorId: ivy.id, purpose: 'correspondence', reason: 'Outreach to the fictional ministry', expiresAt: future(3600) };
    await assert.rejects(w.engine.createGrant(admin, { ...base, capability: 'correspondence:*' }), code('invalid_input'));
    await assert.rejects(w.engine.createGrant(admin, { ...base, capability: 'identity:admin' }), code('forbidden'));
    await assert.rejects(w.engine.createGrant(admin, { ...base, capability: 'correspondence:send', actorId: w.ownerId }), code('forbidden'));
    await assert.rejects(w.engine.createGrant(admin, { ...base, capability: 'correspondence:send', expiresAt: future(90 * 86400) }), code('invalid_input'));
    await assert.rejects(w.engine.createGrant(admin, { ...base, capability: 'correspondence:send', purpose: 'nonsense' }), code('invalid_input'));
    await assert.rejects(w.engine.createGrant(await w.ctx(ivy.session, 'research'), { ...base, capability: 'correspondence:send', actorId: w.ownerId }), code('forbidden'));
    const before = await w.ctx(ivy.session, 'correspondence');
    assert.ok(!hasCapability(before, 'correspondence:send'));
    const grant = await w.engine.createGrant(admin, { ...base, capability: 'correspondence:send', resource: 'E03:thread:t-1', bounds: { maxUses: 2, recipients: ['press@ministry.example.org'], maxAmount: 10 }, idempotencyKey: 'g1' });
    assert.equal(grant.state, 'active');
    assert.equal((await w.engine.createGrant(admin, { ...base, capability: 'correspondence:send', resource: 'E03:thread:t-1', bounds: { maxUses: 2, recipients: ['press@ministry.example.org'], maxAmount: 10 }, idempotencyKey: 'g1' })).id, grant.id);
    // the grant applies only to its purpose
    const research = await w.ctx(ivy.session, 'research');
    assert.ok(!hasCapability(research, 'correspondence:send'));
    assert.equal((await w.engine.authorize({ ...research, capabilities: [...research.capabilities, 'correspondence:send'] }, { capability: 'correspondence:send', resource: 'E03:thread:t-1' })).allowed, false);
    const c = await w.ctx(ivy.session, 'correspondence');
    assert.ok(hasCapability(c, 'correspondence:send') && !hasCapability(c, 'correspondence:contact'));
    const d = await w.engine.authorize(c, { capability: 'correspondence:send', resource: 'E03:thread:t-1@4' });
    assert.equal(d.allowed, true); assert.equal(d.reason, 'grant'); assert.equal(d.via?.kind, 'grant');
    assert.equal((await w.engine.authorize(c, { capability: 'correspondence:send', resource: 'E03:thread:other' })).allowed, false, 'resource outside the grant');
    assert.equal((await w.engine.authorize(c, { capability: 'correspondence:send' })).allowed, false, 'resource-bound grant needs the resource');
    assert.equal((await w.engine.authorize(c, { capability: 'correspondence:contact', resource: 'E03:thread:t-1' })).allowed, false);
    // checkGrant and bounded use
    assert.equal((await w.engine.checkGrant(c, { capability: 'correspondence:send', resource: 'E03:thread:t-1', recipient: 'press@ministry.example.org' })).valid, true);
    assert.equal((await w.engine.checkGrant(c, { capability: 'correspondence:send', resource: 'E03:thread:t-1', recipient: 'someone@else.example.org' })).reason, 'recipient is outside the grant');
    assert.equal((await w.engine.checkGrant(c, { capability: 'correspondence:send', resource: 'E03:thread:t-1', recipient: 'press@ministry.example.org', amount: 11 })).valid, false);
    const use = { grantId: grant.id, recipient: 'press@ministry.example.org', resource: 'E03:thread:t-1' };
    assert.equal((await w.engine.useGrant(c, { ...use, useKey: 'send-1', amount: 4 })).remainingUses, 1);
    assert.equal((await w.engine.useGrant(c, { ...use, useKey: 'send-1', amount: 4 })).remainingUses, 1, 'replay does not consume twice');
    await assert.rejects(w.engine.useGrant(c, { ...use, useKey: 'send-x', recipient: 'someone@else.example.org' }), code('grant_invalid'));
    await assert.rejects(w.engine.useGrant(c, { ...use, useKey: 'send-y', amount: 7 }), code('grant_invalid'));
    await assert.rejects(w.engine.useGrant(admin, { ...use, useKey: 'send-z' }), code('not_found'));
    const concurrent = await Promise.allSettled(['a', 'b', 'c'].map((key) => w.engine.useGrant(c, { ...use, useKey: `send-2${key}` })));
    assert.equal(concurrent.filter((r) => r.status === 'fulfilled').length, 1, 'only one of three concurrent uses fits the remaining bound');
    assert.equal((await w.engine.authorize(c, { capability: 'correspondence:send', resource: 'E03:thread:t-1' })).allowed, false, 'exhausted grant no longer authorizes');
    assert.equal((await w.engine.listGrants(admin, { actorId: ivy.id, includeInactive: true }))[0]!.state, 'exhausted');
    // expiry
    const short = await w.engine.createGrant(admin, { actorId: ivy.id, capability: 'release:publish', purpose: 'release', reason: 'One release', expiresAt: future(3600) });
    const rel = await w.ctx(ivy.session, 'release');
    assert.equal((await w.engine.authorize(rel, { capability: 'release:publish' })).allowed, true);
    await w.sql.query(`update e01_identity.grants set expires_at = now() - interval '1 second' where id=$1`, [short.id]);
    const expired = await w.engine.authorize(rel, { capability: 'release:publish' });
    assert.equal(expired.allowed, false); assert.match(expired.trail.map((s) => s.detail).join('|'), /expired/);
    assert.ok(!hasCapability(await w.ctx(ivy.session, 'release'), 'release:publish'));
    assert.equal((await w.engine.checkGrant(rel, { capability: 'release:publish' })).reason, 'expired');
    // revocation: authorize denies at once and the grantee's outstanding token stops verifying
    const g3 = await w.engine.createGrant(admin, { actorId: ivy.id, capability: 'resources:spend', purpose: 'finance', reason: 'Records request fee', bounds: { maxAmount: 50, currency: 'XTS' }, expiresAt: future(3600) });
    const finToken = await w.engine.issueAccessToken({ refreshToken: ivy.session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'finance' });
    const fin = await verify(finToken.token, { requestId: 'r' });
    assert.equal((await w.engine.authorize(fin, { capability: 'resources:spend' })).allowed, true);
    assert.deepEqual((await w.engine.checkGrant(fin, { capability: 'resources:spend', amount: 20 })).grant?.bounds, { maxAmount: 50, currency: 'XTS' });
    await assert.rejects(w.engine.revokeGrant(fin, { grantId: g3.id, reason: 'self' }), code('forbidden'));
    assert.equal((await w.engine.revokeGrant(admin, { grantId: g3.id, reason: 'Request withdrawn' })).state, 'revoked');
    assert.equal((await w.engine.authorize(fin, { capability: 'resources:spend' })).allowed, false);
    await assert.rejects(verify(finToken.token, { requestId: 'r' }), code('unauthenticated'));
    assert.ok(!hasCapability(await w.ctx(ivy.session, 'finance'), 'resources:spend'));
    const feed = await w.engine.events({ ...admin, capabilities: ['identity:events'] }, { limit: 1000 });
    assert.ok(feed.some((e) => e.type === 'grant.issued' && e.subject === `E01:grant:${g3.id}`) && feed.some((e) => e.type === 'grant.revoked' && e.subject === `E01:grant:${g3.id}`));
    const inspected = await w.engine.inspect(admin, `E01:grant:${g3.id}`);
    assert.equal(inspected?.state, 'revoked'); assert.equal(inspected?.blocked, true); assert.ok(inspected!.history.some((h) => h.action === 'grant.revoked'));
    // disclosure of protected identities needs an explicit grant even for the owner
    assert.ok(!hasCapability(await w.ctx(w.owner, 'participant_support'), 'intake:disclose_identity'));
    const pat = await w.user('pat@example.org', ['participant_support']);
    assert.ok(hasCapability(await w.ctx(pat.session, 'participant_support'), 'intake:disclose_identity'));
    assert.ok(!hasCapability(await w.ctx(pat.session, 'research'), 'intake:disclose_identity'));
  });
});

test('service and agent identities: bounded tokens, no administration, no secrets', needsPg, async () => {
  await withWorld(async (w) => {
    const admin = await w.admin();
    const verify = w.engine.verifier();
    // service identity with client-credentials sign-in
    const { service, secret } = await w.engine.createServiceIdentity(admin, { name: 'Orchestrator', roles: ['service_orchestrator'], projectId: '*' });
    assert.equal((await w.sql.query(`select 1 from e01_identity.actors where secret_hash = $1 or secret_hash is null and id = $2`, [secret, service.id])).length, 0, 'secret is stored hashed');
    await assert.rejects(w.engine.authenticateService({ serviceId: service.id, secret: 'wrong', projectId: 'main', purpose: 'operations' }), code('unauthenticated'));
    await assert.rejects(w.engine.authenticateService({ serviceId: 'no-such-service', secret, projectId: 'main', purpose: 'operations' }), code('unauthenticated'));
    const svcToken = await w.engine.authenticateService({ serviceId: service.id, secret, projectId: 'main', purpose: 'operations' });
    const svc = await verify(svcToken.token, { requestId: 'r' });
    assert.equal(svc.actor.kind, 'service');
    assert.ok(hasCapability(svc, 'evidence:write') && hasCapability(svc, 'evidence:events') && svc.capabilities.includes('identity:issue_token'));
    for (const cap of ['identity:admin', 'identity:grant', 'release:publish', 'correspondence:send', 'resources:spend']) assert.ok(!hasCapability(svc, cap), cap);
    assert.equal((await w.engine.events(svc)).length > 0, true);
    await assert.rejects(w.engine.createUser(svc, { login: 'x@example.org', password: PASSWORD, displayName: 'X' }), code('forbidden'));
    await assert.rejects(w.engine.createGrant(svc, { actorId: w.ownerId, capability: 'release:publish', purpose: 'release', reason: 'x', expiresAt: future(60) }), code('forbidden'));
    // humans cannot use a service sign-in and services have no password login
    await assert.rejects(w.engine.authenticateService({ serviceId: w.ownerId, secret, projectId: 'main', purpose: 'operations' }), code('unauthenticated'));
    // rotating the secret invalidates the old one
    const rotated = await w.engine.rotateServiceSecret(admin, service.id);
    await assert.rejects(w.engine.authenticateService({ serviceId: service.id, secret, projectId: 'main', purpose: 'operations' }), code('unauthenticated'));
    await w.engine.authenticateService({ serviceId: service.id, secret: rotated.secret, projectId: 'main', purpose: 'operations' });
    // trusted in-process issuance and admin-issued service tokens
    const hostToken = await w.engine.host.issueServiceToken({ tenantId: 'org-a', serviceId: service.id, projectId: 'main', purpose: 'operations', capabilities: ['evidence:events'] });
    assert.deepEqual(hostToken.capabilities, ['evidence:events']);
    await assert.rejects(w.engine.host.issueServiceToken({ tenantId: 'org-a', serviceId: w.ownerId, projectId: 'main', purpose: 'operations' }), code('forbidden'));
    assert.equal((await w.engine.issueServiceToken(admin, { serviceId: service.id, purpose: 'operations' })).actorId, service.id);
    // agents
    const agent = await w.engine.createAgent(admin, { name: 'Research agent', description: 'Reads and summarises', roles: ['agent_researcher'] });
    assert.equal(agent.kind, 'agent'); assert.equal(agent.login, null);
    await assert.rejects(w.engine.createAgent(admin, { name: 'Bad agent', roles: ['investigator'] }), code('invalid_input'));
    await assert.rejects(w.engine.createAgent(admin, { name: 'Bad agent', roles: ['service_orchestrator'] }), code('invalid_input'));
    const at = await w.engine.issueAgentToken(svc, { agentId: agent.id, purpose: 'research', capabilities: ['evidence:read', 'knowledge:*'], ttlSeconds: 120 });
    const agentCtx = await verify(at.token, { requestId: 'r' });
    assert.equal(agentCtx.actor.kind, 'agent'); assert.deepEqual(agentCtx.capabilities, ['evidence:read', 'knowledge:*']);
    assert.ok(new Date(at.expiresAt).getTime() - Date.now() <= 121000);
    assert.equal((await w.engine.authorize(agentCtx, { capability: 'knowledge:write' })).allowed, true);
    assert.equal((await w.engine.authorize(agentCtx, { capability: 'evidence:write' })).reason, 'not_in_token');
    // explicit list is strict; forbidden and unavailable capabilities refuse the whole token
    for (const caps of [['identity:admin'], ['identity:read'], ['evidence:read', 'correspondence:send'], ['release:publish'], ['evidence:export'], ['evidence:events'], ['resources:spend'], ['intake:disclose_identity'], []])
      await assert.rejects(w.engine.issueAgentToken(svc, { agentId: agent.id, purpose: 'research', capabilities: caps }), (e: unknown) => code((e as { code: string }).code === 'invalid_input' ? 'invalid_input' : 'forbidden')(e), JSON.stringify(caps));
    await assert.rejects(w.engine.issueAgentToken(svc, { agentId: agent.id, purpose: 'research', capabilities: ['evidence:read'], ttlSeconds: 7200 }), code('invalid_input'));
    await assert.rejects(w.engine.issueAgentToken(svc, { agentId: w.ownerId, purpose: 'research', capabilities: ['evidence:read'] }), code('forbidden'), 'a human is not an agent');
    await assert.rejects(w.engine.issueAgentToken(svc, { agentId: service.id, purpose: 'operations', capabilities: ['evidence:events'] }), code('forbidden'));
    // only issuers may issue; an agent cannot mint tokens, administer or read event feeds
    const ivy = await w.user('ivy@example.org', ['investigator']);
    await assert.rejects(w.engine.issueAgentToken(await w.ctx(ivy.session, 'research'), { agentId: agent.id, purpose: 'research', capabilities: ['evidence:read'] }), code('forbidden'));
    await assert.rejects(w.engine.issueAgentToken({ ...agentCtx, capabilities: ['identity:*'] }, { agentId: agent.id, purpose: 'research', capabilities: ['evidence:read'] }), code('forbidden'), 'identity:* never covers issue_token');
    await assert.rejects(w.engine.issueAgentToken({ ...agentCtx, capabilities: ['identity:issue_token'] }, { agentId: agent.id, purpose: 'research', capabilities: ['evidence:read'] }), code('forbidden'), 'forged agent context fails the current-state check');
    for (const cap of ['identity:admin', 'identity:grant', 'identity:issue_token', 'evidence:events', 'resources:admin'])
      assert.equal((await w.engine.authorize({ ...agentCtx, capabilities: [cap] }, { capability: cap })).reason, 'agent_forbidden', cap);
    // delegation ceiling: an agent acting for an auditor cannot write
    const aud = await w.user('aud@example.org', ['auditor']);
    await assert.rejects(w.engine.issueAgentToken(svc, { agentId: agent.id, purpose: 'research', capabilities: ['knowledge:*'], onBehalfOf: aud.id }), code('forbidden'));
    assert.deepEqual((await w.engine.issueAgentToken(svc, { agentId: agent.id, purpose: 'research', capabilities: ['knowledge:read'], onBehalfOf: aud.id })).capabilities, ['knowledge:read']);
    // sensitive agent action only through an explicit, short grant; some actions are never grantable to agents
    await assert.rejects(w.engine.createGrant(admin, { actorId: agent.id, capability: 'release:publish', purpose: 'release', reason: 'x', expiresAt: future(600) }), code('forbidden'));
    await assert.rejects(w.engine.createGrant(admin, { actorId: agent.id, capability: 'orchestration:admin', purpose: 'operations', reason: 'x', expiresAt: future(600) }), code('forbidden'));
    await assert.rejects(w.engine.createGrant(admin, { actorId: agent.id, capability: 'correspondence:send', purpose: 'correspondence', reason: 'x', expiresAt: future(7 * 86400) }), code('invalid_input'));
    const g = await w.engine.createGrant(admin, { actorId: agent.id, capability: 'correspondence:send', purpose: 'correspondence', reason: 'Send three approved follow-ups', bounds: { maxUses: 3 }, expiresAt: future(3600) });
    const sender = await verify((await w.engine.issueAgentToken(svc, { agentId: agent.id, purpose: 'correspondence', capabilities: ['correspondence:send'] })).token, { requestId: 'r' });
    assert.equal((await w.engine.authorize(sender, { capability: 'correspondence:send' })).via?.kind, 'grant');
    await w.engine.revokeGrant(admin, { grantId: g.id, reason: 'done' });
    assert.equal((await w.engine.authorize(sender, { capability: 'correspondence:send' })).allowed, false);
    await assert.rejects(w.engine.issueAgentToken(svc, { agentId: agent.id, purpose: 'correspondence', capabilities: ['correspondence:send'] }), code('forbidden'));
    // revoking the agent kills its tokens
    const live = await w.engine.issueAgentToken(svc, { agentId: agent.id, purpose: 'research', capabilities: ['evidence:read'] });
    await w.engine.revokeActor(admin, { actorId: agent.id, reason: 'runaway', disable: true });
    await assert.rejects(verify(live.token, { requestId: 'r' }), code('unauthenticated'));
    await assert.rejects(w.engine.issueAgentToken(svc, { agentId: agent.id, purpose: 'research', capabilities: ['evidence:read'] }), code('forbidden'));
    // token issuance is audited without token material
    const audit = JSON.stringify(await w.engine.audit(admin, { limit: 1000 }));
    assert.match(audit, /token\.issued/); assert.ok(!audit.includes(at.token) && !audit.includes(secret) && !audit.includes(rotated.secret));
    assert.deepEqual((await w.engine.listAgents(admin)).map((a) => [a.id, a.status]), [[agent.id, 'disabled']]);
  });
});

test('signing keys: sealed at rest, rotation keeps old tokens valid until expiry, revocation removes a key', needsPg, async () => {
  await withWorld(async (w) => {
    const verify = w.engine.verifier();
    const t1 = await w.engine.issueAccessToken({ refreshToken: w.owner.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    const kid = (token: string): string => JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString()).kid as string;
    const rows = await w.sql.query<{ kid: string; private_sealed: string; public_pem: string }>('select * from e01_identity.signing_keys');
    assert.equal(rows.length, 1); assert.match(rows[0]!.private_sealed, /^v1\./); assert.ok(!rows[0]!.private_sealed.includes('PRIVATE KEY'));
    assert.deepEqual(Object.keys(await w.engine.publicKeys()), [kid(t1.token)]);
    // rotate (platform owner over the ctx API; trusted host method too)
    const admin = await w.admin();
    const rotated = await w.engine.rotateSigningKey(admin);
    assert.deepEqual(rotated.retired, [kid(t1.token)]);
    const t2 = await w.engine.issueAccessToken({ refreshToken: w.owner.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' });
    assert.equal(kid(t2.token), rotated.kid); assert.notEqual(kid(t2.token), kid(t1.token));
    await verify(t1.token, { requestId: 'r' }); await verify(t2.token, { requestId: 'r' });
    const published = await w.engine.jwks();
    assert.deepEqual(Object.keys(published.keys).sort(), [kid(t1.token), kid(t2.token)].sort());
    assert.ok(published.jwks.keys.every((key) => (key as { kty: string; d?: string }).kty === 'OKP' && (key as { d?: string }).d === undefined));
    // a second engine instance (another process) with the same key encryption key verifies and signs
    const other = createEngine({ sql: w.sql, config: baseConfig });
    await other.verifier()(t1.token, { requestId: 'r' });
    assert.equal(kid((await other.issueAccessToken({ refreshToken: w.owner.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' })).token), rotated.kid);
    // a wrong key encryption key cannot open the signing key
    const wrong = createEngine({ sql: w.sql, config: { ...baseConfig, keyEncryptionKey: 'another-key-encryption-key-0123456789' } });
    await assert.rejects(wrong.issueAccessToken({ refreshToken: w.owner.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'research' }), code('unavailable'));
    // once the retired key's verification window passes, its tokens are rejected
    await w.sql.query(`update e01_identity.signing_keys set verify_until = now() - interval '1 second' where kid=$1`, [kid(t1.token)]);
    const fresh = createEngine({ sql: w.sql, config: baseConfig });
    await assert.rejects(fresh.verifier()(t1.token, { requestId: 'r' }), code('unauthenticated'));
    await fresh.verifier()(t2.token, { requestId: 'r' });
    // revoking the active key rejects its tokens; the next issuance creates a new key
    await w.engine.revokeSigningKey(admin, rotated.kid);
    await assert.rejects(verify(t2.token, { requestId: 'r' }), code('unauthenticated'));
    // only the platform organization's owner administers keys
    const t3 = await w.engine.issueAccessToken({ refreshToken: w.owner.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'administration' });
    const admin2 = await verify(t3.token, { requestId: 'r' });
    const b = await w.engine.createOrganization(admin2, { id: 'org-b', name: 'Birch', owner: { login: 'bea@example.org', password: PASSWORD, displayName: 'Bea' } });
    const bea = await w.engine.login({ login: 'bea@example.org', password: PASSWORD });
    const adminB = await w.ctx(bea, 'administration', { tenantId: b.organization.id });
    await assert.rejects(w.engine.rotateSigningKey(adminB), code('forbidden'));
    const al = await w.user('al@example.org', ['admin'], '*');
    await assert.rejects(w.engine.rotateSigningKey(await w.ctx(al.session, 'administration')), code('forbidden'));
    // maintenance rotates keys past the configured age
    await w.sql.query(`update e01_identity.signing_keys set created_at = now() - interval '40 days' where status='active'`);
    assert.notEqual((await w.engine.host.maintenance({ rotateKeysOlderThanSeconds: 30 * 86400 })).rotated, null);
    assert.equal((await w.engine.host.maintenance({ rotateKeysOlderThanSeconds: 30 * 86400 })).rotated, null);
    const ctx: ServiceContext = await w.admin();
    assert.equal((await w.engine.authorize(ctx, { capability: 'identity:admin' })).allowed, true);
  });
});
