// HTTP routes for the E01 service. Every non-public route receives a verified ServiceContext.
import { DomainError } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { standardRoutes } from '../service-kit.ts';
import type { HttpRequest, Route } from '../service-kit.ts';
import type { IdentityEngine } from './index.ts';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Body = any;
const body = (r: HttpRequest): Body => {
  if (r.body === null || typeof r.body !== 'object' || Array.isArray(r.body)) throw new DomainError('invalid_input', 'A JSON object body is required');
  return r.body;
};
const q = (r: HttpRequest, name: string): string | undefined => r.query.get(name) ?? undefined;
const opt = <T extends Record<string, unknown>>(value: T): { [K in keyof T]: Exclude<T[K], undefined> } => Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as never;
const j = (value: unknown): Json => (value ?? null) as Json;

export function routes(engine: IdentityEngine): Route[] {
  type H = (r: HttpRequest) => Promise<unknown>;
  const route = (method: Route['method'], path: string, handler: H, isPublic = false): Route => ({ method, path, ...(isPublic ? { public: true } : {}), handler: async (r) => j(await handler(r)) });
  const pub = (method: Route['method'], path: string, handler: H): Route => route(method, path, handler, true);
  return [
    ...standardRoutes(engine),
    // ── public: keys, bootstrap, sign-in ──
    pub('GET', '/v1/keys', () => engine.jwks()),
    pub('GET', '/v1/bootstrap', async () => ({ bootstrapped: await engine.isBootstrapped() })),
    pub('POST', '/v1/bootstrap', (r) => {
      // Over HTTP the one-time bootstrap always requires the deployment's bootstrap token.
      if (typeof body(r).bootstrapToken !== 'string' || body(r).bootstrapToken === '') throw new DomainError('forbidden', 'Bootstrap is not permitted');
      return engine.bootstrapFirstAdministrator(body(r), { requireToken: true });
    }),
    pub('POST', '/v1/sessions', (r) => engine.login(body(r))),
    pub('POST', '/v1/sessions/directory', (r) => engine.sessionDirectory(body(r).refreshToken)),
    pub('POST', '/v1/sessions/logout', async (r) => { await engine.logout(body(r).refreshToken); return { ok: true }; }),
    pub('POST', '/v1/tokens', (r) => engine.issueAccessToken(body(r))),
    pub('POST', '/v1/tokens/service', (r) => engine.authenticateService(body(r))),
    pub('POST', '/v1/oidc/start', (r) => engine.startOidcLogin(body(r))),
    pub('POST', '/v1/oidc/callback', (r) => engine.completeOidcLogin(body(r))),
    // ── decisions ──
    route('POST', '/v1/policy/evaluate', (r) => engine.authorize(r.ctx, body(r))),
    route('GET', '/v1/access/explain', (r) => engine.explain(r.ctx, q(r, 'actorId') ?? r.ctx.actor.id, q(r, 'capability') ?? '', q(r, 'resource'), opt({ purpose: q(r, 'purpose'), projectId: q(r, 'projectId'), compartment: q(r, 'compartment') }))),
    route('GET', '/v1/whoami', (r) => engine.whoami(r.ctx)),
    // ── grants ──
    route('POST', '/v1/capability-grants', (r) => engine.createGrant(r.ctx, body(r))),
    route('GET', '/v1/capability-grants', (r) => engine.listGrants(r.ctx, opt({ actorId: q(r, 'actorId'), capability: q(r, 'capability'), projectId: q(r, 'projectId'), includeInactive: q(r, 'includeInactive') === 'true' ? true : undefined }))),
    route('POST', '/v1/capability-grants/check', (r) => engine.checkGrant(r.ctx, body(r))),
    route('POST', '/v1/grants/:id/revoke', (r) => engine.revokeGrant(r.ctx, { grantId: r.params.id as string, reason: body(r).reason })),
    route('POST', '/v1/grants/:id/use', (r) => engine.useGrant(r.ctx, { ...body(r), grantId: r.params.id as string })),
    // ── organization, projects ──
    route('GET', '/v1/organization', (r) => engine.getOrganization(r.ctx)),
    route('PATCH', '/v1/organization', (r) => engine.updateOrganization(r.ctx, body(r))),
    route('POST', '/v1/organizations', (r) => engine.createOrganization(r.ctx, body(r))),
    route('GET', '/v1/my/organizations', (r) => engine.listMyOrganizations(r.ctx)),
    route('GET', '/v1/projects', (r) => engine.listProjects(r.ctx)),
    route('POST', '/v1/projects', (r) => engine.createProject(r.ctx, body(r))),
    route('PATCH', '/v1/projects/:id', (r) => engine.updateProject(r.ctx, r.params.id as string, body(r))),
    route('GET', '/v1/counts', (r) => engine.counts(r.ctx)),
    route('GET', '/v1/export', (r) => engine.exportDirectory(r.ctx)),
    // ── actors, memberships ──
    route('POST', '/v1/users', (r) => engine.createUser(r.ctx, body(r))),
    route('GET', '/v1/users', (r) => engine.listUsers(r.ctx)),
    route('GET', '/v1/actors/:id', async (r) => { const a = await engine.getActor(r.ctx, r.params.id as string); if (a === null) throw new DomainError('not_found', 'Not found'); return a; }),
    route('POST', '/v1/users/:id/password', async (r) => { await engine.resetPassword(r.ctx, { actorId: r.params.id as string, newPassword: body(r).newPassword }); return { ok: true }; }),
    route('POST', '/v1/password', async (r) => { await engine.changePassword(r.ctx, body(r)); return { ok: true }; }),
    route('GET', '/v1/members', (r) => engine.listMembers(r.ctx, opt({ projectId: q(r, 'projectId'), kind: q(r, 'kind') as 'human' | 'agent' | 'service' | undefined }))),
    route('PUT', '/v1/members', (r) => engine.setMembership(r.ctx, body(r))),
    route('POST', '/v1/members/remove', async (r) => { await engine.removeMember(r.ctx, body(r)); return { ok: true }; }),
    route('GET', '/v1/agents', (r) => engine.listAgents(r.ctx)),
    route('POST', '/v1/agents', (r) => engine.createAgent(r.ctx, body(r))),
    route('POST', '/v1/agents/:id/tokens', (r) => engine.issueAgentToken(r.ctx, { ...body(r), agentId: r.params.id as string })),
    route('GET', '/v1/services', (r) => engine.listServiceIdentities(r.ctx)),
    route('POST', '/v1/services', (r) => engine.createServiceIdentity(r.ctx, body(r))),
    route('POST', '/v1/services/:id/secret', (r) => engine.rotateServiceSecret(r.ctx, r.params.id as string)),
    route('POST', '/v1/services/:id/tokens', (r) => engine.issueServiceToken(r.ctx, { ...body(r), serviceId: r.params.id as string })),
    // ── roles, purposes, compartments ──
    route('GET', '/v1/roles', (r) => engine.listRoles(r.ctx)),
    route('PUT', '/v1/roles/:name', (r) => engine.defineRole(r.ctx, { ...body(r), name: r.params.name as string })),
    route('GET', '/v1/roles/:name/history', (r) => engine.roleHistory(r.ctx, r.params.name as string)),
    route('GET', '/v1/purposes', (r) => engine.listPurposes(r.ctx)),
    route('PUT', '/v1/purposes/:name', (r) => engine.definePurpose(r.ctx, { ...body(r), name: r.params.name as string })),
    route('GET', '/v1/compartments', (r) => engine.listCompartments(r.ctx, opt({ projectId: q(r, 'projectId') }))),
    route('POST', '/v1/compartments', (r) => engine.createCompartment(r.ctx, body(r))),
    route('PUT', '/v1/compartments/:id/members', async (r) => { await engine.setCompartmentMember(r.ctx, { ...body(r), compartmentId: r.params.id as string }); return { ok: true }; }),
    // ── revocation, sessions, keys ──
    route('POST', '/v1/tokens/revoke', async (r) => { await engine.revokeToken(r.ctx, body(r)); return { ok: true }; }),
    route('GET', '/v1/sessions', (r) => engine.listSessions(r.ctx, opt({ actorId: q(r, 'actorId'), includeEnded: q(r, 'includeEnded') === 'true' ? true : undefined }))),
    route('POST', '/v1/sessions/:id/revoke', async (r) => { await engine.revokeSession(r.ctx, { sessionId: r.params.id as string, reason: (r.body as Body)?.reason }); return { ok: true }; }),
    route('POST', '/v1/actors/:id/revoke', async (r) => { await engine.revokeActor(r.ctx, { ...body(r), actorId: r.params.id as string }); return { ok: true }; }),
    route('POST', '/v1/actors/:id/reinstate', async (r) => { await engine.reinstateActor(r.ctx, { ...body(r), actorId: r.params.id as string }); return { ok: true }; }),
    route('POST', '/v1/keys/rotate', (r) => engine.rotateSigningKey(r.ctx)),
    route('POST', '/v1/keys/:kid/revoke', async (r) => { await engine.revokeSigningKey(r.ctx, r.params.kid as string); return { ok: true }; }),
    // ── federation ──
    route('GET', '/v1/actor-mappings', (r) => engine.listActorMappings(r.ctx, opt({ actorId: q(r, 'actorId'), provider: q(r, 'provider') }))),
    route('POST', '/v1/actor-mappings', (r) => engine.mapExternalActor(r.ctx, body(r))),
    route('POST', '/v1/actor-mappings/resolve', (r) => engine.resolveExternalActor(r.ctx, body(r))),
    route('DELETE', '/v1/actor-mappings/:id', async (r) => { await engine.removeActorMapping(r.ctx, r.params.id as string); return { ok: true }; }),
    route('GET', '/v1/oidc/providers', (r) => engine.listOidcProviders(r.ctx)),
    route('PUT', '/v1/oidc/providers/:id', (r) => engine.configureOidcProvider(r.ctx, { ...body(r), id: r.params.id as string })),
    route('GET', '/v1/intake/connections', (r) => engine.listIntakeConnections(r.ctx)),
    route('POST', '/v1/intake/connections', (r) => engine.registerIntakeConnection(r.ctx, body(r))),
    route('POST', '/v1/intake/connections/:id/verify', (r) => engine.verifyIntakeConnection(r.ctx, r.params.id as string)),
    route('POST', '/v1/intake/connections/:id/tokens', (r) => engine.issueIntakeServiceToken(r.ctx, { ...body(r), connectionId: r.params.id as string })),
  ];
}
