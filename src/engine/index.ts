// E01 Identity, Authorization and Policy — service layer entry point.
import { randomUUID } from 'node:crypto';
import { DomainError, invariant } from '../contracts.ts';
import type { Context, Json } from '../contracts.ts';
import { SERVICE_KIT_VERSION, appendAudit, emitEvent, idempotent, listAudit, parseUref, readEvents, runMigrations } from '../service-kit.ts';
import type { AuditRecord, AuthorizationPort, EngineEvent, EngineManifestV1, Inspection, SearchHit, ServiceContext, Sql, StandardEngine, TokenClaims, TokenVerifier, UpstreamChange } from '../service-kit.ts';
import { DEFAULT_PURPOSES, DEFAULT_ROLES, ENGINES, ORG_WIDE, SCHEMA, migrations } from './schema.ts';
import { hashPassword, randomToken, sameHash, sha256, verifyPassword } from './crypto.ts';
import { EXACT_CAP, ID, covers, denied, futureTime, isSensitive, iso, isoOrNull, jsonObject, need, text, validCaps, validId } from './core.ts';
import type { AccessDecision, ActorKind, EngineDeps, IdentityClaims, IssuedToken, R, SessionInfo } from './core.ts';
import { createKernel } from './kernel.ts';
import { createFederation } from './federation.ts';

export { SCHEMA, migrations, DEFAULT_ROLES, DEFAULT_PURPOSES, ORG_WIDE } from './schema.ts';
export type { AccessDecision, DecisionStep, EngineConfig, EngineDeps, EnginePorts, IdentityClaims, IssuedToken, SessionInfo } from './core.ts';
export { routes } from './http.ts';

const S = SCHEMA;
export const manifest: EngineManifestV1 = {
  id: 'E01', name: 'Identity, Authorization and Policy', version: '1.0.0', kit: SERVICE_KIT_VERSION,
  capabilities: ['identity:read', 'identity:audit', 'identity:admin', 'identity:grant', 'identity:issue_token', 'identity:export', 'identity:events'],
  emits: ['organization.created', 'organization.updated', 'project.created', 'project.updated', 'actor.created', 'actor.updated', 'membership.changed', 'role.changed', 'purpose.changed', 'compartment.changed', 'policy.changed', 'grant.issued', 'grant.revoked', 'grant.used', 'token.revoked', 'session.revoked', 'actor.revoked', 'actor.reinstated', 'key.rotated', 'disclosure.denied', 'mapping.changed', 'federation.changed'],
  consumes: [],
};
export function migrate(sql: Sql): Promise<string[]> { return runMigrations(sql, SCHEMA, migrations); }

export type OrganizationInput = Readonly<{ id?: string; name: string; branding?: Json; defaultLocale?: string; languages?: readonly string[]; jurisdiction?: Json; policyConfig?: Json; project?: Readonly<{ id?: string; name: string; kind?: string; identityProfile?: Json }> }>;
export type Organization = Readonly<{ id: string; name: string; branding: Json; defaultLocale: string; languages: readonly string[]; jurisdiction: Json; policyConfig: Json; policyVersion: string; status: string; createdAt: string }>;
export type Project = Readonly<{ id: string; tenantId: string; name: string; kind: string; identityProfile: Json; status: string; createdAt: string }>;
export type ActorInfo = Readonly<{ id: string; kind: ActorKind; displayName: string; description: string; status: string; homeTenantId: string; homeProjectId: string | null; login: string | null; profile: Json; createdAt: string }>;
export type Member = Readonly<{ actor: ActorInfo; projectId: string; roles: readonly string[]; status: string; expiresAt: string | null; revision: number; updatedAt: string }>;
export type RoleInfo = Readonly<{ name: string; description: string; capabilities: readonly string[]; actorKinds: readonly string[]; version: number; seeded: boolean; updatedAt: string }>;
export type PurposeInfo = Readonly<{ name: string; description: string; capabilities: readonly string[]; updatedAt: string }>;
export type GrantInfo = Readonly<{ id: string; ref: string; tenantId: string; projectId: string; actorId: string; capability: string; purpose: string; resource: string | null; bounds: Json; reason: string; notBefore: string; expiresAt: string; uses: number; amountUsed: number; revokedAt: string | null; revokedBy: string | null; revokeReason: string | null; createdAt: string; createdBy: string; state: 'active' | 'pending' | 'expired' | 'revoked' | 'exhausted' }>;
export type SessionRecord = Readonly<{ id: string; actorId: string; method: string; boundTenantId: string | null; createdAt: string; lastUsedAt: string; expiresAt: string; revokedAt: string | null }>;

const toOrg = (r: R): Organization => ({ id: r.id, name: r.name, branding: r.branding, defaultLocale: r.default_locale, languages: r.languages, jurisdiction: r.jurisdiction, policyConfig: r.policy_config, policyVersion: String(r.pv ?? r.policy_version), status: r.status, createdAt: iso(r.created_at) });
const toProject = (r: R): Project => ({ id: r.id, tenantId: r.tenant_id, name: r.name, kind: r.kind, identityProfile: r.identity_profile, status: r.status, createdAt: iso(r.created_at) });
const toActor = (r: R): ActorInfo => ({ id: r.id, kind: r.kind, displayName: r.display_name, description: r.description, status: r.status, homeTenantId: r.home_tenant_id, homeProjectId: r.home_project_id ?? null, login: r.login ?? null, profile: r.profile, createdAt: iso(r.created_at) });
const toRole = (r: R): RoleInfo => ({ name: r.name, description: r.description, capabilities: r.capabilities, actorKinds: r.actor_kinds, version: r.version, seeded: r.seeded, updatedAt: iso(r.updated_at) });
const toSession = (r: R): SessionRecord => ({ id: r.id, actorId: r.actor_id, method: r.method, boundTenantId: r.bound_tenant_id ?? null, createdAt: iso(r.created_at), lastUsedAt: iso(r.last_used_at), expiresAt: iso(r.expires_at), revokedAt: isoOrNull(r.revoked_at) });
const like = (q: string): string => `%${q.replace(/[\\%_]/g, '\\$&')}%`;
const LOGIN = /^[a-z0-9][a-z0-9._@+-]{2,253}$/;
const ACTOR_COLS = `a.*, (select login from ${S}.credentials c where c.actor_id = a.id) as login`;

export function createEngine(deps: EngineDeps) {
  const k = createKernel(deps);
  const { sql, cfg, clock, ref, record, bump } = k;
  const fed = createFederation(k, deps.ports ?? {}, { needNow, requireOwner, memberActor, issuerGate, createSession: (actorId: string, method: string, boundTenantId: string | null) => createSession(sql, actorId, method, boundTenantId), createNonHuman });
  const ttl = { access: cfg.accessTokenTtlSeconds ?? 600, service: cfg.serviceTokenTtlSeconds ?? 900, agentMax: cfg.agentTokenMaxTtlSeconds ?? 900, session: cfg.sessionTtlSeconds ?? 43200, idle: cfg.sessionIdleSeconds ?? 7200 };
  const lock = { max: cfg.lockout?.maxFailures ?? 5, base: cfg.lockout?.baseLockSeconds ?? 30, cap: cfg.lockout?.maxLockSeconds ?? 900, window: cfg.lockout?.windowSeconds ?? 900 };
  const minPassword = cfg.passwordMinLength ?? 12;
  let dummyHash: Promise<string> | null = null;

  const toGrant = (r: R): GrantInfo => {
    const problem = k.grantUsable(r, clock());
    return { id: r.id, ref: ref('grant', r.id), tenantId: r.tenant_id, projectId: r.project_id, actorId: r.actor_id, capability: r.capability, purpose: r.purpose, resource: r.resource ?? null, bounds: r.bounds, reason: r.reason, notBefore: iso(r.not_before), expiresAt: iso(r.expires_at), uses: r.uses, amountUsed: Number(r.amount_used), revokedAt: isoOrNull(r.revoked_at), revokedBy: r.revoked_by ?? null, revokeReason: r.revoke_reason ?? null, createdAt: iso(r.created_at), createdBy: r.created_by,
      state: problem === null ? 'active' : problem === 'revoked' ? 'revoked' : problem === 'expired' ? 'expired' : problem === 'not yet valid' ? 'pending' : 'exhausted' };
  };
  const password = (value: unknown): string => {
    invariant(typeof value === 'string' && value.length >= minPassword && value.length <= 256, 'invalid_input', `Password must be ${minPassword}–256 characters`);
    return value;
  };
  const loginName = (value: unknown): string => {
    invariant(typeof value === 'string' && LOGIN.test(value.trim().toLowerCase()), 'invalid_input', 'Login must be 3–254 characters of a-z, 0-9 and . _ @ + -');
    return value.trim().toLowerCase();
  };
  /** Token capability plus a current-state decision: used before every administrative side effect. */
  async function needNow(ctx: ServiceContext, capability: string, q: Sql = sql): Promise<void> {
    need(ctx, capability);
    const d = await k.decide(q, { tenantId: ctx.tenantId, projectId: ctx.projectId, actorId: ctx.actor.id, actorKind: ctx.actor.kind, purpose: ctx.purpose, capability, token: { caps: ctx.capabilities, cmp: ctx.compartments, pv: ctx.policyVersion, jti: ctx.tokenId } });
    if (!d.allowed) throw new DomainError('forbidden', `Not currently authorized for ${capability} (${d.reason})`);
  }
  const isAdmin = (ctx: ServiceContext): boolean => covers(ctx.capabilities, 'identity:admin');
  /** A project other than the token's own is visible only to organization administrators. */
  function projectScope(ctx: ServiceContext, projectId: string | undefined): string {
    if (projectId === undefined || projectId === ctx.projectId) return ctx.projectId;
    if (!isAdmin(ctx)) throw new DomainError('not_found', 'Not found');
    return projectId === ORG_WIDE ? ORG_WIDE : validId(projectId, 'projectId');
  }
  const cmd = <T extends Json>(ctx: ServiceContext, key: string | undefined, input: unknown, fn: (tx: Sql) => Promise<T>): Promise<T> => sql.tx((tx) => idempotent(tx, S, ctx, key, input, () => fn(tx)));
  async function currentRoles(q: Sql, ctx: ServiceContext): Promise<readonly string[]> { return (await k.loadState(q, ctx.tenantId, ctx.projectId, ctx.actor.id, clock())).roles; }
  const privilegedRole = (capabilities: readonly string[]): boolean => capabilities.includes('identity:admin') || capabilities.includes('identity:grant');
  async function requireOwner(q: Sql, ctx: ServiceContext, what: string): Promise<void> {
    if (!(await currentRoles(q, ctx)).includes('owner')) throw new DomainError('forbidden', `Only an organization owner may ${what}`);
  }
  async function ensureOwnerRemains(tx: Sql, tenantId: string): Promise<void> {
    const rows = await tx.query(`select 1 from ${S}.memberships m join ${S}.actors a on a.id = m.actor_id where m.tenant_id=$1 and m.project_id='${ORG_WIDE}' and m.status='active' and (m.expires_at is null) and 'owner' = any(m.roles) and a.status='active' and a.kind='human' limit 1`, [tenantId]);
    invariant(rows.length > 0, 'conflict', 'An organization must keep at least one active owner');
  }
  async function memberActor(q: Sql, tenantId: string, actorId: string): Promise<R | undefined> {
    return (await q.query<R>(`select ${ACTOR_COLS} from ${S}.actors a where a.id=$2 and (a.home_tenant_id=$1 or exists(select 1 from ${S}.memberships m where m.tenant_id=$1 and m.actor_id=a.id and m.status <> 'removed'))`, [tenantId, actorId]))[0];
  }

  // ───────────────────────── organizations & projects ─────────────────────────
  async function createOrganizationTx(tx: Sql, by: Context, input: OrganizationInput, ownerActorId: string, orgId: string): Promise<{ organization: Organization; project: Project }> {
    const name = text(input.name, 'Organization name');
    const projectId = input.project?.id === undefined ? 'main' : validId(input.project.id, 'project.id');
    const ctx: Context = { ...by, tenantId: orgId, projectId };
    const languages = input.languages === undefined ? [] : input.languages.map((l) => text(l, 'language', 35));
    const inserted = await tx.query<R>(`insert into ${S}.organizations (id, name, branding, default_locale, languages, jurisdiction, policy_config, created_at, updated_at, created_by) values ($1,$2,$3::jsonb,$4,$5,$6::jsonb,$7::jsonb,$8,$8,$9) on conflict do nothing returning *, policy_version::text as pv`,
      [orgId, name, JSON.stringify(jsonObject(input.branding, 'branding')), text(input.defaultLocale ?? 'en', 'defaultLocale', 35), languages, JSON.stringify(jsonObject(input.jurisdiction, 'jurisdiction')), JSON.stringify(jsonObject(input.policyConfig, 'policyConfig')), by.now, by.actor.id]);
    invariant(inserted[0] !== undefined, 'conflict', 'Organization id is already in use');
    for (const role of DEFAULT_ROLES) {
      await tx.query(`insert into ${S}.roles (tenant_id, name, description, capabilities, actor_kinds, seeded, updated_at, updated_by) values ($1,$2,$3,$4,$5,true,$6,$7)`, [orgId, role.name, role.description, [...new Set(role.capabilities)].sort(), [...role.kinds], by.now, by.actor.id]);
      await tx.query(`insert into ${S}.role_versions (tenant_id, name, version, capabilities, actor_kinds, deleted, policy_version, at, actor_id) values ($1,$2,1,$3,$4,false,1,$5,$6)`, [orgId, role.name, [...new Set(role.capabilities)].sort(), [...role.kinds], by.now, by.actor.id]);
    }
    for (const p of DEFAULT_PURPOSES) await tx.query(`insert into ${S}.purposes (tenant_id, name, description, capabilities, updated_at, updated_by) values ($1,$2,$3,$4,$5,$6)`, [orgId, p.name, p.description, [...new Set(p.capabilities)].sort(), by.now, by.actor.id]);
    const project = await tx.query<R>(`insert into ${S}.projects (tenant_id, id, name, kind, identity_profile, created_at, updated_at, created_by) values ($1,$2,$3,$4,$5::jsonb,$6,$6,$7) returning *`,
      [orgId, projectId, text(input.project?.name ?? 'Main', 'Project name'), text(input.project?.kind ?? 'organizational', 'Project kind', 60), JSON.stringify(jsonObject(input.project?.identityProfile, 'identityProfile')), by.now, by.actor.id]);
    await tx.query(`insert into ${S}.memberships (tenant_id, project_id, actor_id, roles, created_at, updated_at, updated_by) values ($1,'${ORG_WIDE}',$2,'{owner}',$3,$3,$4)`, [orgId, ownerActorId, by.now, by.actor.id]);
    await record(tx, ctx, 'organization.created', ref('organization', orgId), { name, owner: ownerActorId }, 'organization.created');
    await record(tx, ctx, 'project.created', ref('project', projectId), { kind: (project[0] as R).kind as string }, 'project.created');
    await record(tx, ctx, 'membership.changed', ref('actor', ownerActorId), { projectId: ORG_WIDE, roles: ['owner'], status: 'active' }, 'membership.changed');
    return { organization: toOrg(inserted[0]), project: toProject(project[0] as R) };
  }
  async function createHumanTx(tx: Sql, by: Context, homeTenantId: string, input: { login: unknown; password: unknown; displayName: unknown }, actorId: string = randomUUID()): Promise<string> {
    const login = loginName(input.login);
    const hash = await hashPassword(password(input.password), cfg.scryptN);
    await tx.query(`insert into ${S}.actors (id, kind, display_name, home_tenant_id, created_at, updated_at, created_by) values ($1,'human',$2,$3,$4,$4,$5)`, [actorId, text(input.displayName, 'Display name'), homeTenantId, by.now, by.actor.id]);
    const cred = await tx.query(`insert into ${S}.credentials (actor_id, login, password_hash, changed_at) values ($1,$2,$3,$4) on conflict (login) do nothing returning actor_id`, [actorId, login, hash, by.now]);
    invariant(cred.length > 0, 'conflict', 'Login is already in use');
    return actorId;
  }

  /** One-time creation of the first organization and its owner. Refuses once any deployment bootstrap has happened. */
  async function bootstrapFirstAdministrator(input: { login: string; password: string; displayName: string; organization: OrganizationInput; bootstrapToken?: string }, options: { requireToken?: boolean } = {}): Promise<{ organization: Organization; project: Project; actorId: string }> {
    if (options.requireToken === true && cfg.bootstrapToken === undefined) throw new DomainError('unavailable', 'IDENTITY_BOOTSTRAP_TOKEN is not configured; bootstrap over HTTP is disabled');
    if (cfg.bootstrapToken !== undefined) invariant(typeof input.bootstrapToken === 'string' && sameHash(sha256(input.bootstrapToken), sha256(cfg.bootstrapToken)), 'forbidden', 'Bootstrap is not permitted');
    return sql.tx(async (tx) => {
      await tx.query('select pg_advisory_xact_lock(hashtext($1))', ['e01-bootstrap']);
      const done = await tx.query(`select 1 from ${S}.deployment where key='platform' union all select 1 from ${S}.organizations limit 1`);
      invariant(done.length === 0, 'conflict', 'An administrator already exists; bootstrap is disabled');
      const orgId = input.organization?.id === undefined ? randomUUID() : validId(input.organization.id, 'organization.id');
      const actorId = randomUUID();
      const by = k.systemContext(orgId, 'main', actorId, 'human', 'bootstrap');
      await createHumanTx(tx, by, orgId, input, actorId);
      const out = await createOrganizationTx(tx, by, input.organization, actorId, orgId);
      await tx.query(`insert into ${S}.deployment (key, value) values ('platform', $1::jsonb)`, [JSON.stringify({ tenantId: orgId, projectId: out.project.id, at: by.now })]);
      return { ...out, actorId };
    });
  }
  async function isBootstrapped(): Promise<boolean> { return (await sql.query(`select 1 from ${S}.deployment where key='platform'`)).length > 0; }

  async function createOrganization(ctx: ServiceContext, input: OrganizationInput & { owner?: { login: string; password: string; displayName: string } }): Promise<{ organization: Organization; project: Project; ownerActorId: string }> {
    await needNow(ctx, 'identity:admin');
    invariant(cfg.allowOrganizationCreation !== false, 'forbidden', 'Organization creation is disabled in this deployment');
    invariant(ctx.actor.kind === 'human', 'forbidden', 'Only a human administrator may create an organization');
    const orgId = input.id === undefined ? randomUUID() : validId(input.id, 'id');
    return sql.tx(async (tx) => {
      const owner = input.owner === undefined ? ctx.actor.id : await createHumanTx(tx, ctx, orgId, input.owner);
      const out = await createOrganizationTx(tx, ctx, input, owner, orgId);
      await appendAudit(tx, S, ctx, 'organization.created', ref('organization', orgId), { owner });
      return { ...out, ownerActorId: owner };
    });
  }
  async function getOrganization(ctx: ServiceContext): Promise<Organization> {
    need(ctx, 'identity:read');
    const row = (await sql.query<R>(`select *, policy_version::text as pv from ${S}.organizations where id=$1`, [ctx.tenantId]))[0];
    invariant(row !== undefined, 'not_found', 'Not found');
    return toOrg(row);
  }
  async function updateOrganization(ctx: ServiceContext, patch: { name?: string; branding?: Json; defaultLocale?: string; languages?: readonly string[]; jurisdiction?: Json; policyConfig?: Json }): Promise<Organization> {
    await needNow(ctx, 'identity:admin');
    return sql.tx(async (tx) => {
      const cur = (await tx.query<R>(`select * from ${S}.organizations where id=$1 for update`, [ctx.tenantId]))[0];
      invariant(cur !== undefined, 'not_found', 'Not found');
      if (patch.policyConfig !== undefined) await requireOwner(tx, ctx, 'change policy configuration');
      await tx.query(`update ${S}.organizations set name=$2, branding=$3::jsonb, default_locale=$4, languages=$5, jurisdiction=$6::jsonb, policy_config=$7::jsonb, updated_at=$8 where id=$1`,
        [ctx.tenantId, patch.name === undefined ? cur.name : text(patch.name, 'name'), JSON.stringify(patch.branding === undefined ? cur.branding : jsonObject(patch.branding, 'branding')), patch.defaultLocale === undefined ? cur.default_locale : text(patch.defaultLocale, 'defaultLocale', 35),
          patch.languages === undefined ? cur.languages : patch.languages.map((l) => text(l, 'language', 35)), JSON.stringify(patch.jurisdiction === undefined ? cur.jurisdiction : jsonObject(patch.jurisdiction, 'jurisdiction')), JSON.stringify(patch.policyConfig === undefined ? cur.policy_config : jsonObject(patch.policyConfig, 'policyConfig')), ctx.now]);
      await record(tx, ctx, 'organization.updated', ref('organization', ctx.tenantId), { fields: Object.keys(patch) }, 'organization.updated');
      if (patch.policyConfig !== undefined) await bump(tx, ctx, 'policy configuration changed');
      return toOrg((await tx.query<R>(`select *, policy_version::text as pv from ${S}.organizations where id=$1`, [ctx.tenantId]))[0] as R);
    });
  }
  async function createProject(ctx: ServiceContext, input: { id?: string; name: string; kind?: string; identityProfile?: Json; idempotencyKey?: string }): Promise<Project> {
    await needNow(ctx, 'identity:admin');
    const { idempotencyKey, ...rest } = input;
    return cmd(ctx, idempotencyKey, rest, async (tx) => {
      const id = input.id === undefined ? randomUUID() : validId(input.id, 'id');
      const rows = await tx.query<R>(`insert into ${S}.projects (tenant_id, id, name, kind, identity_profile, created_at, updated_at, created_by) values ($1,$2,$3,$4,$5::jsonb,$6,$6,$7) on conflict do nothing returning *`,
        [ctx.tenantId, id, text(input.name, 'name'), text(input.kind ?? 'organizational', 'kind', 60), JSON.stringify(jsonObject(input.identityProfile, 'identityProfile')), ctx.now, ctx.actor.id]);
      invariant(rows[0] !== undefined, 'conflict', 'Project id is already in use');
      await record(tx, { ...ctx, projectId: id }, 'project.created', ref('project', id), { kind: rows[0].kind as string }, 'project.created');
      return toProject(rows[0]) as unknown as Json;
    }) as unknown as Promise<Project>;
  }
  async function updateProject(ctx: ServiceContext, projectId: string, patch: { name?: string; kind?: string; identityProfile?: Json; status?: 'active' | 'archived' }): Promise<Project> {
    await needNow(ctx, 'identity:admin');
    invariant(patch.status === undefined || patch.status === 'active' || patch.status === 'archived', 'invalid_input', 'Invalid status');
    return sql.tx(async (tx) => {
      const cur = (await tx.query<R>(`select * from ${S}.projects where tenant_id=$1 and id=$2 for update`, [ctx.tenantId, projectId]))[0];
      invariant(cur !== undefined, 'not_found', 'Not found');
      const rows = await tx.query<R>(`update ${S}.projects set name=$3, kind=$4, identity_profile=$5::jsonb, status=$6, updated_at=$7 where tenant_id=$1 and id=$2 returning *`,
        [ctx.tenantId, projectId, patch.name === undefined ? cur.name : text(patch.name, 'name'), patch.kind === undefined ? cur.kind : text(patch.kind, 'kind', 60), JSON.stringify(patch.identityProfile === undefined ? cur.identity_profile : jsonObject(patch.identityProfile, 'identityProfile')), patch.status ?? cur.status, ctx.now]);
      await record(tx, ctx, 'project.updated', ref('project', projectId), { fields: Object.keys(patch) }, 'project.updated');
      if (patch.status !== undefined && patch.status !== cur.status) await bump(tx, ctx, `project ${projectId} ${patch.status}`);
      return toProject(rows[0] as R);
    });
  }
  /** Administrators see every project; others see only projects they hold a membership in (or all, with an organization-wide membership). */
  async function listProjects(ctx: ServiceContext): Promise<Project[]> {
    need(ctx, 'identity:read');
    const rows = await sql.query<R>(`select p.* from ${S}.projects p where p.tenant_id=$1 and ($3 or exists(select 1 from ${S}.memberships m where m.tenant_id=$1 and m.actor_id=$2 and m.status='active' and m.project_id in (p.id, '${ORG_WIDE}'))) order by p.created_at, p.id`, [ctx.tenantId, ctx.actor.id, isAdmin(ctx)]);
    return rows.map(toProject);
  }
  /** Organizations and projects the calling actor can enter, across organizations (own memberships only). */
  async function listMyOrganizations(ctx: ServiceContext): Promise<Awaited<ReturnType<typeof directoryFor>>> {
    invariant(typeof ctx?.actor?.id === 'string', 'unauthenticated', 'Authenticated context required');
    return directoryFor(ctx.actor.id, null);
  }
  async function directoryFor(actorId: string, boundTenantId: string | null): Promise<{ organization: { id: string; name: string; branding: Json; defaultLocale: string }; purposes: string[]; projects: { id: string; name: string; kind: string; roles: string[] }[] }[]> {
    const at = clock().toISOString();
    const rows = await sql.query<R>(`select o.id as org_id, o.name as org_name, o.branding, o.default_locale, p.id, p.name, p.kind,
        (select coalesce(array_agg(distinct r), '{}') from ${S}.memberships m, unnest(m.roles) r where m.tenant_id=o.id and m.actor_id=$1 and m.status='active' and (m.expires_at is null or m.expires_at > $2) and m.project_id in (p.id, '${ORG_WIDE}')) as roles,
        (select coalesce(array_agg(name order by name), '{}') from ${S}.purposes pu where pu.tenant_id=o.id) as purposes
      from ${S}.organizations o join ${S}.projects p on p.tenant_id=o.id
      where o.status='active' and p.status='active' and ($3::text is null or o.id=$3)
        and exists(select 1 from ${S}.memberships m where m.tenant_id=o.id and m.actor_id=$1 and m.status='active' and (m.expires_at is null or m.expires_at > $2) and m.project_id in (p.id, '${ORG_WIDE}'))
      order by o.created_at, o.id, p.created_at, p.id`, [actorId, at, boundTenantId]);
    const out = new Map<string, { organization: { id: string; name: string; branding: Json; defaultLocale: string }; purposes: string[]; projects: { id: string; name: string; kind: string; roles: string[] }[] }>();
    for (const r of rows) {
      if (!out.has(r.org_id)) out.set(r.org_id, { organization: { id: r.org_id, name: r.org_name, branding: r.branding, defaultLocale: r.default_locale }, purposes: r.purposes, projects: [] });
      out.get(r.org_id)?.projects.push({ id: r.id, name: r.name, kind: r.kind, roles: r.roles });
    }
    return [...out.values()];
  }

  // ───────────────────────── actors & memberships ─────────────────────────
  async function applyMembership(tx: Sql, ctx: ServiceContext, actor: R, projectId: string, roles: readonly string[], status: 'active' | 'suspended' | 'removed', expiresAt: Date | null): Promise<R> {
    if (projectId !== ORG_WIDE) invariant((await tx.query(`select 1 from ${S}.projects where tenant_id=$1 and id=$2`, [ctx.tenantId, projectId])).length > 0, 'not_found', 'Not found');
    const defs = new Map((await tx.query<R>(`select * from ${S}.roles where tenant_id=$1 and not deleted`, [ctx.tenantId])).map((r) => [r.name as string, r]));
    invariant(Array.isArray(roles) && roles.length <= 32 && (status === 'removed' || roles.length > 0), 'invalid_input', 'At least one role is required');
    for (const name of roles) {
      const def = defs.get(name);
      invariant(def !== undefined, 'invalid_input', `Unknown role ${String(name)}`);
      invariant((def.actor_kinds as string[]).includes(actor.kind), 'invalid_input', `Role ${name} cannot be held by a ${actor.kind} identity`);
    }
    const cur = (await tx.query<R>(`select * from ${S}.memberships where tenant_id=$1 and project_id=$2 and actor_id=$3 for update`, [ctx.tenantId, projectId, actor.id]))[0];
    const touched = [...new Set([...(cur?.roles as string[] | undefined ?? []), ...roles])];
    const touchesPrivileged = touched.some((name) => name === 'owner' || privilegedRole((defs.get(name)?.capabilities as string[] | undefined) ?? ['identity:admin']));
    if (touchesPrivileged) await requireOwner(tx, ctx, 'assign or remove administrative roles');
    const rows = await tx.query<R>(`insert into ${S}.memberships (tenant_id, project_id, actor_id, roles, status, expires_at, created_at, updated_at, updated_by) values ($1,$2,$3,$4,$5,$6,$7,$7,$8)
      on conflict (tenant_id, project_id, actor_id) do update set roles=excluded.roles, status=excluded.status, expires_at=excluded.expires_at, updated_at=excluded.updated_at, updated_by=excluded.updated_by, revision=${S}.memberships.revision+1 returning *`,
      [ctx.tenantId, projectId, actor.id, status === 'removed' ? (cur?.roles ?? []) : [...new Set(roles)].sort(), status, expiresAt === null ? null : expiresAt.toISOString(), ctx.now, ctx.actor.id]);
    if (touched.includes('owner')) await ensureOwnerRemains(tx, ctx.tenantId);
    const pv = await bump(tx, ctx, `membership of ${actor.id} in ${projectId} changed`, [actor.id]);
    await record(tx, ctx, 'membership.changed', ref('actor', actor.id), { projectId, roles: [...roles], status, expiresAt: expiresAt === null ? null : expiresAt.toISOString(), policyVersion: pv }, 'membership.changed');
    return rows[0] as R;
  }
  const toMember = (m: R, actor: R): Member => ({ actor: toActor(actor), projectId: m.project_id, roles: m.roles, status: m.status, expiresAt: isoOrNull(m.expires_at), revision: m.revision, updatedAt: iso(m.updated_at) });

  async function createUser(ctx: ServiceContext, input: { login: string; password: string; displayName: string; projectId?: string; roles?: readonly string[]; idempotencyKey?: string }): Promise<ActorInfo> {
    await needNow(ctx, 'identity:admin');
    const { idempotencyKey, password: _secret, ...rest } = input;
    return cmd(ctx, idempotencyKey, rest, async (tx) => {
      const id = await createHumanTx(tx, ctx, ctx.tenantId, input);
      const actor = (await tx.query<R>(`select ${ACTOR_COLS} from ${S}.actors a where a.id=$1`, [id]))[0] as R;
      await record(tx, ctx, 'actor.created', ref('actor', id), { kind: 'human' }, 'actor.created');
      if (input.roles !== undefined) await applyMembership(tx, ctx, actor, input.projectId ?? ctx.projectId, input.roles, 'active', null);
      return toActor(actor) as unknown as Json;
    }) as unknown as Promise<ActorInfo>;
  }
  /** Adds or changes a membership. `projectId: '*'` is organization-wide. The actor is named by id or (humans) by login. */
  async function setMembership(ctx: ServiceContext, input: { actorId?: string; login?: string; projectId?: string; roles: readonly string[]; expiresAt?: string | null; status?: 'active' | 'suspended'; idempotencyKey?: string }): Promise<Member> {
    await needNow(ctx, 'identity:admin');
    const { idempotencyKey, ...rest } = input;
    return cmd(ctx, idempotencyKey, rest, async (tx) => {
      const actor = input.actorId !== undefined
        ? (await tx.query<R>(`select ${ACTOR_COLS} from ${S}.actors a where a.id=$1`, [input.actorId]))[0]
        : (await tx.query<R>(`select ${ACTOR_COLS} from ${S}.actors a join ${S}.credentials c on c.actor_id=a.id where c.login=$1`, [loginName(input.login)]))[0];
      invariant(actor !== undefined && actor.status === 'active', 'not_found', 'Not found');
      // Service and agent identities belong to one organization and are never shared across organizations.
      invariant(actor.kind === 'human' || actor.home_tenant_id === ctx.tenantId, 'not_found', 'Not found');
      const projectId = input.projectId === ORG_WIDE ? ORG_WIDE : validId(input.projectId ?? ctx.projectId, 'projectId');
      const expires = input.expiresAt === undefined || input.expiresAt === null ? null : futureTime(input.expiresAt, 'expiresAt', clock(), 10 * 365 * 86400);
      invariant(input.status === undefined || input.status === 'active' || input.status === 'suspended', 'invalid_input', 'Invalid status');
      return toMember(await applyMembership(tx, ctx, actor, projectId, input.roles, input.status ?? 'active', expires), actor) as unknown as Json;
    }) as unknown as Promise<Member>;
  }
  async function removeMember(ctx: ServiceContext, input: { actorId: string; projectId?: string }): Promise<void> {
    await needNow(ctx, 'identity:admin');
    await sql.tx(async (tx) => {
      const projectId = input.projectId === ORG_WIDE ? ORG_WIDE : validId(input.projectId ?? ctx.projectId, 'projectId');
      const actor = await memberActor(tx, ctx.tenantId, input.actorId);
      const cur = (await tx.query(`select 1 from ${S}.memberships where tenant_id=$1 and project_id=$2 and actor_id=$3 and status <> 'removed'`, [ctx.tenantId, projectId, input.actorId]))[0];
      invariant(actor !== undefined && cur !== undefined, 'not_found', 'Not found');
      await applyMembership(tx, ctx, actor, projectId, [], 'removed', null);
    });
  }
  async function listMembers(ctx: ServiceContext, options: { projectId?: string; kind?: ActorKind; includeOrganizationWide?: boolean } = {}): Promise<Member[]> {
    need(ctx, 'identity:read');
    const projectId = projectScope(ctx, options.projectId);
    const rows = await sql.query<R>(`select m.*, to_jsonb(x) as actor from ${S}.memberships m join (select ${ACTOR_COLS} from ${S}.actors a) x on x.id=m.actor_id
      where m.tenant_id=$1 and m.status <> 'removed' and (m.project_id=$2 or ($3 and m.project_id='${ORG_WIDE}')) and ($4::text is null or x.kind=$4) order by x.display_name, x.id, m.project_id`,
      [ctx.tenantId, projectId, options.includeOrganizationWide !== false, options.kind ?? null]);
    return rows.map((m) => toMember(m, m.actor as R));
  }
  async function getActor(ctx: ServiceContext, actorId: string): Promise<ActorInfo | null> {
    if (actorId !== ctx?.actor?.id) need(ctx, 'identity:read'); else invariant(typeof ctx.tenantId === 'string', 'unauthenticated', 'Authenticated context required');
    const row = await memberActor(sql, ctx.tenantId, actorId);
    return row === undefined ? null : toActor(row);
  }
  async function whoami(ctx: ServiceContext): Promise<{ actor: ActorInfo | null; tenantId: string; projectId: string; purpose: string; roles: readonly string[]; capabilities: readonly string[]; compartments: readonly string[]; policyVersion: string; tokenId: string | null }> {
    invariant(ctx !== null && typeof ctx === 'object' && typeof ctx.actor?.id === 'string' && typeof ctx.tenantId === 'string', 'unauthenticated', 'Authenticated context required');
    const row = await memberActor(sql, ctx.tenantId, ctx.actor.id);
    return { actor: row === undefined ? null : toActor(row), tenantId: ctx.tenantId, projectId: ctx.projectId, purpose: ctx.purpose, roles: ctx.actor.roles, capabilities: ctx.capabilities, compartments: ctx.compartments, policyVersion: ctx.policyVersion ?? '', tokenId: ctx.tokenId ?? null };
  }
  async function createNonHuman(ctx: ServiceContext, kind: 'agent' | 'service', input: { name: string; description?: string; projectId?: string; roles?: readonly string[]; profile?: Json }, tx: Sql, secretHash: string | null): Promise<R> {
    const id = randomUUID();
    const projectId = input.projectId === ORG_WIDE ? ORG_WIDE : validId(input.projectId ?? ctx.projectId, 'projectId');
    invariant(kind === 'service' || projectId !== ORG_WIDE, 'invalid_input', 'Agents belong to one project');
    await tx.query(`insert into ${S}.actors (id, kind, display_name, home_tenant_id, home_project_id, description, profile, secret_hash, created_at, updated_at, created_by) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$9,$10)`,
      [id, kind, text(input.name, 'name'), ctx.tenantId, projectId === ORG_WIDE ? null : projectId, input.description === undefined ? '' : text(input.description, 'description', 2000), JSON.stringify(jsonObject(input.profile, 'profile')), secretHash, ctx.now, ctx.actor.id]);
    const actor = (await tx.query<R>(`select ${ACTOR_COLS} from ${S}.actors a where a.id=$1`, [id]))[0] as R;
    await record(tx, ctx, 'actor.created', ref('actor', id), { kind }, 'actor.created');
    if (input.roles !== undefined && input.roles.length > 0) await applyMembership(tx, ctx, actor, projectId, input.roles, 'active', null);
    return actor;
  }
  /** Durable agent identity. Agents hold no credential: they act only through bounded tokens issued by `issueAgentToken`. */
  async function createAgent(ctx: ServiceContext, input: { name: string; description?: string; projectId?: string; roles: readonly string[]; profile?: Json; idempotencyKey?: string }): Promise<ActorInfo> {
    await needNow(ctx, 'identity:admin');
    const { idempotencyKey, ...rest } = input;
    return cmd(ctx, idempotencyKey, rest, async (tx) => toActor(await createNonHuman(ctx, 'agent', input, tx, null)) as unknown as Json) as unknown as Promise<ActorInfo>;
  }
  /** Service identity with a client secret returned exactly once (stored only as a SHA-256 digest of 256 random bits). */
  async function createServiceIdentity(ctx: ServiceContext, input: { name: string; description?: string; projectId?: string; roles: readonly string[]; profile?: Json }): Promise<{ service: ActorInfo; secret: string }> {
    await needNow(ctx, 'identity:admin');
    const secret = randomToken(32);
    const actor = await sql.tx((tx) => createNonHuman(ctx, 'service', input, tx, sha256(secret)));
    return { service: toActor(actor), secret };
  }
  async function rotateServiceSecret(ctx: ServiceContext, serviceId: string): Promise<{ secret: string }> {
    await needNow(ctx, 'identity:admin');
    const secret = randomToken(32);
    await sql.tx(async (tx) => {
      const rows = await tx.query(`update ${S}.actors set secret_hash=$3, updated_at=$4 where id=$1 and home_tenant_id=$2 and kind='service' returning id`, [serviceId, ctx.tenantId, sha256(secret), ctx.now]);
      invariant(rows.length > 0, 'not_found', 'Not found');
      await record(tx, ctx, 'actor.secret_rotated', ref('actor', serviceId), {}, 'actor.updated');
    });
    return { secret };
  }
  async function listActors(ctx: ServiceContext, kind: ActorKind): Promise<ActorInfo[]> {
    need(ctx, 'identity:read');
    const rows = await sql.query<R>(`select ${ACTOR_COLS} from ${S}.actors a where a.kind=$2 and (a.home_tenant_id=$1 or exists(select 1 from ${S}.memberships m where m.tenant_id=$1 and m.actor_id=a.id and m.status <> 'removed'))
      and ($3 or a.kind='human' or a.home_project_id is null or a.home_project_id=$4) order by a.display_name, a.id`, [ctx.tenantId, kind, isAdmin(ctx), ctx.projectId]);
    return rows.map(toActor);
  }
  /** An administrator may reset a password only for an account of this organization that has no access elsewhere. */
  async function resetPassword(ctx: ServiceContext, input: { actorId: string; newPassword: string }): Promise<void> {
    await needNow(ctx, 'identity:admin');
    const hash = await hashPassword(password(input.newPassword), cfg.scryptN);
    await sql.tx(async (tx) => {
      const actor = (await tx.query<R>(`select * from ${S}.actors where id=$1 and home_tenant_id=$2 and kind='human' for update`, [input.actorId, ctx.tenantId]))[0];
      invariant(actor !== undefined, 'not_found', 'Not found');
      const elsewhere = await tx.query(`select 1 from ${S}.memberships where actor_id=$1 and tenant_id <> $2 and status <> 'removed' limit 1`, [input.actorId, ctx.tenantId]);
      invariant(elsewhere.length === 0, 'forbidden', 'This account also belongs to another organization; only its holder can change the password');
      if ((await tx.query(`select 1 from ${S}.memberships where tenant_id=$1 and actor_id=$2 and status='active' and roles && array['owner','admin']`, [ctx.tenantId, input.actorId])).length > 0) await requireOwner(tx, ctx, "reset an administrator's password");
      await tx.query(`update ${S}.credentials set password_hash=$2, changed_at=$3 where actor_id=$1`, [input.actorId, hash, ctx.now]);
      await tx.query(`update ${S}.sessions set revoked_at=$2, revoked_by=$3, revoke_reason='password reset' where actor_id=$1 and revoked_at is null`, [input.actorId, ctx.now, ctx.actor.id]);
      await record(tx, ctx, 'actor.password_reset', ref('actor', input.actorId), {}, 'session.revoked');
    });
    k.clearRevocationCache();
  }
  async function changePassword(ctx: ServiceContext, input: { currentPassword: string; newPassword: string }): Promise<void> {
    invariant(typeof ctx?.actor?.id === 'string' && ctx.actor.kind === 'human', 'unauthenticated', 'Authenticated human required');
    const cred = (await sql.query<R>(`select c.* from ${S}.credentials c where c.actor_id=$1`, [ctx.actor.id]))[0];
    await throttle(`actor:${ctx.actor.id}`, async () => cred !== undefined && typeof input?.currentPassword === 'string' && await verifyPassword(input.currentPassword, cred.password_hash));
    const hash = await hashPassword(password(input.newPassword), cfg.scryptN);
    await sql.tx(async (tx) => {
      await tx.query(`update ${S}.credentials set password_hash=$2, changed_at=$3 where actor_id=$1`, [ctx.actor.id, hash, ctx.now]);
      // Every session ends, including the one behind the presenting token: the holder signs in again.
      await tx.query(`update ${S}.sessions set revoked_at=$2, revoked_by=$1, revoke_reason='password changed' where actor_id=$1 and revoked_at is null`, [ctx.actor.id, ctx.now]);
      await appendAudit(tx, S, ctx, 'actor.password_changed', ref('actor', ctx.actor.id), {});
    });
    k.clearRevocationCache();
  }

  // ───────────────────────── roles, purposes, compartments ─────────────────────────
  async function listRoles(ctx: ServiceContext): Promise<RoleInfo[]> {
    need(ctx, 'identity:read');
    return (await sql.query<R>(`select * from ${S}.roles where tenant_id=$1 and not deleted order by name`, [ctx.tenantId])).map(toRole);
  }
  async function roleHistory(ctx: ServiceContext, name: string): Promise<{ version: number; capabilities: string[]; actorKinds: string[]; deleted: boolean; policyVersion: string; at: string; actorId: string }[]> {
    need(ctx, 'identity:read');
    return (await sql.query<R>(`select *, policy_version::text as pv from ${S}.role_versions where tenant_id=$1 and name=$2 order by version`, [ctx.tenantId, name])).map((r) => ({ version: r.version, capabilities: r.capabilities, actorKinds: r.actor_kinds, deleted: r.deleted, policyVersion: r.pv, at: iso(r.at), actorId: r.actor_id }));
  }
  /** Creates or replaces a role definition (a new version). Holders' tokens issued before the change stop verifying. */
  async function defineRole(ctx: ServiceContext, input: { name: string; description?: string; capabilities: readonly string[]; actorKinds?: readonly ActorKind[]; deleted?: boolean; idempotencyKey?: string }): Promise<RoleInfo> {
    await needNow(ctx, 'identity:admin');
    const { idempotencyKey, ...rest } = input;
    return cmd(ctx, idempotencyKey, rest, async (tx) => {
      invariant(typeof input.name === 'string' && /^[a-z][a-z0-9_]{1,62}$/.test(input.name), 'invalid_input', 'Role name must be lower_snake_case');
      const caps = validCaps(input.capabilities);
      const kinds = [...new Set(input.actorKinds ?? ['human'])].sort();
      invariant(kinds.length > 0 && kinds.every((x) => ['human', 'agent', 'service'].includes(x)), 'invalid_input', 'Invalid actor kinds');
      const cur = (await tx.query<R>(`select * from ${S}.roles where tenant_id=$1 and name=$2 for update`, [ctx.tenantId, input.name]))[0];
      const deleted = input.deleted === true;
      if (input.name === 'owner') invariant(!deleted && caps.includes('identity:admin') && caps.includes('identity:grant') && kinds.length === 1 && kinds[0] === 'human', 'invalid_input', 'The owner role must remain a human role with identity:admin and identity:grant');
      if (privilegedRole(caps) || (cur !== undefined && privilegedRole(cur.capabilities)) || input.name === 'owner') await requireOwner(tx, ctx, 'define administrative roles');
      if (kinds.includes('agent')) for (const c of caps) invariant(!isSensitive(c), 'invalid_input', `Agent roles cannot name the sensitive capability ${c}; use a time-bounded grant`);
      const version = (cur?.version as number | undefined ?? 0) + 1;
      const rows = await tx.query<R>(`insert into ${S}.roles (tenant_id, name, description, capabilities, actor_kinds, version, deleted, updated_at, updated_by) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        on conflict (tenant_id, name) do update set description=excluded.description, capabilities=excluded.capabilities, actor_kinds=excluded.actor_kinds, version=excluded.version, deleted=excluded.deleted, updated_at=excluded.updated_at, updated_by=excluded.updated_by returning *`,
        [ctx.tenantId, input.name, input.description === undefined ? (cur?.description ?? '') : text(input.description, 'description', 1000), caps, kinds, version, deleted, ctx.now, ctx.actor.id]);
      const holders = (await tx.query<R>(`select distinct actor_id from ${S}.memberships where tenant_id=$1 and $2 = any(roles) and status <> 'removed'`, [ctx.tenantId, input.name])).map((r) => r.actor_id as string);
      const pv = await bump(tx, ctx, `role ${input.name} ${deleted ? 'deleted' : 'defined'} (version ${version})`, holders);
      await tx.query(`insert into ${S}.role_versions (tenant_id, name, version, capabilities, actor_kinds, deleted, policy_version, at, actor_id) values ($1,$2,$3,$4,$5,$6,$7::bigint,$8,$9)`, [ctx.tenantId, input.name, version, caps, kinds, deleted, pv, ctx.now, ctx.actor.id]);
      await record(tx, ctx, 'role.changed', ref('role', input.name), { version, deleted, policyVersion: pv, holders: holders.length }, 'role.changed');
      return toRole(rows[0] as R) as unknown as Json;
    }) as unknown as Promise<RoleInfo>;
  }
  async function listPurposes(ctx: ServiceContext): Promise<PurposeInfo[]> {
    need(ctx, 'identity:read');
    return (await sql.query<R>(`select * from ${S}.purposes where tenant_id=$1 order by name`, [ctx.tenantId])).map((r) => ({ name: r.name, description: r.description, capabilities: r.capabilities, updatedAt: iso(r.updated_at) }));
  }
  /** Purposes bound which capabilities a token may carry; changing one is an owner decision and revokes outstanding tokens of every member. */
  async function definePurpose(ctx: ServiceContext, input: { name: string; description?: string; capabilities: readonly string[] }): Promise<PurposeInfo> {
    await needNow(ctx, 'identity:admin');
    return sql.tx(async (tx) => {
      await requireOwner(tx, ctx, 'define purposes');
      invariant(typeof input.name === 'string' && /^[a-z][a-z0-9_]{1,62}$/.test(input.name), 'invalid_input', 'Purpose name must be lower_snake_case');
      const caps = validCaps(input.capabilities);
      const rows = await tx.query<R>(`insert into ${S}.purposes (tenant_id, name, description, capabilities, updated_at, updated_by) values ($1,$2,$3,$4,$5,$6)
        on conflict (tenant_id, name) do update set description=excluded.description, capabilities=excluded.capabilities, updated_at=excluded.updated_at, updated_by=excluded.updated_by returning *`, [ctx.tenantId, input.name, input.description === undefined ? '' : text(input.description, 'description', 1000), caps, ctx.now, ctx.actor.id]);
      const members = (await tx.query<R>(`select distinct actor_id from ${S}.memberships where tenant_id=$1 and status <> 'removed'`, [ctx.tenantId])).map((r) => r.actor_id as string);
      const pv = await bump(tx, ctx, `purpose ${input.name} defined`, members);
      await record(tx, ctx, 'purpose.changed', ref('purpose', input.name), { policyVersion: pv }, 'purpose.changed');
      const r = rows[0] as R;
      return { name: r.name, description: r.description, capabilities: r.capabilities, updatedAt: iso(r.updated_at) };
    });
  }
  async function createCompartment(ctx: ServiceContext, input: { id: string; description?: string; projectId?: string }): Promise<{ id: string; projectId: string; description: string }> {
    await needNow(ctx, 'identity:admin');
    const projectId = validId(input.projectId ?? ctx.projectId, 'projectId');
    return sql.tx(async (tx) => {
      invariant((await tx.query(`select 1 from ${S}.projects where tenant_id=$1 and id=$2`, [ctx.tenantId, projectId])).length > 0, 'not_found', 'Not found');
      const rows = await tx.query(`insert into ${S}.compartments (tenant_id, project_id, id, description, created_at, created_by) values ($1,$2,$3,$4,$5,$6) on conflict do nothing returning id`, [ctx.tenantId, projectId, validId(input.id, 'id'), input.description === undefined ? '' : text(input.description, 'description', 1000), ctx.now, ctx.actor.id]);
      invariant(rows.length > 0, 'conflict', 'Compartment already exists');
      const pv = await bump(tx, ctx, `compartment ${input.id} created`);
      await record(tx, { ...ctx, projectId }, 'compartment.changed', ref('compartment', input.id), { projectId, change: 'created', policyVersion: pv }, 'compartment.changed');
      return { id: input.id, projectId, description: input.description ?? '' };
    });
  }
  async function setCompartmentMember(ctx: ServiceContext, input: { compartmentId: string; actorId: string; member: boolean; projectId?: string; expiresAt?: string | null }): Promise<void> {
    await needNow(ctx, 'identity:admin');
    const projectId = validId(input.projectId ?? ctx.projectId, 'projectId');
    await sql.tx(async (tx) => {
      invariant((await tx.query(`select 1 from ${S}.compartments where tenant_id=$1 and project_id=$2 and id=$3`, [ctx.tenantId, projectId, input.compartmentId])).length > 0, 'not_found', 'Not found');
      const active = await tx.query(`select 1 from ${S}.memberships where tenant_id=$1 and actor_id=$2 and status='active' and project_id in ($3, '${ORG_WIDE}')`, [ctx.tenantId, input.actorId, projectId]);
      invariant(active.length > 0, 'not_found', 'Not found');
      if (input.member) {
        const expires = input.expiresAt === undefined || input.expiresAt === null ? null : futureTime(input.expiresAt, 'expiresAt', clock(), 10 * 365 * 86400).toISOString();
        await tx.query(`insert into ${S}.compartment_members (tenant_id, project_id, compartment_id, actor_id, expires_at, added_at, added_by) values ($1,$2,$3,$4,$5,$6,$7) on conflict (tenant_id, project_id, compartment_id, actor_id) do update set expires_at=excluded.expires_at, added_at=excluded.added_at, added_by=excluded.added_by`, [ctx.tenantId, projectId, input.compartmentId, input.actorId, expires, ctx.now, ctx.actor.id]);
      } else await tx.query(`delete from ${S}.compartment_members where tenant_id=$1 and project_id=$2 and compartment_id=$3 and actor_id=$4`, [ctx.tenantId, projectId, input.compartmentId, input.actorId]);
      const pv = await bump(tx, ctx, `compartment ${input.compartmentId} membership of ${input.actorId} changed`, [input.actorId]);
      await record(tx, { ...ctx, projectId }, 'compartment.changed', ref('compartment', input.compartmentId), { projectId, actorId: input.actorId, member: input.member, policyVersion: pv }, 'compartment.changed');
    });
  }
  /** Administrators see every compartment of the project; others see only the compartments they belong to. */
  async function listCompartments(ctx: ServiceContext, options: { projectId?: string } = {}): Promise<{ id: string; projectId: string; description: string; members: string[] }[]> {
    need(ctx, 'identity:read');
    const projectId = projectScope(ctx, options.projectId);
    const rows = await sql.query<R>(`select c.*, (select coalesce(array_agg(actor_id order by actor_id), '{}') from ${S}.compartment_members cm where cm.tenant_id=c.tenant_id and cm.project_id=c.project_id and cm.compartment_id=c.id and (cm.expires_at is null or cm.expires_at > $5)) as members
      from ${S}.compartments c where c.tenant_id=$1 and c.project_id=$2 and ($3 or exists(select 1 from ${S}.compartment_members cm where cm.tenant_id=c.tenant_id and cm.project_id=c.project_id and cm.compartment_id=c.id and cm.actor_id=$4 and (cm.expires_at is null or cm.expires_at > $5))) order by c.id`, [ctx.tenantId, projectId, isAdmin(ctx), ctx.actor.id, clock().toISOString()]);
    return rows.map((r) => ({ id: r.id, projectId: r.project_id, description: r.description, members: isAdmin(ctx) ? r.members : [ctx.actor.id] }));
  }

  // ───────────────────────── authentication, sessions, tokens ─────────────────────────
  /** Uniform failure counting keyed by a hash, for existing and unknown logins alike (no account enumeration). */
  async function throttle(subject: string, check: () => Promise<boolean>): Promise<void> {
    const key = sha256(`attempt:${subject}`);
    const at = clock();
    const cur = (await sql.query<R>(`select * from ${S}.auth_attempts where key=$1`, [key]))[0];
    if (cur !== undefined && cur.locked_until !== null && new Date(cur.locked_until).getTime() > at.getTime()) throw new DomainError('rate_limited', 'Too many failed attempts; try again later');
    if (await check()) { if (cur !== undefined) await sql.query(`delete from ${S}.auth_attempts where key=$1`, [key]); return; }
    const row = (await sql.query<R>(`insert into ${S}.auth_attempts (key, failures, last_failed_at) values ($1, 1, $2)
      on conflict (key) do update set failures = case when ${S}.auth_attempts.last_failed_at < $3 then 1 else ${S}.auth_attempts.failures + 1 end, last_failed_at = $2 returning failures`, [key, at.toISOString(), new Date(at.getTime() - lock.window * 1000).toISOString()]))[0] as R;
    if (row.failures >= lock.max) await sql.query(`update ${S}.auth_attempts set locked_until=$2 where key=$1`, [key, new Date(at.getTime() + Math.min(lock.cap, lock.base * 2 ** Math.min(row.failures - lock.max, 10)) * 1000).toISOString()]);
    throw denied();
  }
  async function createSession(q: Sql, actorId: string, method: string, boundTenantId: string | null): Promise<SessionInfo> {
    const id = randomUUID(), secret = randomToken(32), at = clock();
    const expires = new Date(at.getTime() + ttl.session * 1000).toISOString();
    await q.query(`insert into ${S}.sessions (id, actor_id, refresh_hash, bound_tenant_id, method, created_at, last_used_at, expires_at) values ($1,$2,$3,$4,$5,$6,$6,$7)`, [id, actorId, sha256(secret), boundTenantId, method, at.toISOString(), expires]);
    return { sessionId: id, refreshToken: `${id}.${secret}`, actorId, expiresAt: expires, boundTenantId };
  }
  /** Local password sign-in. Returns a session whose refresh token is exchanged for short-lived access tokens. */
  async function login(input: { login: string; password: string }): Promise<SessionInfo> {
    invariant(input !== null && typeof input === 'object' && typeof input.login === 'string' && typeof input.password === 'string' && input.login.length <= 254 && input.password.length <= 256, 'invalid_input', 'Login and password are required');
    const name = input.login.trim().toLowerCase();
    let actorId = '';
    await throttle(`login:${name}`, async () => {
      const cred = (await sql.query<R>(`select c.actor_id, c.password_hash, a.status from ${S}.credentials c join ${S}.actors a on a.id=c.actor_id where c.login=$1`, [name]))[0];
      if (cred === undefined) { dummyHash ??= hashPassword(randomToken(), cfg.scryptN); await verifyPassword(input.password, await dummyHash); return false; }
      const ok = await verifyPassword(input.password, cred.password_hash);
      actorId = cred.actor_id;
      return ok && cred.status === 'active';
    });
    return createSession(sql, actorId, 'password', null);
  }
  async function loadSession(refreshToken: unknown): Promise<R> {
    if (typeof refreshToken !== 'string' || refreshToken.length > 200) throw denied();
    const dot = refreshToken.indexOf('.');
    const id = refreshToken.slice(0, Math.max(dot, 0)), secret = refreshToken.slice(dot + 1);
    const at = clock();
    const row = (await sql.query<R>(`select s.*, a.status as actor_status from ${S}.sessions s join ${S}.actors a on a.id=s.actor_id where s.id=$1`, [id]))[0];
    if (row === undefined || !sameHash(sha256(secret), row.refresh_hash) || row.revoked_at !== null || row.actor_status !== 'active'
      || new Date(row.expires_at).getTime() <= at.getTime() || new Date(row.last_used_at).getTime() + ttl.idle * 1000 <= at.getTime()) throw denied('Session is invalid or has ended');
    await sql.query(`update ${S}.sessions set last_used_at=$2 where id=$1`, [id, at.toISOString()]);
    return row;
  }
  /** Organizations, projects and purposes the session's actor may request tokens for. */
  async function sessionDirectory(refreshToken: string): Promise<{ actorId: string; sessionId: string; expiresAt: string; organizations: Awaited<ReturnType<typeof directoryFor>> }> {
    const s = await loadSession(refreshToken);
    return { actorId: s.actor_id, sessionId: s.id, expiresAt: iso(s.expires_at), organizations: await directoryFor(s.actor_id, s.bound_tenant_id ?? null) };
  }
  /** Exchanges a session for an access token scoped to one organization + project + purpose. Capabilities are resolved from current state. */
  async function issueAccessToken(input: { refreshToken: string; tenantId: string; projectId: string; purpose: string; capabilities?: readonly string[]; ttlSeconds?: number }): Promise<IssuedToken> {
    const s = await loadSession(input?.refreshToken);
    if (s.bound_tenant_id !== null && s.bound_tenant_id !== input.tenantId) throw new DomainError('forbidden', 'No active access to this organization and project');
    return k.mint({ actorId: s.actor_id, tenantId: input.tenantId, projectId: input.projectId, purpose: input.purpose, ttlSeconds: input.ttlSeconds ?? ttl.access, kind: 'human', sessionId: s.id, ...(input.capabilities === undefined ? {} : { requested: validCaps(input.capabilities) }) });
  }
  async function logout(refreshToken: string): Promise<void> {
    const s = await loadSession(refreshToken);
    await sql.query(`update ${S}.sessions set revoked_at=$2, revoked_by=$3, revoke_reason='logout' where id=$1 and revoked_at is null`, [s.id, clock().toISOString(), s.actor_id]);
    k.clearRevocationCache();
  }
  /** Client-credentials sign-in for a service identity: returns an access token directly (no session). */
  async function authenticateService(input: { serviceId: string; secret: string; projectId: string; purpose: string; capabilities?: readonly string[]; ttlSeconds?: number }): Promise<IssuedToken> {
    invariant(input !== null && typeof input === 'object' && typeof input.serviceId === 'string' && typeof input.secret === 'string' && input.serviceId.length <= 128 && input.secret.length <= 200, 'invalid_input', 'Service id and secret are required');
    let tenantId = '';
    await throttle(`service:${input.serviceId}`, async () => {
      const a = (await sql.query<R>(`select * from ${S}.actors where id=$1 and kind='service'`, [input.serviceId]))[0];
      tenantId = a?.home_tenant_id ?? '';
      return sameHash(sha256(input.secret), a?.secret_hash ?? sha256(randomToken())) && a !== undefined && a.status === 'active' && a.secret_hash !== null;
    });
    return k.mint({ actorId: input.serviceId, tenantId, projectId: input.projectId, purpose: input.purpose, ttlSeconds: input.ttlSeconds ?? ttl.service, kind: 'service', ...(input.capabilities === undefined ? {} : { requested: validCaps(input.capabilities) }) });
  }
  async function issuerGate(ctx: ServiceContext, projectId: string | undefined): Promise<string> {
    if (covers(ctx.capabilities, 'identity:issue_token')) await needNow(ctx, 'identity:issue_token'); else await needNow(ctx, 'identity:admin');
    if (projectId !== undefined && projectId !== ctx.projectId) invariant(isAdmin(ctx), 'forbidden', 'Tokens for another project require identity:admin');
    return projectId ?? ctx.projectId;
  }
  /** Issues a token for a service identity of the caller's organization. Requires `identity:issue_token` (exact) or `identity:admin`. */
  async function issueServiceToken(ctx: ServiceContext, input: { serviceId: string; projectId?: string; purpose: string; capabilities?: readonly string[]; ttlSeconds?: number }): Promise<IssuedToken> {
    const projectId = await issuerGate(ctx, input.projectId);
    const out = await k.mint({ actorId: input.serviceId, tenantId: ctx.tenantId, projectId, purpose: input.purpose, ttlSeconds: input.ttlSeconds ?? ttl.service, kind: 'service', ...(input.capabilities === undefined ? {} : { requested: validCaps(input.capabilities) }) });
    await sql.tx((tx) => appendAudit(tx, S, ctx, 'token.issued', ref('actor', input.serviceId), { tokenId: out.tokenId, purpose: input.purpose, projectId, expiresAt: out.expiresAt, capabilities: [...out.capabilities] }));
    return out;
  }
  /**
   * Issues a bounded token for an agent identity: an explicit capability list (every entry must be available to the
   * agent for the purpose, by its agent roles or by an active grant), bounded lifetime, optional ceiling of a human
   * on whose behalf the agent runs. Agents never receive admin, grant, issue_token, events or secret-bearing actions.
   */
  async function issueAgentToken(ctx: ServiceContext, input: { agentId: string; projectId?: string; purpose: string; capabilities: readonly string[]; ttlSeconds?: number; onBehalfOf?: string; compartments?: readonly string[] }): Promise<IssuedToken> {
    const projectId = await issuerGate(ctx, input.projectId);
    const requested = validCaps(input.capabilities);
    invariant(requested.length > 0, 'invalid_input', 'An explicit capability list is required for an agent token');
    const seconds = input.ttlSeconds ?? Math.min(ttl.agentMax, 600);
    invariant(Number.isInteger(seconds) && seconds >= 30 && seconds <= ttl.agentMax, 'invalid_input', `Agent token lifetime must be 30–${ttl.agentMax} seconds`);
    let ceiling: readonly string[] | undefined;
    if (input.onBehalfOf !== undefined) {
      const st = await k.loadState(sql, ctx.tenantId, projectId, input.onBehalfOf, clock());
      invariant(st.actor !== undefined && st.actor.status === 'active' && st.actor.kind === 'human' && st.memberships.length > 0, 'forbidden', 'The delegating human has no active access to this project');
      ceiling = st.roleCaps;
    }
    const out = await k.mint({ actorId: input.agentId, tenantId: ctx.tenantId, projectId, purpose: input.purpose, ttlSeconds: seconds, kind: 'agent', requested, strict: true, ceiling, compartments: input.compartments });
    await sql.tx((tx) => appendAudit(tx, S, ctx, 'token.issued', ref('actor', input.agentId), { tokenId: out.tokenId, purpose: input.purpose, projectId, expiresAt: out.expiresAt, capabilities: [...out.capabilities], onBehalfOf: input.onBehalfOf ?? null }));
    return out;
  }

  // ───────────────────────── grants ─────────────────────────
  /**
   * Time-bounded, revocable grant of one exact capability to one actor for one purpose. `bounds` is stored and
   * returned verbatim; the engine itself enforces `maxUses`, `maxAmount`, `recipients` and `resources` when present.
   */
  async function createGrant(ctx: ServiceContext, input: { actorId: string; capability: string; purpose: string; projectId?: string; resource?: string; bounds?: Json; reason: string; notBefore?: string; expiresAt: string; idempotencyKey?: string }): Promise<GrantInfo> {
    await needNow(ctx, 'identity:grant');
    const { idempotencyKey, ...rest } = input;
    return cmd(ctx, idempotencyKey, rest, async (tx) => {
      invariant(typeof input.capability === 'string' && EXACT_CAP.test(input.capability), 'invalid_input', 'An exact capability `engine:action` is required');
      invariant(!['identity:admin', 'identity:grant', 'identity:issue_token'].includes(input.capability), 'forbidden', 'Identity administration cannot be delegated through a grant');
      invariant(input.actorId !== ctx.actor.id, 'forbidden', 'A grant cannot be issued to oneself');
      const projectId = input.projectId === ORG_WIDE ? ORG_WIDE : validId(input.projectId ?? ctx.projectId, 'projectId');
      if (projectId !== ctx.projectId) invariant(isAdmin(ctx), 'forbidden', 'Grants for another project require identity:admin');
      const st = await k.loadState(tx, ctx.tenantId, projectId === ORG_WIDE ? ctx.projectId : projectId, input.actorId, clock());
      invariant(st.org !== undefined && st.actor !== undefined && st.actor.status === 'active' && st.memberships.length > 0 && (projectId === ORG_WIDE || st.project !== undefined), 'not_found', 'Not found');
      const agent = st.actor.kind === 'agent';
      invariant(!(agent && k.agentBlocked(st.org, input.capability)), 'forbidden', `Agents may not hold ${input.capability} in this organization`);
      invariant(await k.purposeCaps(tx, ctx.tenantId, input.purpose) !== null, 'invalid_input', 'Unknown purpose');
      const now = clock();
      const expires = futureTime(input.expiresAt, 'expiresAt', now, agent ? (cfg.maxAgentGrantSeconds ?? 86400) : (cfg.maxGrantSeconds ?? 30 * 86400));
      const notBefore = input.notBefore === undefined ? now : new Date(input.notBefore);
      invariant(Number.isFinite(notBefore.getTime()) && notBefore.getTime() < expires.getTime(), 'invalid_input', 'notBefore must precede expiresAt');
      const bounds = jsonObject(input.bounds, 'bounds');
      for (const key of ['maxUses', 'maxAmount']) invariant(bounds[key] === undefined || (typeof bounds[key] === 'number' && (bounds[key] as number) > 0), 'invalid_input', `bounds.${key} must be a positive number`);
      for (const key of ['recipients', 'resources']) invariant(bounds[key] === undefined || (Array.isArray(bounds[key]) && (bounds[key] as Json[]).every((x) => typeof x === 'string')), 'invalid_input', `bounds.${key} must be a list of strings`);
      const id = randomUUID();
      const rows = await tx.query<R>(`insert into ${S}.grants (id, tenant_id, project_id, actor_id, capability, purpose, resource, bounds, reason, not_before, expires_at, created_at, created_by) values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13) returning *`,
        [id, ctx.tenantId, projectId, input.actorId, input.capability, input.purpose, input.resource === undefined ? null : text(input.resource, 'resource', 500), JSON.stringify(bounds), text(input.reason, 'reason', 2000), notBefore.toISOString(), expires.toISOString(), ctx.now, ctx.actor.id]);
      const pv = await bump(tx, ctx, `grant ${id} issued`);
      await record(tx, ctx, 'grant.issued', ref('grant', id), { actorId: input.actorId, capability: input.capability, purpose: input.purpose, projectId, resource: input.resource ?? null, expiresAt: expires.toISOString(), policyVersion: pv }, 'grant.issued');
      return toGrant(rows[0] as R) as unknown as Json;
    }) as unknown as Promise<GrantInfo>;
  }
  /** Revokes a grant. The grantee's outstanding tokens stop verifying immediately (within the revocation cache window). */
  async function revokeGrant(ctx: ServiceContext, input: { grantId: string; reason: string }): Promise<GrantInfo> {
    await needNow(ctx, 'identity:grant');
    return sql.tx(async (tx) => {
      const cur = (await tx.query<R>(`select * from ${S}.grants where id=$1 and tenant_id=$2 for update`, [input.grantId, ctx.tenantId]))[0];
      invariant(cur !== undefined && (cur.project_id === ctx.projectId || isAdmin(ctx)), 'not_found', 'Not found');
      if (cur.revoked_at !== null) return toGrant(cur);
      const rows = await tx.query<R>(`update ${S}.grants set revoked_at=$2, revoked_by=$3, revoke_reason=$4 where id=$1 returning *`, [input.grantId, ctx.now, ctx.actor.id, text(input.reason, 'reason', 2000)]);
      const pv = await bump(tx, ctx, `grant ${input.grantId} revoked`, [cur.actor_id]);
      await record(tx, ctx, 'grant.revoked', ref('grant', input.grantId), { actorId: cur.actor_id, capability: cur.capability, policyVersion: pv }, 'grant.revoked');
      return toGrant(rows[0] as R);
    });
  }
  /** Own grants are always visible; other actors' grants need `identity:read`. Limited to the token's project unless administrator. */
  async function listGrants(ctx: ServiceContext, options: { actorId?: string; capability?: string; projectId?: string; includeInactive?: boolean } = {}): Promise<GrantInfo[]> {
    if (options.actorId !== ctx?.actor?.id) need(ctx, 'identity:read'); else invariant(typeof ctx.tenantId === 'string', 'unauthenticated', 'Authenticated context required');
    const rows = await sql.query<R>(`select * from ${S}.grants where tenant_id=$1 and ($2::text is null or actor_id=$2) and ($3::text is null or capability=$3) and ($4::text is null or project_id in ($4, '${ORG_WIDE}')) order by created_at desc limit 1000`,
      [ctx.tenantId, options.actorId ?? null, options.capability ?? null, isAdmin(ctx) ? (options.projectId ?? null) : ctx.projectId]);
    return rows.map(toGrant).filter((g) => options.includeInactive === true || g.state === 'active' || g.state === 'pending');
  }
  /** Answers whether an actor holds a currently valid grant for the capability (and resource / recipient / amount). */
  async function checkGrant(ctx: ServiceContext, input: { actorId?: string; capability: string; purpose?: string; resource?: string; recipient?: string; amount?: number; grantId?: string }): Promise<{ valid: boolean; reason: string; grant: GrantInfo | null; remainingUses: number | null; remainingAmount: number | null; policyVersion: string }> {
    const actorId = input.actorId ?? ctx?.actor?.id;
    if (actorId !== ctx?.actor?.id) need(ctx, 'identity:read'); else invariant(typeof ctx.tenantId === 'string' && typeof ctx.projectId === 'string', 'unauthenticated', 'Authenticated context required');
    const at = clock();
    const pv = String((await sql.query<R>(`select policy_version::text as pv from ${S}.organizations where id=$1`, [ctx.tenantId]))[0]?.pv ?? '0');
    const rows = await sql.query<R>(`select * from ${S}.grants where tenant_id=$1 and actor_id=$2 and capability=$3 and purpose=$4 and project_id in ($5, '${ORG_WIDE}') and ($6::text is null or id=$6) order by created_at`, [ctx.tenantId, actorId, input.capability, input.purpose ?? ctx.purpose, ctx.projectId, input.grantId ?? null]);
    let reason = 'no grant';
    for (const g of rows) {
      const b = g.bounds as R;
      const problem = k.grantUsable(g, at) ?? (k.grantCoversResource(g, input.resource) ? null : 'resource is outside the grant')
        ?? (Array.isArray(b.recipients) && (input.recipient === undefined || !(b.recipients as string[]).includes(input.recipient)) ? 'recipient is outside the grant' : null)
        ?? (typeof b.maxAmount === 'number' && input.amount !== undefined && Number(g.amount_used) + input.amount > b.maxAmount ? 'amount exceeds the remaining ceiling' : null);
      if (problem !== null) { reason = problem; continue; }
      return { valid: true, reason: 'valid', grant: toGrant(g), remainingUses: typeof b.maxUses === 'number' ? b.maxUses - g.uses : null, remainingAmount: typeof b.maxAmount === 'number' ? b.maxAmount - Number(g.amount_used) : null, policyVersion: pv };
    }
    return { valid: false, reason, grant: null, remainingUses: null, remainingAmount: null, policyVersion: pv };
  }
  /** Atomically consumes part of a grant's bounds (uses / amount) by the grantee. Idempotent by `useKey`. */
  async function useGrant(ctx: ServiceContext, input: { grantId: string; useKey: string; units?: number; amount?: number; recipient?: string; resource?: string }): Promise<{ grant: GrantInfo; remainingUses: number | null; remainingAmount: number | null }> {
    invariant(typeof ctx?.actor?.id === 'string' && typeof ctx.tenantId === 'string', 'unauthenticated', 'Authenticated context required');
    const units = input.units ?? 1, amount = input.amount ?? 0;
    invariant(Number.isInteger(units) && units >= 1 && units <= 100000 && Number.isFinite(amount) && amount >= 0, 'invalid_input', 'Invalid units or amount');
    text(input.useKey, 'useKey', 200);
    return sql.tx(async (tx) => {
      const g = (await tx.query<R>(`select * from ${S}.grants where id=$1 and tenant_id=$2 and actor_id=$3 and project_id in ($4, '${ORG_WIDE}') for update`, [input.grantId, ctx.tenantId, ctx.actor.id, ctx.projectId]))[0];
      invariant(g !== undefined, 'not_found', 'Not found');
      const b = g.bounds as R;
      const out = (row: R) => ({ grant: toGrant(row), remainingUses: typeof b.maxUses === 'number' ? b.maxUses - row.uses : null, remainingAmount: typeof b.maxAmount === 'number' ? b.maxAmount - Number(row.amount_used) : null });
      if ((await tx.query(`select 1 from ${S}.grant_uses where grant_id=$1 and use_key=$2`, [g.id, input.useKey])).length > 0) return out(g);
      const problem = (g.purpose !== ctx.purpose ? 'purpose does not match the grant' : null) ?? k.grantUsable(g, clock()) ?? (k.grantCoversResource(g, input.resource) ? null : 'resource is outside the grant')
        ?? (Array.isArray(b.recipients) && (input.recipient === undefined || !(b.recipients as string[]).includes(input.recipient)) ? 'recipient is outside the grant' : null)
        ?? (typeof b.maxUses === 'number' && g.uses + units > b.maxUses ? 'use limit would be exceeded' : null)
        ?? (typeof b.maxAmount === 'number' && Number(g.amount_used) + amount > b.maxAmount ? 'amount ceiling would be exceeded' : null);
      if (problem !== null) throw new DomainError('grant_invalid', `Grant cannot be used: ${problem}`);
      await tx.query(`insert into ${S}.grant_uses (grant_id, use_key, units, amount, at) values ($1,$2,$3,$4,$5)`, [g.id, input.useKey, units, amount, ctx.now]);
      const row = (await tx.query<R>(`update ${S}.grants set uses = uses + $2, amount_used = amount_used + $3 where id=$1 returning *`, [g.id, units, amount]))[0] as R;
      await record(tx, ctx, 'grant.used', ref('grant', g.id), { units, amount, uses: row.uses as number }, 'grant.used');
      return out(row);
    });
  }

  // ───────────────────────── revocation ─────────────────────────
  /** Revokes one access token by id. Anyone may revoke the token they present; others need `identity:admin`. */
  async function revokeToken(ctx: ServiceContext, input: { tokenId: string; reason?: string; actorId?: string; expiresAt?: string }): Promise<void> {
    if (input.tokenId !== ctx?.tokenId) await needNow(ctx, 'identity:admin'); else invariant(typeof ctx.tenantId === 'string', 'unauthenticated', 'Authenticated context required');
    text(input.tokenId, 'tokenId', 200);
    const expires = input.expiresAt !== undefined && Number.isFinite(Date.parse(input.expiresAt)) ? new Date(input.expiresAt) : new Date(clock().getTime() + (k.maxTokenTtl + 120) * 1000);
    await sql.tx(async (tx) => {
      const rows = await tx.query(`insert into ${S}.token_revocations (tenant_id, jti, actor_id, token_expires_at, revoked_at, revoked_by, reason) values ($1,$2,$3,$4,$5,$6,$7) on conflict do nothing returning jti`, [ctx.tenantId, input.tokenId, input.actorId ?? null, expires.toISOString(), ctx.now, ctx.actor.id, input.reason ?? '']);
      if (rows.length > 0) await record(tx, ctx, 'token.revoked', ref('actor', ID.test(input.actorId ?? '') ? input.actorId as string : ctx.actor.id), { tokenId: input.tokenId, reason: input.reason ?? '' }, 'token.revoked');
    });
    k.clearRevocationCache();
  }
  /** Sessions are visible to their own actor, and to administrators of the actor's home organization or of the organization a federated session is bound to. */
  async function listSessions(ctx: ServiceContext, options: { actorId?: string; includeEnded?: boolean } = {}): Promise<SessionRecord[]> {
    const actorId = options.actorId ?? ctx?.actor?.id;
    if (actorId !== ctx?.actor?.id) need(ctx, 'identity:admin'); else invariant(typeof ctx.tenantId === 'string', 'unauthenticated', 'Authenticated context required');
    const rows = await sql.query<R>(`select s.* from ${S}.sessions s join ${S}.actors a on a.id=s.actor_id where s.actor_id=$1 and ($2 or a.home_tenant_id=$3 or s.bound_tenant_id=$3) and ($4 or (s.revoked_at is null and s.expires_at > $5)) order by s.created_at desc limit 500`,
      [actorId, actorId === ctx.actor.id, ctx.tenantId, options.includeEnded === true, clock().toISOString()]);
    return rows.map(toSession);
  }
  async function revokeSession(ctx: ServiceContext, input: { sessionId: string; reason?: string }): Promise<void> {
    invariant(typeof ctx?.actor?.id === 'string' && typeof ctx.tenantId === 'string', 'unauthenticated', 'Authenticated context required');
    await sql.tx(async (tx) => {
      const s = (await tx.query<R>(`select s.*, a.home_tenant_id from ${S}.sessions s join ${S}.actors a on a.id=s.actor_id where s.id=$1 for update of s`, [input.sessionId]))[0];
      const own = s !== undefined && s.actor_id === ctx.actor.id;
      invariant(s !== undefined && (own || ((s.home_tenant_id === ctx.tenantId || s.bound_tenant_id === ctx.tenantId) && isAdmin(ctx))), 'not_found', 'Not found');
      if (!own) await needNow(ctx, 'identity:admin', tx);
      if (s.revoked_at !== null) return;
      await tx.query(`update ${S}.sessions set revoked_at=$2, revoked_by=$3, revoke_reason=$4 where id=$1`, [input.sessionId, ctx.now, ctx.actor.id, input.reason ?? '']);
      await record(tx, ctx, 'session.revoked', ref('session', input.sessionId), { actorId: s.actor_id, reason: input.reason ?? '' }, 'session.revoked');
    });
    k.clearRevocationCache();
  }
  /**
   * Immediately invalidates every outstanding token of an actor in this organization. With `disable`, the actor's
   * memberships here are suspended too; an actor whose home is this organization is disabled outright and its sessions end.
   */
  async function revokeActor(ctx: ServiceContext, input: { actorId: string; reason: string; disable?: boolean }): Promise<void> {
    await needNow(ctx, 'identity:admin');
    await sql.tx(async (tx) => {
      const actor = await memberActor(tx, ctx.tenantId, input.actorId);
      invariant(actor !== undefined, 'not_found', 'Not found');
      const st = await tx.query<R>(`select roles from ${S}.memberships where tenant_id=$1 and actor_id=$2 and status='active'`, [ctx.tenantId, input.actorId]);
      const privileged = st.some((m) => (m.roles as string[]).some((r) => r === 'owner' || r === 'admin'));
      if (privileged) await requireOwner(tx, ctx, 'revoke an administrator');
      if (input.disable === true) {
        await tx.query(`update ${S}.memberships set status='suspended', updated_at=$3, updated_by=$4, revision=revision+1 where tenant_id=$1 and actor_id=$2 and status='active'`, [ctx.tenantId, input.actorId, ctx.now, ctx.actor.id]);
        const elsewhere = await tx.query(`select 1 from ${S}.memberships where actor_id=$1 and tenant_id <> $2 and status <> 'removed' limit 1`, [input.actorId, ctx.tenantId]);
        if (actor.home_tenant_id === ctx.tenantId && elsewhere.length === 0) {
          await tx.query(`update ${S}.actors set status='disabled', updated_at=$2 where id=$1`, [input.actorId, ctx.now]);
          await tx.query(`update ${S}.sessions set revoked_at=$2, revoked_by=$3, revoke_reason='actor disabled' where actor_id=$1 and revoked_at is null`, [input.actorId, ctx.now, ctx.actor.id]);
        }
        if (privileged) await ensureOwnerRemains(tx, ctx.tenantId);
      }
      const pv = await bump(tx, ctx, `actor ${input.actorId} revoked`, [input.actorId]);
      await record(tx, ctx, 'actor.revoked', ref('actor', input.actorId), { reason: text(input.reason, 'reason', 2000), disabled: input.disable === true, policyVersion: pv }, 'actor.revoked');
    });
    k.clearRevocationCache();
  }
  /** Re-enables an actor disabled by `revokeActor` and reactivates its suspended memberships in this organization. */
  async function reinstateActor(ctx: ServiceContext, input: { actorId: string; reason: string }): Promise<void> {
    await needNow(ctx, 'identity:admin');
    await sql.tx(async (tx) => {
      const actor = await memberActor(tx, ctx.tenantId, input.actorId);
      invariant(actor !== undefined, 'not_found', 'Not found');
      const suspended = await tx.query<R>(`select roles from ${S}.memberships where tenant_id=$1 and actor_id=$2 and status='suspended'`, [ctx.tenantId, input.actorId]);
      if (suspended.some((m) => (m.roles as string[]).some((r) => r === 'owner' || r === 'admin'))) await requireOwner(tx, ctx, 'reinstate an administrator');
      if (actor.home_tenant_id === ctx.tenantId) await tx.query(`update ${S}.actors set status='active', updated_at=$2 where id=$1`, [input.actorId, ctx.now]);
      await tx.query(`update ${S}.memberships set status='active', updated_at=$3, updated_by=$4, revision=revision+1 where tenant_id=$1 and actor_id=$2 and status='suspended'`, [ctx.tenantId, input.actorId, ctx.now, ctx.actor.id]);
      const pv = await bump(tx, ctx, `actor ${input.actorId} reinstated`, [input.actorId]);
      await record(tx, ctx, 'actor.reinstated', ref('actor', input.actorId), { reason: text(input.reason, 'reason', 2000), policyVersion: pv }, 'actor.reinstated');
    });
    k.clearRevocationCache();
  }

  // ───────────────────────── decisions ─────────────────────────
  /**
   * Current-state authorization for the calling context (kit `AuthorizationPort`). Checks, in order: scope, active
   * membership, token revocation and policy version, the token's own capabilities, agent limits, purpose,
   * compartment, then role or grant. Never throws for a denial; if the decision cannot be made it denies.
   */
  async function authorize(ctx: ServiceContext, request: { capability: string; resource?: string; compartment?: string }): Promise<AccessDecision> {
    const base = { actorId: String(ctx?.actor?.id ?? ''), tenantId: String(ctx?.tenantId ?? ''), projectId: String(ctx?.projectId ?? ''), purpose: String(ctx?.purpose ?? ''), capability: String(request?.capability ?? ''), resource: request?.resource ?? null };
    let decision: AccessDecision;
    try {
      invariant(ctx !== null && typeof ctx === 'object' && Array.isArray(ctx.capabilities) && Array.isArray(ctx.compartments) && ctx.actor !== null && typeof ctx.actor === 'object' && request !== null && typeof request === 'object', 'invalid_context', 'Context required');
      const compartment = request.compartment ?? (typeof request.resource === 'string' && request.resource.startsWith('compartment:') ? request.resource.slice(12) : undefined);
      decision = await k.decide(sql, { tenantId: ctx.tenantId, projectId: ctx.projectId, actorId: ctx.actor.id, actorKind: ctx.actor.kind, purpose: ctx.purpose, capability: request.capability, resource: compartment !== undefined && request.compartment === undefined ? undefined : request.resource, compartment, token: { caps: ctx.capabilities, cmp: ctx.compartments, pv: ctx.policyVersion, jti: ctx.tokenId } });
    } catch {
      return { ...base, allowed: false, reason: 'authorization_unavailable', policyVersion: '0', via: null, trail: [{ rule: 'authorization_unavailable', outcome: 'fail', detail: 'The decision could not be established; access is denied' }] };
    }
    if (!decision.allowed && isSensitive(base.capability) && !['organization_unavailable', 'invalid_context', 'invalid_capability'].includes(decision.reason) && ID.test(base.actorId)) {
      try {
        await sql.tx(async (tx) => {
          const detail = { capability: base.capability, reason: decision.reason, resource: base.resource, purpose: base.purpose };
          await appendAudit(tx, S, ctx, 'access.denied', ref('actor', base.actorId), detail);
          if (base.capability.endsWith(':disclose_identity')) await emitEvent(tx, S, ctx, 'disclosure.denied', ref('actor', base.actorId), detail);
        });
      } catch { /* the denial stands even when it cannot be recorded */ }
    }
    return decision;
  }
  /** The decision trail for any actor of this organization, evaluated on current state (no token involved). */
  async function explain(ctx: ServiceContext, actorId: string, capability: string, resource?: string, options: { purpose?: string; projectId?: string; compartment?: string } = {}): Promise<AccessDecision> {
    if (actorId !== ctx?.actor?.id) need(ctx, 'identity:read'); else invariant(typeof ctx.tenantId === 'string' && typeof ctx.projectId === 'string', 'unauthenticated', 'Authenticated context required');
    return k.decide(sql, { tenantId: ctx.tenantId, projectId: projectScope(ctx, options.projectId), actorId, purpose: options.purpose ?? ctx.purpose, capability, resource, compartment: options.compartment });
  }

  // ───────────────────────── export, counts, standard surface ─────────────────────────
  async function counts(ctx: ServiceContext): Promise<{ projects: number; members: number; agents: number; services: number; roles: number; activeGrants: number; compartments: number }> {
    need(ctx, 'identity:read');
    const admin = isAdmin(ctx);
    const r = (await sql.query<R>(`select
      (select count(*) from ${S}.projects p where p.tenant_id=$1 and ($3 or p.id=$2))::int as projects,
      (select count(distinct m.actor_id) from ${S}.memberships m join ${S}.actors a on a.id=m.actor_id where m.tenant_id=$1 and m.status='active' and a.kind='human' and ($3 or m.project_id in ($2,'${ORG_WIDE}')))::int as members,
      (select count(*) from ${S}.actors a where a.home_tenant_id=$1 and a.kind='agent' and ($3 or a.home_project_id=$2))::int as agents,
      (select count(*) from ${S}.actors a where a.home_tenant_id=$1 and a.kind='service' and ($3 or a.home_project_id is null or a.home_project_id=$2))::int as services,
      (select count(*) from ${S}.roles where tenant_id=$1 and not deleted)::int as roles,
      (select count(*) from ${S}.grants g where g.tenant_id=$1 and g.revoked_at is null and g.expires_at > $4 and ($3 or g.project_id in ($2,'${ORG_WIDE}')))::int as grants,
      (select count(*) from ${S}.compartments c where c.tenant_id=$1 and ($3 or c.project_id=$2))::int as compartments`, [ctx.tenantId, ctx.projectId, admin, clock().toISOString()]))[0] as R;
    return { projects: r.projects, members: r.members, agents: r.agents, services: r.services, roles: r.roles, activeGrants: r.grants, compartments: r.compartments };
  }
  /** Organization directory export (no credentials, secrets or session material). Requires `identity:export` exactly. */
  async function exportDirectory(ctx: ServiceContext): Promise<{ organization: Organization; projects: Project[]; roles: RoleInfo[]; purposes: PurposeInfo[]; members: Member[]; grants: GrantInfo[]; exportedAt: string; policyVersion: string }> {
    await needNow(ctx, 'identity:export');
    const admin: ServiceContext = { ...ctx, capabilities: [...ctx.capabilities, 'identity:read'] };
    const organization = await getOrganization(admin);
    const projects = await listProjects(admin);
    const members: Member[] = [];
    for (const p of isAdmin(ctx) ? [ORG_WIDE, ...projects.map((x) => x.id)] : [ctx.projectId]) members.push(...await listMembers(admin, { projectId: p, includeOrganizationWide: false }));
    const out = { organization, projects, roles: await listRoles(admin), purposes: await listPurposes(admin), members, grants: await listGrants(admin, { includeInactive: true }), exportedAt: clock().toISOString(), policyVersion: organization.policyVersion };
    await sql.tx((tx) => appendAudit(tx, S, ctx, 'directory.exported', ref('organization', ctx.tenantId), { members: members.length, grants: out.grants.length }));
    return out;
  }

  async function inspect(ctx: ServiceContext, value: string): Promise<Inspection | null> {
    need(ctx, 'identity:read');
    let parsed: ReturnType<typeof parseUref>;
    try { parsed = parseUref(value); } catch { return null; }
    if (parsed.engine !== 'E01') return null;
    const { kind, id } = parsed;
    const history = async (subject: string): Promise<Inspection['history']> => (await listAudit(sql, S, ctx, { subject, allProjects: true, limit: 200 })).map((a) => ({ at: a.at, actorId: a.actorId, action: a.action, detail: a.detail }));
    const make = async (k2: string, title: string, state: string, data: Json, extra: Partial<Inspection> = {}): Promise<Inspection> => ({ ref: ref(k2, id), kind: k2, title, state, stale: false, blocked: state === 'disabled' || state === 'revoked' || state === 'suspended', staleReasons: [], versions: [], sources: [], dependents: [], permissions: [], decisions: [], history: await history(ref(k2, id)), data, ...extra });
    if (kind === 'organization') {
      if (id !== ctx.tenantId) return null;
      const o = await getOrganization(ctx);
      return make('organization', o.name, o.status, o as unknown as Json);
    }
    if (kind === 'project') {
      const p = (await listProjects(ctx)).find((x) => x.id === id);
      return p === undefined ? null : make('project', p.name, p.status, p as unknown as Json);
    }
    if (['actor', 'user', 'agent', 'service'].includes(kind)) {
      const row = await memberActor(sql, ctx.tenantId, id);
      if (row === undefined || (kind !== 'actor' && (kind === 'user' ? 'human' : kind) !== row.kind)) return null;
      const ms = await sql.query<R>(`select project_id, roles, status, expires_at from ${S}.memberships where tenant_id=$1 and actor_id=$2 and status <> 'removed' and ($3 or project_id in ($4, '${ORG_WIDE}')) order by project_id`, [ctx.tenantId, id, isAdmin(ctx), ctx.projectId]);
      if (ms.length === 0 && !isAdmin(ctx)) return null;
      const grants = await listGrants({ ...ctx, capabilities: [...ctx.capabilities, 'identity:read'] }, { actorId: id });
      return make('actor', row.display_name, row.status, toActor(row) as unknown as Json, { permissions: ms.map((m) => ({ projectId: m.project_id, roles: m.roles, status: m.status, expiresAt: isoOrNull(m.expires_at) })), dependents: grants.map((g) => g.ref) });
    }
    if (kind === 'role') {
      const r = (await sql.query<R>(`select * from ${S}.roles where tenant_id=$1 and name=$2`, [ctx.tenantId, id]))[0];
      if (r === undefined) return null;
      const versions = (await roleHistory(ctx, id)).map((v) => ({ revision: v.version, at: v.at, actorId: v.actorId, summary: `${v.deleted ? 'deleted; ' : ''}${v.capabilities.length} capabilities at policy version ${v.policyVersion}` }));
      return make('role', r.name, r.deleted ? 'deleted' : 'active', toRole(r) as unknown as Json, { versions });
    }
    if (kind === 'grant') {
      const g = (await sql.query<R>(`select * from ${S}.grants where tenant_id=$1 and id=$2 and ($3 or project_id in ($4, '${ORG_WIDE}'))`, [ctx.tenantId, id, isAdmin(ctx), ctx.projectId]))[0];
      if (g === undefined) return null;
      const info = toGrant(g);
      return make('grant', `${info.capability} → ${info.actorId}`, info.state, info as unknown as Json, { sources: [ref('actor', info.actorId)], permissions: [{ capability: info.capability, purpose: info.purpose, bounds: info.bounds, expiresAt: info.expiresAt }] });
    }
    if (kind === 'compartment') {
      const c = (await listCompartments(ctx)).find((x) => x.id === id);
      return c === undefined ? null : make('compartment', c.id, 'active', c as unknown as Json);
    }
    return null;
  }
  async function search(ctx: ServiceContext, query: { q: string; limit?: number }): Promise<SearchHit[]> {
    need(ctx, 'identity:read');
    const q = typeof query?.q === 'string' ? query.q.trim().slice(0, 200) : '';
    if (q === '') return [];
    const limit = Math.min(Math.max(Number.isInteger(query.limit) ? query.limit as number : 20, 1), 100);
    const admin = isAdmin(ctx), p = like(q);
    const rows = await sql.query<R>(`
      (select 'project' as kind, p.id, p.name as title, p.kind as snippet, p.status as state from ${S}.projects p where p.tenant_id=$1 and (p.name ilike $2 or p.id ilike $2) and ($3 or p.id=$4))
      union all (select 'actor', a.id, a.display_name, a.kind || coalesce(' · ' || nullif(a.description, ''), ''), a.status from ${S}.actors a where (a.display_name ilike $2 or a.description ilike $2 or exists(select 1 from ${S}.credentials c where c.actor_id=a.id and c.login ilike $2))
        and exists(select 1 from ${S}.memberships m where m.tenant_id=$1 and m.actor_id=a.id and m.status <> 'removed' and ($3 or m.project_id in ($4, '${ORG_WIDE}'))))
      union all (select 'role', r.name, r.name, r.description, 'active' from ${S}.roles r where r.tenant_id=$1 and not r.deleted and (r.name ilike $2 or r.description ilike $2))
      union all (select 'grant', g.id, g.capability || ' → ' || g.actor_id, g.reason, case when g.revoked_at is not null then 'revoked' when g.expires_at <= $5 then 'expired' else 'active' end from ${S}.grants g where g.tenant_id=$1 and (g.capability ilike $2 or g.reason ilike $2) and ($3 or g.project_id in ($4, '${ORG_WIDE}')))
      union all (select 'compartment', c.id, c.id, c.description, 'active' from ${S}.compartments c where c.tenant_id=$1 and c.project_id=$4 and (c.id ilike $2 or c.description ilike $2)
        and ($3 or exists(select 1 from ${S}.compartment_members cm where cm.tenant_id=c.tenant_id and cm.project_id=c.project_id and cm.compartment_id=c.id and cm.actor_id=$6)))
      order by kind, title limit ${limit}`, [ctx.tenantId, p, admin, ctx.projectId, clock().toISOString(), ctx.actor.id]);
    return rows.map((r) => ({ ref: ref(r.kind, r.id), kind: r.kind, title: r.title, snippet: String(r.snippet ?? '').slice(0, 300), state: r.state }));
  }
  /** Organization-wide for administrators; otherwise limited to entries recorded in the token's project. */
  async function audit(ctx: ServiceContext, options: { after?: string; limit?: number; subject?: string } = {}): Promise<AuditRecord[]> {
    need(ctx, 'identity:audit');
    return listAudit(sql, S, ctx, { ...options, allProjects: isAdmin(ctx) });
  }
  async function events(ctx: ServiceContext, options: { after?: string; limit?: number } = {}): Promise<EngineEvent[]> {
    need(ctx, 'identity:events');
    return (await readEvents(sql, S, { ...options, tenantId: ctx.tenantId })).map((e) => ({ ...e, engine: 'E01' }));
  }
  /** Identity depends on no other engine: upstream changes are acknowledged and affect nothing. */
  async function applyUpstreamChange(ctx: ServiceContext, _change: UpstreamChange): Promise<{ affected: string[] }> {
    need(ctx, 'identity:events');
    return { affected: [] };
  }
  async function health(): Promise<{ ok: boolean; detail: Json }> {
    try {
      const keys = await sql.query<R>(`select count(*) filter (where status='active')::int as active from ${S}.signing_keys`);
      return { ok: true, detail: { database: 'ok', bootstrapped: await isBootstrapped(), signing: k.sealer === null ? 'unavailable: IDENTITY_KEY_ENCRYPTION_KEY not configured' : ((keys[0] as R).active > 0 ? 'ready' : 'no key yet (created on first issuance)') } };
    } catch { return { ok: false, detail: { database: 'unavailable' } }; }
  }
  /** Housekeeping: drops expired throttles, OIDC states and revocation rows that can no longer matter; optionally rotates an old signing key. */
  async function maintenance(options: { rotateKeysOlderThanSeconds?: number } = {}): Promise<{ rotated: string | null }> {
    const at = clock().toISOString();
    await sql.query(`delete from ${S}.oidc_states where expires_at < $1`, [at]);
    await sql.query(`delete from ${S}.token_revocations where token_expires_at < $1`, [at]);
    await sql.query(`delete from ${S}.auth_attempts where last_failed_at < $1 and (locked_until is null or locked_until < $2)`, [new Date(clock().getTime() - lock.window * 1000).toISOString(), at]);
    if (options.rotateKeysOlderThanSeconds !== undefined && k.sealer !== null) {
      const old = await sql.query(`select 1 from ${S}.signing_keys where status='active' and created_at < $1`, [new Date(clock().getTime() - options.rotateKeysOlderThanSeconds * 1000).toISOString()]);
      if (old.length > 0) return { rotated: (await k.rotateSigningKey()).kid };
    }
    return { rotated: null };
  }
  /** The deployment's first organization may administer signing keys over HTTP. */
  async function requirePlatformAdmin(ctx: ServiceContext): Promise<void> {
    await needNow(ctx, 'identity:admin');
    const platform = (await sql.query<R>(`select value from ${S}.deployment where key='platform'`))[0];
    invariant(platform !== undefined && (platform.value as R).tenantId === ctx.tenantId, 'forbidden', 'Signing keys are administered from the platform organization');
    await requireOwner(sql, ctx, 'administer signing keys');
  }
  async function jwks(): Promise<{ issuer: string; keys: Record<string, string>; jwks: { keys: Json[] } }> {
    const { createPublicKey } = await import('node:crypto');
    const keys = await k.loadPublicKeys();
    return { issuer: k.issuer, keys, jwks: { keys: Object.entries(keys).map(([kid, pem]) => ({ ...(createPublicKey(pem).export({ format: 'jwk' }) as { [key: string]: Json }), kid, use: 'sig', alg: 'EdDSA' })) } };
  }

  const engine = {
    manifest,
    // host / unauthenticated entry points
    bootstrapFirstAdministrator, isBootstrapped, login, logout, sessionDirectory, issueAccessToken, authenticateService,
    publicKeys: k.loadPublicKeys, jwks, verifier: k.verifier as () => TokenVerifier, isRevoked: k.isRevoked as (claims: TokenClaims | IdentityClaims) => Promise<boolean>,
    host: {
      /** Trusted in-process callers only (never exposed over HTTP). */
      rotateSigningKey: k.rotateSigningKey, revokeSigningKey: k.revokeSigningKey, maintenance,
      issueServiceToken: (input: { tenantId: string; serviceId: string; projectId: string; purpose: string; capabilities?: readonly string[]; ttlSeconds?: number }): Promise<IssuedToken> =>
        k.mint({ actorId: input.serviceId, tenantId: input.tenantId, projectId: input.projectId, purpose: input.purpose, ttlSeconds: input.ttlSeconds ?? ttl.service, kind: 'service', ...(input.capabilities === undefined ? {} : { requested: validCaps(input.capabilities) }) }),
    },
    rotateSigningKey: async (ctx: ServiceContext) => { await requirePlatformAdmin(ctx); const out = await k.rotateSigningKey(); return out; },
    revokeSigningKey: async (ctx: ServiceContext, kid: string) => { await requirePlatformAdmin(ctx); await k.revokeSigningKey(kid); },
    // directory
    whoami, changePassword, createOrganization, getOrganization, updateOrganization, listMyOrganizations, createProject, updateProject, listProjects,
    createUser, setMembership, removeMember, listMembers, getActor, resetPassword, createAgent, createServiceIdentity, rotateServiceSecret,
    listAgents: (ctx: ServiceContext) => listActors(ctx, 'agent'), listServiceIdentities: (ctx: ServiceContext) => listActors(ctx, 'service'), listUsers: (ctx: ServiceContext) => listActors(ctx, 'human'),
    listRoles, roleHistory, defineRole, listPurposes, definePurpose, createCompartment, setCompartmentMember, listCompartments,
    // tokens, grants, revocation, decisions
    issueServiceToken, issueAgentToken, createGrant, revokeGrant, listGrants, checkGrant, useGrant,
    revokeToken, listSessions, revokeSession, revokeActor, reinstateActor, authorize, explain, counts, exportDirectory,
    // federation
    ...fed,
    // standard surface
    inspect, search, audit, events, applyUpstreamChange, health,
  };
  return engine satisfies StandardEngine & AuthorizationPort;
}
export type IdentityEngine = ReturnType<typeof createEngine>;
