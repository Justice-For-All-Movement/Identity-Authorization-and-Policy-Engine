// Governance views and account lifecycle: who-can-access, revocation impact, redacted projections, rate limits,
// invitations and password reset. All decisions reuse the kernel's single `decide` procedure on current state.
import { randomUUID } from 'node:crypto';
import { DomainError, invariant } from '../contracts.ts';
import type { Context, Json } from '../contracts.ts';
import { appendAudit, emitEvent } from '../service-kit.ts';
import type { ServiceContext, Sql } from '../service-kit.ts';
import { ORG_WIDE, SCHEMA } from './schema.ts';
import { hashPassword, randomToken, sha256 } from './crypto.ts';
import { EXACT_CAP, covers, denied, iso, need, text, validId } from './core.ts';
import type { AccessDecision, EnginePorts, R, SessionInfo } from './core.ts';
import type { Kernel } from './kernel.ts';

const S = SCHEMA;
const KEY = /^[a-z][a-z0-9_.:-]{0,127}$/;
const INVITATION_DEFAULT_SECONDS = 7 * 86400, INVITATION_MAX_SECONDS = 30 * 86400;
const RESET_SECONDS = 1800, RESETS_PER_HOUR = 3;

export type AccessHolder = Readonly<{ actorId: string; kind: string; displayName: string; via: AccessDecision['via'] }>;
export type InvitationInfo = Readonly<{ id: string; projectId: string; roles: readonly string[]; displayName: string | null; expiresAt: string; createdAt: string; createdBy: string; state: 'pending' | 'accepted' | 'revoked' | 'expired'; acceptedBy: string | null }>;
export type RateLimitState = Readonly<{ allowed: boolean; key: string; subject: string; limit: number; used: number; remaining: number; resetAt: string }>;

type Helpers = Readonly<{
  needNow: (ctx: ServiceContext, capability: string, q?: Sql) => Promise<void>;
  requireOwner: (q: Sql, ctx: ServiceContext, what: string) => Promise<void>;
  isAdmin: (ctx: ServiceContext) => boolean;
  projectScope: (ctx: ServiceContext, projectId: string | undefined) => string;
  authorize: (ctx: ServiceContext, request: { capability: string; resource?: string; compartment?: string }) => Promise<AccessDecision>;
  createHumanTx: (tx: Sql, by: Context, homeTenantId: string, input: { login: unknown; password: unknown; displayName: unknown }) => Promise<string>;
  createSession: (q: Sql, actorId: string, method: string, boundTenantId: string | null) => Promise<SessionInfo>;
  loadSession: (refreshToken: unknown) => Promise<R>;
  secondFactor: (m: R, input: { code?: string; recoveryCode?: string }) => Promise<boolean>;
  password: (value: unknown) => string;
  loginName: (value: unknown) => string;
  privilegedRole: (capabilities: readonly string[]) => boolean;
}>;

export function createGovernance(k: Kernel, ports: EnginePorts, h: Helpers) {
  const { sql, cfg, clock, ref, record, bump } = k;

  // ───────────────────────── policy inspector views ─────────────────────────
  /**
   * "Who can access this record": every actor with a current membership in the project, evaluated with the same
   * decision procedure as `authorize` (no token involved). Requires `identity:read`; another project needs `identity:admin`.
   */
  async function whoCanAccess(ctx: ServiceContext, input: { capability: string; resource?: string; purpose?: string; projectId?: string; compartment?: string; limit?: number }): Promise<{ capability: string; purpose: string; projectId: string; resource: string | null; policyVersion: string; allowed: AccessHolder[]; deniedCount: number; evaluated: number; truncated: boolean }> {
    need(ctx, 'identity:read');
    invariant(typeof input?.capability === 'string' && EXACT_CAP.test(input.capability), 'invalid_input', 'An exact capability `engine:action` is required');
    const projectId = h.projectScope(ctx, input.projectId);
    invariant(projectId !== ORG_WIDE, 'invalid_input', 'A concrete project is required');
    const purpose = input.purpose ?? ctx.purpose;
    const limit = Math.min(Math.max(Number.isInteger(input.limit) ? input.limit as number : 200, 1), 500);
    const at = clock().toISOString();
    const candidates = await sql.query<R>(`select distinct a.id, a.kind, a.display_name from ${S}.memberships m join ${S}.actors a on a.id=m.actor_id
      where m.tenant_id=$1 and m.project_id in ($2, '${ORG_WIDE}') and m.status='active' and (m.expires_at is null or m.expires_at > $3) order by a.id limit ${limit + 1}`, [ctx.tenantId, projectId, at]);
    const truncated = candidates.length > limit;
    const allowed: AccessHolder[] = [];
    let deniedCount = 0, pv = '0';
    for (const c of candidates.slice(0, limit)) {
      const d = await k.decide(sql, { tenantId: ctx.tenantId, projectId, actorId: c.id, purpose, capability: input.capability, resource: input.resource, compartment: input.compartment });
      pv = d.policyVersion;
      if (d.allowed) allowed.push({ actorId: c.id, kind: c.kind, displayName: c.display_name, via: d.via }); else deniedCount++;
    }
    return { capability: input.capability, purpose, projectId, resource: input.resource ?? null, policyVersion: pv, allowed, deniedCount, evaluated: Math.min(candidates.length, limit), truncated };
  }

  /**
   * Read-only preview of what a revocation would end: an actor (memberships, grants, sessions), a role (each holder's
   * capabilities that no other current role supplies) or a grant (whether the grantee keeps the capability by role).
   */
  async function revocationImpact(ctx: ServiceContext, input: { actorId?: string; role?: string; grantId?: string }): Promise<Json> {
    need(ctx, 'identity:read');
    const given = [input?.actorId, input?.role, input?.grantId].filter((v) => v !== undefined);
    invariant(given.length === 1, 'invalid_input', 'Exactly one of actorId, role or grantId is required');
    const admin = h.isAdmin(ctx), at = clock().toISOString();
    if (input.actorId !== undefined) {
      const actorId = validId(input.actorId, 'actorId');
      const ms = await sql.query<R>(`select project_id, roles, status from ${S}.memberships where tenant_id=$1 and actor_id=$2 and status='active' and ($3 or project_id in ($4,'${ORG_WIDE}')) order by project_id`, [ctx.tenantId, actorId, admin, ctx.projectId]);
      if (ms.length === 0) throw new DomainError('not_found', 'Not found');
      const grants = await sql.query<R>(`select id, capability, purpose, project_id from ${S}.grants where tenant_id=$1 and actor_id=$2 and revoked_at is null and expires_at > $3 and ($4 or project_id in ($5,'${ORG_WIDE}')) order by created_at`, [ctx.tenantId, actorId, at, admin, ctx.projectId]);
      const actor = (await sql.query<R>(`select kind, home_tenant_id, (select count(distinct tenant_id) from ${S}.memberships where actor_id=$1 and status <> 'removed' and tenant_id <> $2)::int as elsewhere from ${S}.actors where id=$1`, [actorId, ctx.tenantId]))[0] as R;
      const sessions = admin ? Number((await sql.query<R>(`select count(*)::int as n from ${S}.sessions where actor_id=$1 and revoked_at is null and expires_at > $2`, [actorId, at]))[0]?.n ?? 0) : null;
      const accountDisabled = actor.home_tenant_id === ctx.tenantId && actor.elsewhere === 0;
      return { kind: 'actor', actorId, memberships: ms.map((m) => ({ projectId: m.project_id, roles: m.roles })), activeGrants: grants.map((g) => ({ grantId: g.id, capability: g.capability, purpose: g.purpose, projectId: g.project_id })),
        activeSessions: sessions, revoke: { outstandingTokensEnd: true }, revokeAndDisable: { membershipsSuspended: ms.length, accountDisabled, sessionsEnded: accountDisabled ? sessions : 0 } };
    }
    if (input.role !== undefined) {
      const role = text(input.role, 'role', 60);
      const defs = new Map((await sql.query<R>(`select name, capabilities from ${S}.roles where tenant_id=$1 and not deleted`, [ctx.tenantId])).map((r) => [r.name as string, r.capabilities as string[]]));
      const caps = defs.get(role);
      if (caps === undefined) throw new DomainError('not_found', 'Not found');
      const holders = await sql.query<R>(`select actor_id, project_id, roles from ${S}.memberships where tenant_id=$1 and status='active' and $2 = any(roles) and ($3 or project_id in ($4,'${ORG_WIDE}')) order by actor_id, project_id`, [ctx.tenantId, role, admin, ctx.projectId]);
      return { kind: 'role', role, capabilities: caps, holders: holders.map((m) => {
        const others = (m.roles as string[]).filter((r) => r !== role).flatMap((r) => defs.get(r) ?? []);
        return { actorId: m.actor_id, projectId: m.project_id, loses: caps.filter((c) => !covers(others, c)) };
      }) };
    }
    const grantId = validId(input.grantId, 'grantId');
    const g = (await sql.query<R>(`select * from ${S}.grants where tenant_id=$1 and id=$2 and ($3 or project_id in ($4,'${ORG_WIDE}'))`, [ctx.tenantId, grantId, admin, ctx.projectId]))[0];
    if (g === undefined) throw new DomainError('not_found', 'Not found');
    const project = g.project_id === ORG_WIDE ? ctx.projectId : g.project_id as string;
    const st = await k.loadState(sql, ctx.tenantId, project, g.actor_id, clock());
    const pcaps = await k.purposeCaps(sql, ctx.tenantId, g.purpose);
    const byRole = covers(st.roleCaps, g.capability) && pcaps !== null && covers(pcaps, g.capability) && !(st.actor?.kind === 'agent');
    return { kind: 'grant', grantId, actorId: g.actor_id, capability: g.capability, purpose: g.purpose, active: k.grantUsable(g, clock()) === null, granteeRetainsByRole: byRole };
  }

  /**
   * Field-level redacted projection of a record supplied by another engine. `fields` classifies each top-level field
   * by the exact capability needed to see it (`null` = visible to anyone who may read the record). Unclassified
   * fields are withheld unless `unclassified: 'include'`. Decisions are current-state: for the caller through
   * `authorize` (token-bound, audited for sensitive denials), or a preview for another actor (`identity:read`).
   */
  async function redact(ctx: ServiceContext, input: { record: Json; fields: Record<string, string | null>; resource?: string; compartment?: string; actorId?: string; purpose?: string; unclassified?: 'withhold' | 'include' }): Promise<{ projection: { [key: string]: Json }; withheld: { field: string; capability: string | null; reason: string }[]; decisions: Record<string, { allowed: boolean; reason: string }>; policyVersion: string }> {
    invariant(typeof ctx?.actor?.id === 'string', 'unauthenticated', 'Authenticated context required');
    const rec = input?.record;
    invariant(rec !== null && typeof rec === 'object' && !Array.isArray(rec) && JSON.stringify(rec).length <= 100000, 'invalid_input', 'record must be a JSON object of at most 100 kB');
    const fields = input.fields;
    invariant(fields !== null && typeof fields === 'object' && !Array.isArray(fields) && Object.keys(fields).length <= 200, 'invalid_input', 'fields must map field names to a capability or null');
    for (const [name, cap] of Object.entries(fields)) invariant(name.length <= 128 && (cap === null || (typeof cap === 'string' && EXACT_CAP.test(cap))), 'invalid_input', `Field ${name.slice(0, 64)} needs an exact capability or null`);
    invariant(input.unclassified === undefined || input.unclassified === 'withhold' || input.unclassified === 'include', 'invalid_input', 'unclassified must be withhold or include');
    const preview = input.actorId !== undefined && input.actorId !== ctx.actor.id;
    if (preview) { need(ctx, 'identity:read'); validId(input.actorId, 'actorId'); }
    const decisions: Record<string, { allowed: boolean; reason: string }> = {};
    let pv = '0';
    for (const cap of new Set(Object.values(fields).filter((c): c is string => c !== null))) {
      const d = preview
        ? await k.decide(sql, { tenantId: ctx.tenantId, projectId: ctx.projectId, actorId: input.actorId as string, purpose: input.purpose ?? ctx.purpose, capability: cap, resource: input.resource, compartment: input.compartment })
        : await h.authorize(ctx, { capability: cap, ...(input.resource === undefined ? {} : { resource: input.resource }), ...(input.compartment === undefined ? {} : { compartment: input.compartment }) });
      decisions[cap] = { allowed: d.allowed, reason: d.reason };
      pv = d.policyVersion;
    }
    const projection: { [key: string]: Json } = {};
    const withheld: { field: string; capability: string | null; reason: string }[] = [];
    for (const [field, value] of Object.entries(rec as { [key: string]: Json })) {
      if (!Object.hasOwn(fields, field)) { if (input.unclassified === 'include') projection[field] = value; else withheld.push({ field, capability: null, reason: 'unclassified' }); continue; }
      const cap = fields[field] ?? null;
      if (cap === null || decisions[cap]?.allowed === true) projection[field] = value;
      else withheld.push({ field, capability: cap, reason: decisions[cap]?.reason ?? 'capability_not_granted' });
    }
    return { projection, withheld, decisions, policyVersion: pv };
  }

  // ───────────────────────── rate limits ─────────────────────────
  function limitInput(ctx: ServiceContext, input: { key: string; subject?: string }): { key: string; subject: string } {
    invariant(typeof ctx?.actor?.id === 'string' && typeof ctx.tenantId === 'string', 'unauthenticated', 'Authenticated context required');
    invariant(typeof input?.key === 'string' && KEY.test(input.key), 'invalid_input', 'key must match ' + KEY.source);
    const subject = input.subject === undefined ? ctx.actor.id : validId(input.subject, 'subject');
    if (subject !== ctx.actor.id) invariant(ctx.actor.kind === 'service' || h.isAdmin(ctx), 'forbidden', 'Only a service identity or an administrator may meter another actor');
    return { key: input.key, subject };
  }
  async function consume(q: Sql, tenantId: string, subject: string, key: string, limit: number, windowSeconds: number, cost: number): Promise<RateLimitState> {
    const at = clock();
    await q.query(`insert into ${S}.rate_limits (tenant_id, subject, key, window_start, used) values ($1,$2,$3,$4,0) on conflict do nothing`, [tenantId, subject, key, at.toISOString()]);
    const row = (await q.query<R>(`select * from ${S}.rate_limits where tenant_id=$1 and subject=$2 and key=$3 for update`, [tenantId, subject, key]))[0] as R;
    let start = new Date(row.window_start), used = row.used as number;
    if (start.getTime() + windowSeconds * 1000 <= at.getTime()) { start = at; used = 0; }
    const allowed = used + cost <= limit;
    if (allowed) used += cost;
    await q.query(`update ${S}.rate_limits set window_start=$4, used=$5 where tenant_id=$1 and subject=$2 and key=$3`, [tenantId, subject, key, start.toISOString(), used]);
    return { allowed, key, subject, limit, used, remaining: Math.max(limit - used, 0), resetAt: new Date(start.getTime() + windowSeconds * 1000).toISOString() };
  }
  /**
   * Fixed-window counter shared by every engine process: atomically consumes `cost` units of `limit` per
   * `windowSeconds` for (organization, subject, key), or answers `allowed: false` without consuming. Callers use
   * consistent parameters per key. Another subject may be metered only by a service identity or an administrator.
   */
  async function consumeRateLimit(ctx: ServiceContext, input: { key: string; limit: number; windowSeconds: number; cost?: number; subject?: string }): Promise<RateLimitState> {
    const { key, subject } = limitInput(ctx, input);
    const limit = input.limit, windowSeconds = input.windowSeconds, cost = input.cost ?? 1;
    invariant(Number.isInteger(limit) && limit >= 1 && limit <= 1_000_000, 'invalid_input', 'limit must be an integer 1–1000000');
    invariant(Number.isInteger(windowSeconds) && windowSeconds >= 1 && windowSeconds <= 86400, 'invalid_input', 'windowSeconds must be an integer 1–86400');
    invariant(Number.isInteger(cost) && cost >= 1 && cost <= limit, 'invalid_input', 'cost must be an integer 1–limit');
    return sql.tx((tx) => consume(tx, ctx.tenantId, subject, key, limit, windowSeconds, cost));
  }
  async function rateLimitStatus(ctx: ServiceContext, input: { key: string; subject?: string }): Promise<{ key: string; subject: string; used: number; windowStart: string } | null> {
    const { key, subject } = limitInput(ctx, input);
    const row = (await sql.query<R>(`select * from ${S}.rate_limits where tenant_id=$1 and subject=$2 and key=$3`, [ctx.tenantId, subject, key]))[0];
    return row === undefined ? null : { key, subject, used: row.used, windowStart: iso(row.window_start) };
  }

  // ───────────────────────── invitations ─────────────────────────
  const toInvitation = (r: R): InvitationInfo => ({ id: r.id, projectId: r.project_id, roles: r.roles, displayName: r.display_name ?? null, expiresAt: iso(r.expires_at), createdAt: iso(r.created_at), createdBy: r.created_by,
    state: r.accepted_at !== null ? 'accepted' : r.revoked_at !== null ? 'revoked' : new Date(r.expires_at).getTime() <= clock().getTime() ? 'expired' : 'pending', acceptedBy: r.accepted_by ?? null });
  async function checkRoles(q: Sql, tenantId: string, roles: unknown): Promise<{ roles: string[]; privileged: boolean }> {
    invariant(Array.isArray(roles) && roles.length > 0 && roles.length <= 32 && roles.every((r) => typeof r === 'string'), 'invalid_input', 'At least one role is required');
    const defs = new Map((await q.query<R>(`select * from ${S}.roles where tenant_id=$1 and not deleted`, [tenantId])).map((r) => [r.name as string, r]));
    let privileged = false;
    for (const name of roles as string[]) {
      const def = defs.get(name);
      invariant(def !== undefined, 'invalid_input', `Unknown role ${name}`);
      invariant((def.actor_kinds as string[]).includes('human'), 'invalid_input', `Role ${name} cannot be held by a person`);
      if (name === 'owner' || h.privilegedRole(def.capabilities as string[])) privileged = true;
    }
    return { roles: [...new Set(roles as string[])].sort(), privileged };
  }
  /**
   * Creates a single-use invitation to join a project with given roles. The token is returned once (the host delivers
   * it; this engine sends nothing) and stored only as a hash. Administrative roles need an owner.
   */
  async function createInvitation(ctx: ServiceContext, input: { projectId?: string; roles: readonly string[]; displayName?: string; expiresInSeconds?: number }): Promise<{ invitation: InvitationInfo; token: string }> {
    await h.needNow(ctx, 'identity:admin');
    const projectId = input?.projectId === undefined ? ctx.projectId : input.projectId === ORG_WIDE ? ORG_WIDE : validId(input.projectId, 'projectId');
    const seconds = input.expiresInSeconds ?? INVITATION_DEFAULT_SECONDS;
    invariant(Number.isInteger(seconds) && seconds >= 300 && seconds <= INVITATION_MAX_SECONDS, 'invalid_input', `expiresInSeconds must be 300–${INVITATION_MAX_SECONDS}`);
    const token = randomToken(32);
    return sql.tx(async (tx) => {
      if (projectId !== ORG_WIDE) invariant((await tx.query(`select 1 from ${S}.projects where tenant_id=$1 and id=$2 and status='active'`, [ctx.tenantId, projectId])).length > 0, 'not_found', 'Not found');
      const { roles, privileged } = await checkRoles(tx, ctx.tenantId, input.roles);
      if (privileged) await h.requireOwner(tx, ctx, 'invite with administrative roles');
      const rows = await tx.query<R>(`insert into ${S}.invitations (id, tenant_id, project_id, roles, token_hash, display_name, purpose, issuer_project_id, expires_at, created_at, created_by) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) returning *`,
        [randomUUID(), ctx.tenantId, projectId, roles, sha256(token), input.displayName === undefined ? null : text(input.displayName, 'displayName'), ctx.purpose, ctx.projectId, new Date(clock().getTime() + seconds * 1000).toISOString(), ctx.now, ctx.actor.id]);
      const inv = toInvitation(rows[0] as R);
      await appendAudit(tx, S, ctx, 'invitation.created', ref('invitation', inv.id), { projectId, roles, expiresAt: inv.expiresAt });
      return { invitation: inv, token };
    });
  }
  async function listInvitations(ctx: ServiceContext, options: { includeClosed?: boolean } = {}): Promise<InvitationInfo[]> {
    need(ctx, 'identity:admin');
    const rows = await sql.query<R>(`select * from ${S}.invitations where tenant_id=$1 order by created_at desc limit 500`, [ctx.tenantId]);
    return rows.map(toInvitation).filter((i) => options.includeClosed === true || i.state === 'pending');
  }
  async function revokeInvitation(ctx: ServiceContext, invitationId: string): Promise<InvitationInfo> {
    await h.needNow(ctx, 'identity:admin');
    return sql.tx(async (tx) => {
      const rows = await tx.query<R>(`update ${S}.invitations set revoked_at=$3, revoked_by=$4 where tenant_id=$1 and id=$2 and accepted_at is null and revoked_at is null returning *`, [ctx.tenantId, validId(invitationId, 'invitationId'), ctx.now, ctx.actor.id]);
      invariant(rows[0] !== undefined, 'not_found', 'Not found');
      await appendAudit(tx, S, ctx, 'invitation.revoked', ref('invitation', invitationId), {});
      return toInvitation(rows[0]);
    });
  }
  /**
   * Redeems an invitation, either creating a new local account (`login`, `password`, `displayName`) or, with a
   * `refreshToken`, adding the membership to the signed-in person's existing account (one identity across
   * organizations). The inviter's authority is re-checked on current state; a demoted inviter's invitations fail.
   */
  async function acceptInvitation(input: { token: string; login?: string; password?: string; displayName?: string; refreshToken?: string }): Promise<{ actorId: string; tenantId: string; projectId: string; roles: readonly string[]; session: SessionInfo | null }> {
    invariant(input !== null && typeof input === 'object' && typeof input.token === 'string' && input.token.length <= 200, 'invalid_input', 'An invitation token is required');
    const existing = input.refreshToken === undefined ? null : await h.loadSession(input.refreshToken);
    return sql.tx(async (tx) => {
      const inv = (await tx.query<R>(`select * from ${S}.invitations where token_hash=$1 for update`, [sha256(input.token)]))[0];
      const at = clock();
      if (inv === undefined || inv.accepted_at !== null || inv.revoked_at !== null || new Date(inv.expires_at).getTime() <= at.getTime()) throw denied('The invitation is not valid');
      const inviter = await k.decide(tx, { tenantId: inv.tenant_id, projectId: inv.issuer_project_id, actorId: inv.created_by, purpose: inv.purpose, capability: 'identity:admin' });
      const { roles, privileged } = await checkRoles(tx, inv.tenant_id, inv.roles);
      const inviterRoles = (await k.loadState(tx, inv.tenant_id, inv.issuer_project_id, inv.created_by, at)).roles;
      if (!inviter.allowed || (privileged && !inviterRoles.includes('owner'))) throw new DomainError('forbidden', 'The invitation is no longer backed by a current administrator');
      if (inv.project_id !== ORG_WIDE) invariant((await tx.query(`select 1 from ${S}.projects where tenant_id=$1 and id=$2 and status='active'`, [inv.tenant_id, inv.project_id])).length > 0, 'forbidden', 'The project is no longer active');
      let actorId: string;
      const by = k.systemContext(inv.tenant_id, inv.project_id === ORG_WIDE ? inv.issuer_project_id : inv.project_id, inv.created_by, 'human', 'invitation');
      if (existing !== null) {
        actorId = existing.actor_id as string;
        const kind = (await tx.query<R>(`select kind from ${S}.actors where id=$1`, [actorId]))[0]?.kind;
        invariant(kind === 'human', 'forbidden', 'Only a person can accept an invitation');
      } else {
        actorId = await h.createHumanTx(tx, by, inv.tenant_id, { login: input.login, password: input.password, displayName: input.displayName ?? inv.display_name ?? undefined });
      }
      await tx.query(`select 1 from ${S}.organizations where id=$1 for update`, [inv.tenant_id]);
      await tx.query(`insert into ${S}.memberships (tenant_id, project_id, actor_id, roles, status, created_at, updated_at, updated_by) values ($1,$2,$3,$4,'active',$5,$5,$6)
        on conflict (tenant_id, project_id, actor_id) do update set roles = (select array_agg(distinct r order by r) from unnest(${S}.memberships.roles || excluded.roles) r), status='active', expires_at=null, updated_at=excluded.updated_at, updated_by=excluded.updated_by, revision=${S}.memberships.revision+1`,
        [inv.tenant_id, inv.project_id, actorId, roles, at.toISOString(), inv.created_by]);
      await tx.query(`update ${S}.invitations set accepted_at=$2, accepted_by=$3 where id=$1`, [inv.id, at.toISOString(), actorId]);
      const pv = await bump(tx, by, `invitation ${inv.id} accepted`);
      await record(tx, by, 'invitation.accepted', ref('invitation', inv.id), { actorId, projectId: inv.project_id, roles }, undefined);
      await record(tx, by, 'membership.changed', ref('actor', actorId), { projectId: inv.project_id, roles, status: 'active', expiresAt: null, policyVersion: pv }, 'membership.changed');
      const session = existing === null ? await h.createSession(tx, actorId, 'password', null) : null;
      return { actorId, tenantId: inv.tenant_id, projectId: inv.project_id, roles, session };
    });
  }

  // ───────────────────────── password reset ─────────────────────────
  /**
   * Starts a self-service reset. Always answers `{ accepted: true }` for any well-formed login (no enumeration) and
   * delivers asynchronously through the host's `passwordResetDelivery` port, at most three times an hour per login.
   */
  async function requestPasswordReset(input: { login: string }): Promise<{ accepted: true }> {
    const deliver = ports.passwordResetDelivery;
    if (deliver === undefined) throw new DomainError('unavailable', 'Password reset delivery is not configured for this deployment');
    const login = h.loginName(input?.login);
    const metered = await sql.tx((tx) => consume(tx, '-', sha256(`reset:${login}`).slice(0, 64), 'password_reset', RESETS_PER_HOUR, 3600, 1));
    if (!metered.allowed) return { accepted: true };
    const cred = (await sql.query<R>(`select c.actor_id, a.home_tenant_id, a.home_project_id from ${S}.credentials c join ${S}.actors a on a.id=c.actor_id where c.login=$1 and a.status='active' and a.kind='human'`, [login]))[0];
    if (cred === undefined) return { accepted: true };
    const token = randomToken(32), at = clock();
    const expiresAt = new Date(at.getTime() + RESET_SECONDS * 1000).toISOString();
    await sql.tx(async (tx) => {
      await tx.query(`delete from ${S}.password_resets where actor_id=$1 and used_at is null`, [cred.actor_id]);
      await tx.query(`insert into ${S}.password_resets (token_hash, actor_id, expires_at, created_at) values ($1,$2,$3,$4)`, [sha256(token), cred.actor_id, expiresAt, at.toISOString()]);
      await appendAudit(tx, S, k.systemContext(cred.home_tenant_id, cred.home_project_id ?? 'main', cred.actor_id, 'human', 'account_recovery'), 'password_reset.requested', ref('actor', cred.actor_id), { expiresAt });
    });
    // Delivered in the background so the answer takes the same time whether or not the account exists.
    void deliver({ type: 'password_reset', actorId: cred.actor_id, login, token, expiresAt }, AbortSignal.timeout(10000)).catch(() => {
      void sql.query(`delete from ${S}.password_resets where token_hash=$1`, [sha256(token)]).catch(() => {});
    });
    return { accepted: true };
  }
  /**
   * Completes a reset with the delivered token: single use, 30 minutes. When two-factor sign-in is enabled a current
   * code or recovery code is also required. Every session of the account ends and the login lock is cleared.
   */
  async function completePasswordReset(input: { token: string; newPassword: string; code?: string; recoveryCode?: string }): Promise<{ ok: true }> {
    invariant(input !== null && typeof input === 'object' && typeof input.token === 'string' && input.token.length <= 200, 'invalid_input', 'A reset token is required');
    const newPassword = h.password(input.newPassword);
    const at = clock();
    const row = (await sql.query<R>(`select r.*, a.status, a.home_tenant_id, a.home_project_id, c.login from ${S}.password_resets r join ${S}.actors a on a.id=r.actor_id join ${S}.credentials c on c.actor_id=r.actor_id where r.token_hash=$1`, [sha256(input.token)]))[0];
    if (row === undefined || row.used_at !== null || row.status !== 'active' || new Date(row.expires_at).getTime() <= at.getTime()) throw denied('The reset link is not valid or has expired');
    const m = (await sql.query<R>(`select * from ${S}.mfa where actor_id=$1 and confirmed_at is not null`, [row.actor_id]))[0];
    if (m !== undefined) {
      if (input.code === undefined && input.recoveryCode === undefined) throw new DomainError('invalid_mfa_required', 'Enter the one-time code from your authenticator app, or a recovery code');
      const attempt = await sql.tx((tx) => consume(tx, '-', row.actor_id as string, 'password_reset_second_factor', 5, 900, 1));
      if (!attempt.allowed) throw new DomainError('rate_limited', 'Too many failed attempts; try again later');
      if (!(await h.secondFactor(m, input))) throw denied('The code is not valid');
    }
    const hash = await hashPassword(newPassword, cfg.scryptN);
    await sql.tx(async (tx) => {
      const used = await tx.query(`update ${S}.password_resets set used_at=$2 where token_hash=$1 and used_at is null returning actor_id`, [sha256(input.token), at.toISOString()]);
      if (used.length === 0) throw denied('The reset link is not valid or has expired');
      await tx.query(`update ${S}.credentials set password_hash=$2, changed_at=$3 where actor_id=$1`, [row.actor_id, hash, at.toISOString()]);
      await tx.query(`delete from ${S}.password_resets where actor_id=$1 and used_at is null`, [row.actor_id]);
      await tx.query(`update ${S}.sessions set revoked_at=$2, revoked_by=$1, revoke_reason='password_reset' where actor_id=$1 and revoked_at is null`, [row.actor_id, at.toISOString()]);
      await tx.query(`delete from ${S}.auth_attempts where key=$1`, [sha256(`attempt:login:${row.login as string}`)]);
      const ctx = k.systemContext(row.home_tenant_id, row.home_project_id ?? 'main', row.actor_id, 'human', 'account_recovery');
      await appendAudit(tx, S, ctx, 'password_reset.completed', ref('actor', row.actor_id), {});
      await emitEvent(tx, S, ctx, 'session.revoked', ref('actor', row.actor_id), { reason: 'password_reset' });
    });
    k.clearRevocationCache();
    return { ok: true };
  }

  /** Housekeeping for maintenance(): expired reset tokens and stale rate-limit windows (the longest window is one day). */
  async function sweep(): Promise<void> {
    const at = clock();
    await sql.query(`delete from ${S}.password_resets where expires_at < $1`, [at.toISOString()]);
    await sql.query(`delete from ${S}.rate_limits where window_start < $1`, [new Date(at.getTime() - 2 * 86400 * 1000).toISOString()]);
  }

  return { whoCanAccess, revocationImpact, redact, consumeRateLimit, rateLimitStatus, createInvitation, listInvitations, revokeInvitation, acceptInvitation, requestPasswordReset, completePasswordReset, sweep };
}
