// Kernel: current-state loading, access decisions, signing keys, token minting and revocation checks.
import { randomUUID } from 'node:crypto';
import { DomainError, invariant } from '../contracts.ts';
import type { Context, Json } from '../contracts.ts';
import { appendAudit, createTokenVerifier, emitEvent, generateSigningKey, hasCapability, signAccessToken, uref, urefMatches } from '../service-kit.ts';
import type { ServiceContext, Sql, TokenVerifier } from '../service-kit.ts';
import { SCHEMA, ORG_WIDE } from './schema.ts';
import { Sealer } from './crypto.ts';
import { AGENT_DEFAULT_DENIED, EXACT_CAP, ID, actionOf, agentForbidden, covers, intersect, isSensitive, iso } from './core.ts';
import type { AccessDecision, ActorKind, DecisionStep, EngineDeps, IdentityClaims, IssuedToken, R } from './core.ts';

const S = SCHEMA;
export type ActorState = Readonly<{
  org: R | undefined; project: R | undefined; actor: R | undefined;
  memberships: readonly R[]; roleDefs: ReadonlyMap<string, R>; compartments: readonly string[]; minPv: bigint | null;
  roles: readonly string[]; roleCaps: readonly string[];
}>;
export type DecideInput = Readonly<{
  tenantId: string; projectId: string; actorId: string; actorKind?: ActorKind; purpose: string; capability: string;
  resource?: string | undefined; compartment?: string | undefined;
  token?: Readonly<{ caps: readonly string[]; cmp: readonly string[]; pv?: string | undefined; jti?: string | undefined }> | undefined;
}>;
export type MintInput = Readonly<{
  actorId: string; tenantId: string; projectId: string; purpose: string; ttlSeconds: number; kind?: ActorKind;
  requested?: readonly string[] | undefined; strict?: boolean; sessionId?: string; ceiling?: readonly string[] | undefined; compartments?: readonly string[] | undefined;
}>;

export function createKernel(deps: EngineDeps) {
  const sql = deps.sql;
  const cfg = deps.config ?? {};
  const clock = cfg.clock ?? (() => new Date());
  const issuer = cfg.issuer ?? 'e01-identity';
  const sealer = cfg.keyEncryptionKey === undefined || cfg.keyEncryptionKey === '' ? null : new Sealer(cfg.keyEncryptionKey);
  const revocationCacheMs = Math.min(Math.max(cfg.revocationCacheMs ?? 2000, 0), 5000);
  const maxTokenTtl = 3600;
  const requireSealer = (): Sealer => { if (sealer === null) throw new DomainError('unavailable', 'IDENTITY_KEY_ENCRYPTION_KEY is not configured; secrets cannot be sealed and tokens cannot be issued'); return sealer; };

  // ── context helpers ──
  const systemContext = (tenantId: string, projectId: string, actorId: string, kind: ActorKind, purpose: string): Context =>
    ({ tenantId, projectId, purpose, requestId: randomUUID(), now: clock().toISOString(), actor: { id: actorId, kind, roles: [] } });
  const ref = (kind: string, id: string): string => uref('E01', kind, id);
  async function record(tx: Sql, ctx: Context, action: string, subject: string, detail: Json, event?: string): Promise<void> {
    await appendAudit(tx, S, ctx, action, subject, detail);
    if (event !== undefined) await emitEvent(tx, S, ctx, event, subject, detail);
  }
  /** Bumps the organization's policy version; every role, membership, compartment, purpose or grant change calls this. */
  async function bump(tx: Sql, ctx: Context, cause: string, revokeActors: readonly string[] = []): Promise<string> {
    const row = (await tx.query<R>(`update ${S}.organizations set policy_version = policy_version + 1, updated_at = $2 where id = $1 returning policy_version::text as pv`, [ctx.tenantId, ctx.now]))[0];
    invariant(row !== undefined, 'not_found', 'Not found');
    const pv = row.pv as string;
    if (revokeActors.length > 0) {
      await tx.query(`insert into ${S}.actor_revocations (tenant_id, actor_id, min_policy_version, reason, at) select $1, a, $3::bigint, $4, $5 from unnest($2::text[]) a
        on conflict (tenant_id, actor_id) do update set min_policy_version = excluded.min_policy_version, reason = excluded.reason, at = excluded.at`, [ctx.tenantId, [...new Set(revokeActors)], pv, cause, ctx.now]);
      revocationCache.clear();
    }
    await emitEvent(tx, S, ctx, 'policy.changed', ref('organization', ctx.tenantId), { policyVersion: pv, cause, actors: [...new Set(revokeActors)].slice(0, 200) });
    return pv;
  }

  // ── current state ──
  async function loadState(q: Sql, tenantId: string, projectId: string, actorId: string, at: Date): Promise<ActorState> {
    // Sequential on purpose: `q` may be a single transaction connection.
    const queries: [string, unknown[]][] = [
      [`select *, policy_version::text as pv from ${S}.organizations where id=$1`, [tenantId]],
      [`select * from ${S}.projects where tenant_id=$1 and id=$2`, [tenantId, projectId]],
      [`select * from ${S}.actors where id=$1`, [actorId]],
      [`select * from ${S}.memberships where tenant_id=$1 and actor_id=$2 and project_id in ($3, '${ORG_WIDE}') and status='active' and (expires_at is null or expires_at > $4)`, [tenantId, actorId, projectId, at.toISOString()]],
      [`select * from ${S}.roles where tenant_id=$1 and not deleted`, [tenantId]],
      [`select compartment_id from ${S}.compartment_members where tenant_id=$1 and project_id=$2 and actor_id=$3 and (expires_at is null or expires_at > $4) order by compartment_id`, [tenantId, projectId, actorId, at.toISOString()]],
      [`select min_policy_version::text as min from ${S}.actor_revocations where tenant_id=$1 and actor_id=$2`, [tenantId, actorId]],
    ];
    const out: R[][] = [];
    for (const [textSql, params] of queries) out.push(await q.query<R>(textSql, params));
    const [org, project, actor, memberships, roleRows, cmp, rev] = out as [R[], R[], R[], R[], R[], R[], R[]];
    const roleDefs = new Map(roleRows.map((r) => [r.name as string, r]));
    const kind = actor[0]?.kind as string | undefined;
    const roles = [...new Set(memberships.flatMap((m) => m.roles as string[]))].filter((name) => { const def = roleDefs.get(name); return def !== undefined && kind !== undefined && (def.actor_kinds as string[]).includes(kind); }).sort();
    const roleCaps = [...new Set(roles.flatMap((name) => (roleDefs.get(name) as R).capabilities as string[]))].sort();
    return { org: org[0], project: project[0], actor: actor[0], memberships, roleDefs, compartments: cmp.map((c) => c.compartment_id as string), minPv: rev[0] === undefined ? null : BigInt(rev[0].min as string), roles, roleCaps };
  }
  async function purposeCaps(q: Sql, tenantId: string, purpose: string): Promise<string[] | null> {
    const row = (await q.query<R>(`select capabilities from ${S}.purposes where tenant_id=$1 and name=$2`, [tenantId, purpose]))[0];
    return row === undefined ? null : (row.capabilities as string[]);
  }
  const grantUsable = (g: R, at: Date): string | null => {
    if (g.revoked_at !== null) return 'revoked';
    if (new Date(g.not_before as string).getTime() > at.getTime()) return 'not yet valid';
    if (new Date(g.expires_at as string).getTime() <= at.getTime()) return 'expired';
    const b = g.bounds as R;
    if (typeof b.maxUses === 'number' && (g.uses as number) >= b.maxUses) return 'use limit reached';
    if (typeof b.maxAmount === 'number' && Number(g.amount_used) >= b.maxAmount) return 'amount ceiling reached';
    return null;
  };
  function grantCoversResource(g: R, resource: string | undefined): boolean {
    const allowed = [...(g.resource === null ? [] : [g.resource as string]), ...(Array.isArray((g.bounds as R).resources) ? (g.bounds as R).resources as string[] : [])];
    if (allowed.length === 0) return true;
    if (resource === undefined) return false;
    return allowed.some((a) => { if (a === resource) return true; try { return urefMatches(a, resource); } catch { return false; } });
  }
  /**
   * Agents never hold admin/grant/issue_token/events or secret-bearing actions. approve, publish and disclose_identity
   * are also withheld unless the organization's policy config lists the action in `agentGrantableActions`.
   */
  const agentBlocked = (org: R, capability: string): boolean => agentForbidden(capability)
    || (AGENT_DEFAULT_DENIED.includes(actionOf(capability)) && !(Array.isArray((org.policy_config as R).agentGrantableActions) && ((org.policy_config as R).agentGrantableActions as unknown[]).includes(actionOf(capability))));
  const activeGrants = (q: Sql, tenantId: string, projectId: string, actorId: string, purpose: string): Promise<R[]> =>
    q.query<R>(`select * from ${S}.grants where tenant_id=$1 and actor_id=$2 and project_id in ($3, '${ORG_WIDE}') and purpose=$4 and revoked_at is null order by created_at`, [tenantId, actorId, projectId, purpose]);

  /** The single access decision procedure. Never throws for a denial; storage failures propagate (callers fail closed). */
  async function decide(q: Sql, input: DecideInput): Promise<AccessDecision> {
    const at = clock();
    const trail: DecisionStep[] = [];
    let pv = '0';
    const base = { actorId: input.actorId, tenantId: input.tenantId, projectId: input.projectId, purpose: input.purpose, capability: input.capability, resource: input.resource ?? null };
    const deny = (reason: string, detail: string): AccessDecision => { trail.push({ rule: reason, outcome: 'fail', detail }); return { ...base, allowed: false, reason, policyVersion: pv, via: null, trail }; };
    const pass = (rule: string, detail: string): void => { trail.push({ rule, outcome: 'pass', detail }); };
    if (typeof input.capability !== 'string' || !EXACT_CAP.test(input.capability)) return deny('invalid_capability', 'An exact capability `engine:action` is required');
    for (const v of [input.tenantId, input.projectId, input.actorId]) if (typeof v !== 'string' || !ID.test(v)) return deny('invalid_context', 'Tenant, project and actor are required');
    if (typeof input.purpose !== 'string' || input.purpose === '') return deny('invalid_context', 'A purpose is required');
    const st = await loadState(q, input.tenantId, input.projectId, input.actorId, at);
    if (st.org === undefined || st.org.status !== 'active') return deny('organization_unavailable', 'Organization is unknown or suspended');
    pv = st.org.pv as string;
    if (st.project === undefined || st.project.status !== 'active') return deny('project_unavailable', 'Project is unknown or archived in this organization');
    pass('scope', `Organization ${input.tenantId} and project ${input.projectId} are active at policy version ${pv}`);
    if (st.actor === undefined || st.memberships.length === 0) return deny('no_membership', 'Actor is unknown or has no active membership in this organization and project');
    if (st.actor.status !== 'active') return deny('actor_disabled', 'Actor is disabled');
    if (input.actorKind !== undefined && input.actorKind !== st.actor.kind) return deny('actor_kind_mismatch', 'Presented actor kind does not match the stored identity');
    const kind = st.actor.kind as ActorKind;
    pass('membership', `Active membership with roles [${st.roles.join(', ')}]`);
    if (input.token !== undefined) {
      if (input.token.jti !== undefined && (await q.query(`select 1 from ${S}.token_revocations where tenant_id=$1 and jti=$2`, [input.tenantId, input.token.jti])).length > 0) return deny('token_revoked', 'The presented token was revoked');
      if (st.minPv !== null) {
        let tokenPv: bigint; try { tokenPv = BigInt(input.token.pv ?? ''); } catch { return deny('stale_policy_version', 'The presented token carries no policy version'); }
        if (input.token.pv === undefined || input.token.pv === '' || tokenPv < st.minPv) return deny('stale_policy_version', `Token policy version ${input.token.pv ?? ''} predates a change to this actor's access (minimum ${st.minPv})`);
      }
      if (!hasCapability({ capabilities: input.token.caps } as unknown as ServiceContext, input.capability) || !covers(input.token.caps, input.capability)) return deny('not_in_token', `The presented token does not carry ${input.capability} for purpose ${input.purpose}`);
      pass('token', 'The presented token carries the capability and is not revoked');
    }
    if (kind === 'agent' && agentBlocked(st.org, input.capability)) return deny('agent_forbidden', `Agents may not hold ${input.capability} in this organization`);
    const pcaps = await purposeCaps(q, input.tenantId, input.purpose);
    if (pcaps === null) return deny('unknown_purpose', `Purpose ${input.purpose} is not defined for this organization`);
    if (input.compartment !== undefined && input.compartment !== '') {
      if (!st.compartments.includes(input.compartment) || (input.token !== undefined && !input.token.cmp.includes(input.compartment))) return deny('compartment_denied', 'Actor is not a current member of the required compartment');
      pass('compartment', `Current member of compartment ${input.compartment}`);
    }
    let via: AccessDecision['via'] = null;
    const sensitive = isSensitive(input.capability);
    const byRole = st.roles.filter((name) => covers((st.roleDefs.get(name) as R).capabilities as string[], input.capability));
    if (byRole.length > 0 && covers(pcaps, input.capability) && !(kind === 'agent' && sensitive)) {
      via = { kind: 'role', roles: byRole };
      pass('role', `Granted by role${byRole.length > 1 ? 's' : ''} ${byRole.join(', ')} within purpose ${input.purpose}`);
    } else {
      if (byRole.length === 0) trail.push({ rule: 'role', outcome: 'info', detail: sensitive ? `No current role names ${input.capability} exactly (wildcards never grant sensitive actions)` : `No current role grants ${input.capability}` });
      else if (kind === 'agent' && sensitive) trail.push({ rule: 'role', outcome: 'info', detail: 'Agents hold sensitive actions only through an explicit grant' });
      else trail.push({ rule: 'purpose', outcome: 'info', detail: `Purpose ${input.purpose} does not include ${input.capability}` });
      const grants = (await activeGrants(q, input.tenantId, input.projectId, input.actorId, input.purpose)).filter((g) => g.capability === input.capability);
      for (const g of grants) {
        const problem = grantUsable(g, at) ?? (grantCoversResource(g, input.resource) ? null : 'resource is outside the grant');
        if (problem !== null) { trail.push({ rule: 'grant', outcome: 'info', detail: `Grant ${g.id} not applicable: ${problem}` }); continue; }
        via = { kind: 'grant', grantId: g.id as string, bounds: g.bounds as Json, expiresAt: iso(g.expires_at) };
        pass('grant', `Granted by purpose grant ${g.id} valid until ${iso(g.expires_at)}`);
        break;
      }
      if (via === null) return deny(sensitive ? 'sensitive_capability_not_granted' : 'capability_not_granted', `Neither a current role within purpose ${input.purpose} nor a valid grant allows ${input.capability}`);
    }
    return { ...base, allowed: true, reason: via.kind === 'role' ? 'role' : 'grant', policyVersion: pv, via, trail };
  }

  // ── signing keys ──
  let signing: { kid: string; privateKeyPem: string; loadedAt: number } | null = null;
  let publicCache: { keys: Record<string, string>; loadedAt: number; missAt: number } | null = null;
  async function loadPublicKeys(): Promise<Record<string, string>> {
    const rows = await sql.query<R>(`select kid, public_pem from ${S}.signing_keys where status='active' or (status='retired' and verify_until > $1) order by created_at`, [clock().toISOString()]);
    const keys: Record<string, string> = {};
    for (const r of rows) keys[r.kid as string] = r.public_pem as string;
    publicCache = { keys, loadedAt: Date.now(), missAt: publicCache?.missAt ?? 0 };
    return keys;
  }
  async function publicKeysFor(kid: string | null): Promise<Record<string, string>> {
    const c = publicCache;
    if (c !== null && Date.now() - c.loadedAt < 5000 && (kid === null || Object.hasOwn(c.keys, kid) || Date.now() - c.missAt < 1000)) return c.keys;
    const keys = await loadPublicKeys();
    if (kid !== null && !Object.hasOwn(keys, kid) && publicCache !== null) publicCache.missAt = Date.now();
    return keys;
  }
  /** Creates a new active key and retires the previous one; retired keys verify until every token they signed has expired. */
  async function rotateSigningKey(): Promise<{ kid: string; retired: string[] }> {
    const seal = requireSealer();
    const out = await sql.tx(async (tx) => {
      await tx.query('select pg_advisory_xact_lock(hashtext($1))', ['e01-signing-keys']);
      const at = clock();
      const key = generateSigningKey();
      const retired = await tx.query<R>(`update ${S}.signing_keys set status='retired', retired_at=$1, verify_until=$2 where status='active' returning kid`, [at.toISOString(), new Date(at.getTime() + (maxTokenTtl + 120) * 1000).toISOString()]);
      await tx.query(`insert into ${S}.signing_keys (kid, public_pem, private_sealed, status, created_at) values ($1,$2,$3,'active',$4)`, [key.kid, key.publicKeyPem, seal.seal(key.privateKeyPem, `signing-key:${key.kid}`), at.toISOString()]);
      const platform = (await tx.query<R>(`select value from ${S}.deployment where key='platform'`))[0];
      if (platform !== undefined) {
        const v = platform.value as R;
        await record(tx, systemContext(v.tenantId as string, v.projectId as string, 'system', 'service', 'key-rotation'), 'key.rotated', ref('signing_key', key.kid), { kid: key.kid, retired: retired.map((r) => r.kid as string) }, 'key.rotated');
      }
      return { kid: key.kid, retired: retired.map((r) => r.kid as string), pem: key.privateKeyPem };
    });
    signing = { kid: out.kid, privateKeyPem: out.pem, loadedAt: Date.now() };
    publicCache = null;
    return { kid: out.kid, retired: out.retired };
  }
  async function revokeSigningKey(kid: string): Promise<void> {
    const rows = await sql.query(`update ${S}.signing_keys set status='revoked', retired_at=coalesce(retired_at,$2), verify_until=null where kid=$1 returning kid`, [kid, clock().toISOString()]);
    invariant(rows.length > 0, 'not_found', 'Not found');
    signing = null; publicCache = null;
  }
  async function signingKey(): Promise<{ kid: string; privateKeyPem: string }> {
    const seal = requireSealer();
    if (signing !== null && Date.now() - signing.loadedAt < 30000) return signing;
    const row = (await sql.query<R>(`select kid, private_sealed from ${S}.signing_keys where status='active' order by created_at desc limit 1`))[0];
    if (row === undefined) { await rotateSigningKey(); return signing as unknown as { kid: string; privateKeyPem: string }; }
    signing = { kid: row.kid as string, privateKeyPem: seal.open(row.private_sealed as string, `signing-key:${row.kid}`), loadedAt: Date.now() };
    return signing;
  }

  // ── token minting ──
  /** Resolves the capabilities an actor may carry for one organization + project + purpose, from current state. */
  async function resolveCapabilities(q: Sql, st: ActorState, tenantId: string, projectId: string, purpose: string, ceiling?: readonly string[]): Promise<{ caps: string[]; grantIds: string[] }> {
    const pcaps = await purposeCaps(q, tenantId, purpose);
    if (pcaps === null) throw new DomainError('forbidden', 'Purpose is not defined for this organization');
    const kind = (st.actor as R).kind as ActorKind;
    let caps = intersect(st.roleCaps, pcaps);
    if (ceiling !== undefined) caps = intersect(caps, ceiling);
    if (kind === 'agent') caps = caps.filter((c) => !isSensitive(c));
    const at = clock();
    const grantIds: string[] = [];
    for (const g of await activeGrants(q, tenantId, projectId, (st.actor as R).id as string, purpose)) {
      if (grantUsable(g, at) !== null) continue;
      caps.push(g.capability as string); grantIds.push(g.id as string);
    }
    if (kind === 'agent') caps = caps.filter((c) => !agentBlocked(st.org as R, c));
    return { caps: [...new Set(caps)].sort(), grantIds };
  }
  async function mint(input: MintInput): Promise<IssuedToken> {
    invariant(ID.test(input.tenantId) && ID.test(input.projectId) && typeof input.purpose === 'string' && input.purpose.length > 0 && input.purpose.length <= 100, 'invalid_input', 'Organization, project and purpose are required');
    invariant(Number.isInteger(input.ttlSeconds) && input.ttlSeconds >= 30 && input.ttlSeconds <= maxTokenTtl, 'invalid_input', `Token lifetime must be 30–${maxTokenTtl} seconds`);
    const key = await signingKey();
    const at = clock();
    const st = await loadState(sql, input.tenantId, input.projectId, input.actorId, at);
    const no = (): never => { throw new DomainError('forbidden', 'No active access to this organization and project'); };
    if (st.org === undefined || st.org.status !== 'active' || st.project === undefined || st.project.status !== 'active') no();
    if (st.actor === undefined || st.actor.status !== 'active' || st.memberships.length === 0 || (input.kind !== undefined && st.actor.kind !== input.kind)) no();
    const resolved = await resolveCapabilities(sql, st, input.tenantId, input.projectId, input.purpose, input.ceiling);
    let caps = resolved.caps;
    if (input.requested !== undefined) {
      if (input.strict === true) {
        for (const r of input.requested) if (!covers(caps, r)) throw new DomainError('forbidden', `Capability ${r} is not available to this identity for purpose ${input.purpose}`);
        caps = [...new Set(input.requested)].sort();
      } else caps = intersect(caps, input.requested);
    }
    let cmp = [...st.compartments];
    if (input.compartments !== undefined) {
      for (const c of input.compartments) if (!cmp.includes(c)) throw new DomainError('forbidden', 'Requested compartment is not available to this identity');
      cmp = [...new Set(input.compartments)].sort();
    }
    const iat = Math.floor(at.getTime() / 1000);
    const org = st.org as R, actor = st.actor as R;
    const claims: IdentityClaims = {
      iss: issuer, sub: input.actorId, kind: actor.kind as ActorKind, tid: input.tenantId, pid: input.projectId, roles: [...st.roles], caps, cmp,
      purpose: input.purpose, pv: org.pv as string, iat, exp: iat + input.ttlSeconds, jti: randomUUID(), locale: org.default_locale as string,
      ...(input.sessionId === undefined ? {} : { sid: input.sessionId }),
    };
    return { token: signAccessToken(claims, key), tokenId: claims.jti, expiresAt: new Date(claims.exp * 1000).toISOString(), actorId: input.actorId, tenantId: input.tenantId, projectId: input.projectId, purpose: input.purpose, roles: claims.roles, capabilities: caps, compartments: cmp, policyVersion: claims.pv };
  }

  // ── revocation ──
  const revocationCache = new Map<string, { at: number; revoked: boolean }>();
  /**
   * True when a verified token must no longer be honoured: its jti, session, actor or organization was revoked or
   * disabled, or the actor's access changed after the token's policy version. Answers are cached per jti for
   * `revocationCacheMs` (default 2 s, maximum 5 s); storage failures throw, which the kit verifier treats as denial.
   */
  async function isRevoked(claims: IdentityClaims): Promise<boolean> {
    if (typeof claims.jti !== 'string' || claims.jti === '') return true;
    const hit = revocationCache.get(claims.jti);
    if (hit !== undefined && Date.now() - hit.at < revocationCacheMs) return hit.revoked;
    const sid = typeof claims.sid === 'string' ? claims.sid : null;
    const row = (await sql.query<R>(`select
        exists(select 1 from ${S}.token_revocations where tenant_id=$1 and jti=$2) as jti_revoked,
        (select status from ${S}.organizations where id=$1) as org_status,
        (select status from ${S}.actors where id=$3) as actor_status,
        (select kind from ${S}.actors where id=$3) as actor_kind,
        (select min_policy_version::text from ${S}.actor_revocations where tenant_id=$1 and actor_id=$3) as min_pv,
        (select case when revoked_at is null and expires_at > $5 and actor_id = $3 then 'ok' else 'ended' end from ${S}.sessions where id=$4) as session_state`,
      [claims.tid, claims.jti, claims.sub, sid, clock().toISOString()]))[0] as R;
    let revoked = row.jti_revoked === true || row.org_status !== 'active' || row.actor_status !== 'active' || row.actor_kind !== claims.kind || (sid !== null && row.session_state !== 'ok');
    if (!revoked && row.min_pv !== null) { try { revoked = BigInt(claims.pv) < BigInt(row.min_pv as string); } catch { revoked = true; } }
    if (revocationCache.size > 20000) revocationCache.clear();
    revocationCache.set(claims.jti, { at: Date.now(), revoked });
    return revoked;
  }
  function verifier(): TokenVerifier {
    return async (token, request) => {
      let kid: string | null = null;
      try { const h = JSON.parse(Buffer.from(String(token).split('.')[0] ?? '', 'base64url').toString('utf8')) as { kid?: unknown }; if (typeof h.kid === 'string') kid = h.kid; } catch { /* the kit verifier rejects it */ }
      let keys: Record<string, string>;
      try { keys = await publicKeysFor(kid); } catch { throw new DomainError('unauthenticated', 'Invalid or expired credentials'); }
      return createTokenVerifier({ publicKeys: keys, issuer, isRevoked: isRevoked as (c: IdentityClaims) => Promise<boolean> })(token, request);
    };
  }

  return { sql, cfg, clock, issuer, sealer, requireSealer, systemContext, ref, record, bump, loadState, purposeCaps, grantUsable, grantCoversResource, agentBlocked, decide, loadPublicKeys, rotateSigningKey, revokeSigningKey, signingKey, resolveCapabilities, mint, isRevoked, verifier, clearRevocationCache: () => revocationCache.clear(), maxTokenTtl };
}
export type Kernel = ReturnType<typeof createKernel>;
