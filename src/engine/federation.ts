// Federation: external-subject ↔ internal-actor mappings, OIDC sign-in and the intake service adapter.
import { randomUUID } from 'node:crypto';
import { DomainError, invariant } from '../contracts.ts';
import type { ServiceContext, Sql } from '../service-kit.ts';
import { createHumanFederationProvider } from '../human-federation.ts';
import { verifyIntakeService } from '../intake-service-adapter.ts';
import type { IntakeServiceMapping } from '../intake-service-adapter.ts';
import { SCHEMA } from './schema.ts';
import { randomToken, sha256 } from './crypto.ts';
import { ID, covers, denied, iso, isoOrNull, need, text, validId } from './core.ts';
import type { EnginePorts, IssuedToken, R, SessionInfo } from './core.ts';
import type { Kernel } from './kernel.ts';
import { authorizationUrl, discover, pkce, redeem } from './oidc.ts';
import type { OidcClient, OidcTransport } from './oidc.ts';

const S = SCHEMA;
export type ActorMapping = Readonly<{ id: string; provider: string; issuer: string; subject: string; audience: string; actorId: string; enabled: boolean; createdAt: string }>;
export type OidcProviderInfo = Readonly<{ id: string; issuer: string; clientId: string; hasClientSecret: boolean; scopes: readonly string[]; redirectUris: readonly string[]; discoveryUrl: string | null; enabled: boolean; maxSessionAgeSeconds: number }>;
export type IntakeConnection = Readonly<{ connectionId: string; projectId: string; origin: string; actorId: string; localRoles: readonly string[]; requiredScopes: readonly string[]; supportedVersions: readonly string[]; epoch: number; enabled: boolean; verifiedAt: string | null; upstreamVersion: string | null; lastError: string | null }>;
type Helpers = Readonly<{
  needNow: (ctx: ServiceContext, capability: string, q?: Sql) => Promise<void>;
  requireOwner: (q: Sql, ctx: ServiceContext, what: string) => Promise<void>;
  memberActor: (q: Sql, tenantId: string, actorId: string) => Promise<R | undefined>;
  issuerGate: (ctx: ServiceContext, projectId: string | undefined) => Promise<string>;
  createSession: (actorId: string, method: string, boundTenantId: string | null) => Promise<SessionInfo>;
  createNonHuman: (ctx: ServiceContext, kind: 'agent' | 'service', input: { name: string; description?: string; projectId?: string; roles?: readonly string[] }, tx: Sql, secretHash: string | null) => Promise<R>;
}>;
const toMapping = (r: R): ActorMapping => ({ id: r.id, provider: r.provider, issuer: r.issuer, subject: r.subject, audience: r.audience, actorId: r.actor_id, enabled: r.enabled, createdAt: iso(r.created_at) });
const toProvider = (r: R): OidcProviderInfo => ({ id: r.id, issuer: r.issuer, clientId: r.client_id, hasClientSecret: r.client_secret_sealed !== null, scopes: r.scopes, redirectUris: r.redirect_uris, discoveryUrl: r.discovery_url ?? null, enabled: r.enabled, maxSessionAgeSeconds: r.max_session_age_seconds });
const toConnection = (r: R): IntakeConnection => ({ connectionId: r.connection_id, projectId: r.project_id, origin: r.origin, actorId: r.actor_id, localRoles: r.local_roles, requiredScopes: r.required_scopes, supportedVersions: r.supported_versions, epoch: r.epoch, enabled: r.enabled, verifiedAt: isoOrNull(r.verified_at), upstreamVersion: r.upstream_version ?? null, lastError: r.last_error ?? null });
function httpsUrl(value: unknown, label: string): string {
  let url: URL | null = null;
  try { url = new URL(String(value)); } catch { /* reported below */ }
  invariant(typeof value === 'string' && value.length <= 512 && url !== null && url.protocol === 'https:' && !url.username && !url.password && !url.hash && !url.search, 'invalid_input', `${label} must be an HTTPS URL without credentials, query or fragment`);
  return value;
}

export function createFederation(k: Kernel, ports: EnginePorts, h: Helpers) {
  const { sql, clock, ref, record } = k;
  const transport = (): OidcTransport => ({ fetch: ports.oidcFetch ?? fetch, allowLoopbackHttp: k.cfg.oidcAllowInsecureLoopback === true });

  // ── actor mappings ──
  /**
   * Binds an external subject (OIDC `iss`+`sub`+client, an intake user or connection, …) to an existing internal
   * actor that is a member of this organization, so external identities federate instead of duplicating actors.
   */
  async function mapExternalActor(ctx: ServiceContext, input: { provider: string; issuer: string; subject: string; audience?: string; actorId: string }, tx0?: Sql): Promise<ActorMapping> {
    if (tx0 === undefined) await h.needNow(ctx, 'identity:admin');
    const run = async (tx: Sql): Promise<ActorMapping> => {
      invariant(typeof input.provider === 'string' && /^[a-z][a-z0-9_]{1,30}$/.test(input.provider), 'invalid_input', 'Invalid provider');
      const actor = await h.memberActor(tx, ctx.tenantId, input.actorId);
      const member = await tx.query<R>(`select roles from ${S}.memberships where tenant_id=$1 and actor_id=$2 and status='active'`, [ctx.tenantId, input.actorId]);
      invariant(actor !== undefined && member.length > 0, 'not_found', 'Not found');
      if (member.some((m) => (m.roles as string[]).some((r) => r === 'owner' || r === 'admin'))) await h.requireOwner(tx, ctx, 'federate an administrator identity');
      const rows = await tx.query<R>(`insert into ${S}.actor_mappings (id, tenant_id, provider, issuer, subject, audience, actor_id, created_at, created_by) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        on conflict (tenant_id, provider, issuer, subject, audience) do nothing returning *`, [randomUUID(), ctx.tenantId, input.provider, text(input.issuer, 'issuer', 512), text(input.subject, 'subject', 255), input.audience === undefined ? '' : text(input.audience, 'audience', 255), input.actorId, ctx.now, ctx.actor.id]);
      invariant(rows[0] !== undefined, 'conflict', 'This external subject is already mapped');
      await record(tx, ctx, 'mapping.created', ref('actor', input.actorId), { mappingId: rows[0].id as string, provider: input.provider, issuer: input.issuer }, 'mapping.changed');
      return toMapping(rows[0]);
    };
    return tx0 === undefined ? sql.tx(run) : run(tx0);
  }
  async function listActorMappings(ctx: ServiceContext, options: { actorId?: string; provider?: string } = {}): Promise<ActorMapping[]> {
    need(ctx, 'identity:admin');
    return (await sql.query<R>(`select * from ${S}.actor_mappings where tenant_id=$1 and ($2::text is null or actor_id=$2) and ($3::text is null or provider=$3) order by created_at`, [ctx.tenantId, options.actorId ?? null, options.provider ?? null])).map(toMapping);
  }
  async function removeActorMapping(ctx: ServiceContext, mappingId: string): Promise<void> {
    await h.needNow(ctx, 'identity:admin');
    await sql.tx(async (tx) => {
      const rows = await tx.query<R>(`delete from ${S}.actor_mappings where tenant_id=$1 and id=$2 returning *`, [ctx.tenantId, mappingId]);
      invariant(rows[0] !== undefined, 'not_found', 'Not found');
      // Sessions obtained through this organization's federation for the actor end with the mapping.
      await tx.query(`update ${S}.sessions set revoked_at=$3, revoked_by=$4, revoke_reason='mapping removed' where actor_id=$1 and bound_tenant_id=$2 and revoked_at is null`, [rows[0].actor_id, ctx.tenantId, ctx.now, ctx.actor.id]);
      await record(tx, ctx, 'mapping.removed', ref('actor', rows[0].actor_id as string), { mappingId, provider: rows[0].provider as string }, 'mapping.changed');
    });
    k.clearRevocationCache();
  }
  /** Resolves an external subject to the internal actor id, or null. Other engines use this instead of minting identities. */
  async function resolveExternalActor(ctx: ServiceContext, input: { provider: string; issuer: string; subject: string; audience?: string }): Promise<{ actorId: string; kind: string; status: string } | null> {
    need(ctx, 'identity:read');
    const row = (await sql.query<R>(`select a.id, a.kind, a.status from ${S}.actor_mappings m join ${S}.actors a on a.id=m.actor_id where m.tenant_id=$1 and m.provider=$2 and m.issuer=$3 and m.subject=$4 and m.audience=$5 and m.enabled`, [ctx.tenantId, input.provider, input.issuer, input.subject, input.audience ?? '']))[0];
    return row === undefined ? null : { actorId: row.id, kind: row.kind, status: row.status };
  }

  // ── OIDC ──
  async function configureOidcProvider(ctx: ServiceContext, input: { id: string; issuer: string; clientId: string; clientSecret?: string | null; scopes?: readonly string[]; redirectUris: readonly string[]; discoveryUrl?: string | null; enabled?: boolean; maxSessionAgeSeconds?: number }): Promise<OidcProviderInfo> {
    await h.needNow(ctx, 'identity:admin');
    const issuer = httpsUrl(input.issuer, 'issuer');
    invariant(Array.isArray(input.redirectUris) && input.redirectUris.length > 0 && input.redirectUris.length <= 10, 'invalid_input', 'At least one redirect URI is required');
    const loopbackOk = k.cfg.oidcAllowInsecureLoopback === true;
    const redirectUris = input.redirectUris.map((u) => { const url = new URL(String(u)); invariant(url.protocol === 'https:' || (loopbackOk && ['127.0.0.1', 'localhost'].includes(url.hostname)), 'invalid_input', 'Redirect URIs must use HTTPS'); invariant(!url.hash, 'invalid_input', 'Redirect URIs cannot carry a fragment'); return String(u); });
    const scopes = (input.scopes ?? ['openid']).map((s) => { invariant(typeof s === 'string' && /^[\x21\x23-\x5b\x5d-\x7e]{1,64}$/.test(s), 'invalid_input', 'Invalid scope'); return s; });
    const age = input.maxSessionAgeSeconds ?? 600;
    invariant(Number.isInteger(age) && age >= 1 && age <= 86400, 'invalid_input', 'maxSessionAgeSeconds must be 1–86400');
    if (input.discoveryUrl !== undefined && input.discoveryUrl !== null) { const u = new URL(input.discoveryUrl); invariant(u.protocol === 'https:' || (loopbackOk && ['127.0.0.1', 'localhost'].includes(u.hostname)), 'invalid_input', 'discoveryUrl must use HTTPS'); }
    return sql.tx(async (tx) => {
      await h.requireOwner(tx, ctx, 'configure sign-in providers');
      const id = validId(input.id, 'id');
      const cur = (await tx.query<R>(`select client_secret_sealed from ${S}.oidc_providers where tenant_id=$1 and id=$2`, [ctx.tenantId, id]))[0];
      const sealed = input.clientSecret === undefined ? (cur?.client_secret_sealed ?? null) : input.clientSecret === null ? null : k.requireSealer().seal(text(input.clientSecret, 'clientSecret', 1000), `oidc:${ctx.tenantId}:${id}`);
      const rows = await tx.query<R>(`insert into ${S}.oidc_providers (tenant_id, id, issuer, client_id, client_secret_sealed, scopes, redirect_uris, discovery_url, enabled, max_session_age_seconds, updated_at, updated_by) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        on conflict (tenant_id, id) do update set issuer=excluded.issuer, client_id=excluded.client_id, client_secret_sealed=excluded.client_secret_sealed, scopes=excluded.scopes, redirect_uris=excluded.redirect_uris, discovery_url=excluded.discovery_url, enabled=excluded.enabled, max_session_age_seconds=excluded.max_session_age_seconds, updated_at=excluded.updated_at, updated_by=excluded.updated_by returning *`,
        [ctx.tenantId, id, issuer, text(input.clientId, 'clientId', 255), sealed, scopes, redirectUris, input.discoveryUrl ?? null, input.enabled !== false, age, ctx.now, ctx.actor.id]);
      await record(tx, ctx, 'federation.configured', ref('oidc_provider', id), { issuer, enabled: input.enabled !== false }, 'federation.changed');
      return toProvider(rows[0] as R);
    });
  }
  async function listOidcProviders(ctx: ServiceContext): Promise<OidcProviderInfo[]> {
    need(ctx, 'identity:admin');
    return (await sql.query<R>(`select * from ${S}.oidc_providers where tenant_id=$1 order by id`, [ctx.tenantId])).map(toProvider);
  }
  async function loadProvider(tenantId: string, providerId: string): Promise<{ row: R; client: OidcClient }> {
    const row = (await sql.query<R>(`select p.* from ${S}.oidc_providers p join ${S}.organizations o on o.id=p.tenant_id where p.tenant_id=$1 and p.id=$2 and p.enabled and o.status='active'`, [tenantId, providerId]))[0];
    if (row === undefined) throw new DomainError('not_found', 'Not found');
    const secret = row.client_secret_sealed === null ? null : k.requireSealer().open(row.client_secret_sealed, `oidc:${tenantId}:${providerId}`);
    return { row, client: { issuer: row.issuer, clientId: row.client_id, clientSecret: secret, scopes: row.scopes, discoveryUrl: row.discovery_url ?? null } };
  }
  /** Begins authorization-code + PKCE sign-in. The caller redirects the browser to `authorizationUrl` and keeps `state`. */
  async function startOidcLogin(input: { tenantId: string; providerId: string; redirectUri: string }): Promise<{ authorizationUrl: string; state: string; expiresAt: string }> {
    invariant(input !== null && typeof input === 'object' && typeof input.tenantId === 'string' && typeof input.providerId === 'string' && typeof input.redirectUri === 'string', 'invalid_input', 'Organization, provider and redirect URI are required');
    const { row, client } = await loadProvider(input.tenantId, input.providerId);
    invariant((row.redirect_uris as string[]).includes(input.redirectUri), 'invalid_input', 'Redirect URI is not registered for this provider');
    const meta = await discover(client, transport());
    const state = randomToken(32), nonce = randomToken(24), proof = pkce(), at = clock();
    const expires = new Date(at.getTime() + 600000).toISOString();
    await sql.query(`insert into ${S}.oidc_states (state_hash, tenant_id, provider_id, verifier_sealed, nonce, redirect_uri, created_at, expires_at) values ($1,$2,$3,$4,$5,$6,$7,$8)`, [sha256(state), input.tenantId, input.providerId, k.requireSealer().seal(proof.verifier, 'oidc-state'), nonce, input.redirectUri, at.toISOString(), expires]);
    return { authorizationUrl: authorizationUrl(meta, client, { state, nonce, challenge: proof.challenge, redirectUri: input.redirectUri }), state, expiresAt: expires };
  }
  /**
   * Completes sign-in: redeems the code, verifies the id token against the issuer's JWKS, then maps issuer+subject+client
   * to a local actor through this organization's actor mappings (no automatic provisioning). The resulting session is
   * bound to the provider's organization and cannot obtain tokens for any other.
   */
  async function completeOidcLogin(input: { state: string; code: string }): Promise<SessionInfo> {
    invariant(input !== null && typeof input === 'object' && typeof input.state === 'string' && typeof input.code === 'string' && input.state.length <= 200 && input.code.length > 0 && input.code.length <= 4096, 'invalid_input', 'State and code are required');
    const at = clock();
    // The state is single-use: it is consumed before any call to the provider.
    const st = (await sql.query<R>(`update ${S}.oidc_states set consumed_at=$2 where state_hash=$1 and consumed_at is null and expires_at > $2 returning *`, [sha256(input.state), at.toISOString()]))[0];
    if (st === undefined) throw denied('Federated sign-in was not accepted');
    const { row, client } = await loadProvider(st.tenant_id, st.provider_id);
    const meta = await discover(client, transport());
    const identity = await redeem(meta, client, transport(), { code: input.code, verifier: k.requireSealer().open(st.verifier_sealed, 'oidc-state'), redirectUri: st.redirect_uri, nonce: st.nonce, now: at });
    const mappings = await sql.query<R>(`select m.* from ${S}.actor_mappings m join ${S}.actors a on a.id=m.actor_id where m.tenant_id=$1 and m.provider='oidc' and m.issuer=$2 and m.subject=$3 and m.audience in ($4, '') and a.kind='human' and a.status='active'
      and exists(select 1 from ${S}.memberships ms where ms.tenant_id=m.tenant_id and ms.actor_id=m.actor_id and ms.status='active')`, [st.tenant_id, identity.issuer, identity.subject, identity.audience]);
    if (mappings.length === 0) throw denied('Federated sign-in was not accepted');
    // The existing federation boundary performs the final claim-window and exact issuer/subject/audience mapping checks.
    const canonicalIssuer = new URL(identity.issuer).href;
    let mapped: { actorId: string } | null;
    try {
      const provider = createHumanFederationProvider(
        { verify: async () => ({ issuer: canonicalIssuer, subject: identity.subject, audience: identity.audience, authenticatedAt: identity.authenticatedAt.toISOString(), expiresAt: identity.expiresAt.toISOString(), requestId: randomUUID(), csrfToken: randomToken(32) }) },
        { mappings: mappings.map((m) => ({ issuer: canonicalIssuer, subject: m.subject as string, audience: identity.audience, actorId: m.actor_id as string, enabled: m.enabled as boolean })).slice(0, 1), maxSessionAgeSeconds: row.max_session_age_seconds },
        () => at.toISOString());
      mapped = await provider.authenticate({ url: st.redirect_uri, method: 'GET', headers: new Headers() }, AbortSignal.timeout(5000));
    } catch { throw denied('Federated sign-in was not accepted'); }
    if (mapped === null) throw denied('Federated sign-in was not accepted');
    const session = await h.createSession(mapped.actorId, `oidc:${st.provider_id}`, st.tenant_id);
    await sql.tx((tx) => record(tx, k.systemContext(st.tenant_id, '*', mapped.actorId, 'human', 'sign-in'), 'session.federated', ref('actor', mapped.actorId), { provider: st.provider_id as string, sessionId: session.sessionId }));
    return session;
  }

  // ── intake service adapter ──
  /**
   * Registers a managed connection to the intake engine. The connection is represented by one service identity
   * (created here, without any secret) and an actor mapping `intake / <origin> / <connectionId>`, so intake's identity
   * boundary federates into this directory. Intake users are federated the same way with `mapExternalActor`.
   */
  async function registerIntakeConnection(ctx: ServiceContext, input: { connectionId: string; origin: string; credentialFingerprint: string; requiredScopes: readonly string[]; supportedVersions: readonly string[]; localRoles?: readonly ('viewer' | 'researcher' | 'operator')[]; roles?: readonly string[]; projectId?: string }): Promise<IntakeConnection> {
    await h.needNow(ctx, 'identity:admin');
    const origin = httpsUrl(input.origin, 'origin');
    invariant(new URL(origin).pathname === '/' && /^[a-f0-9]{64}$/.test(String(input.credentialFingerprint)), 'invalid_input', 'An HTTPS origin and a SHA-256 credential fingerprint are required');
    const strings = (v: unknown, n: number): v is string[] => Array.isArray(v) && v.length <= n && v.every((s) => typeof s === 'string' && s.length > 0 && s.length <= 128);
    invariant(strings(input.requiredScopes, 200) && strings(input.supportedVersions, 32) && input.supportedVersions.length > 0, 'invalid_input', 'Required scopes and supported versions are required');
    const localRoles = [...new Set(input.localRoles ?? ['viewer'])];
    invariant(localRoles.length > 0 && localRoles.every((r) => ['viewer', 'researcher', 'operator'].includes(r)), 'invalid_input', 'Invalid local roles');
    const connectionId = validId(input.connectionId, 'connectionId');
    return sql.tx(async (tx) => {
      invariant((await tx.query(`select 1 from ${S}.intake_connections where tenant_id=$1 and connection_id=$2`, [ctx.tenantId, connectionId])).length === 0, 'conflict', 'Connection already registered');
      const actor = await h.createNonHuman(ctx, 'service', { name: `Intake connection ${connectionId}`, description: `Federated intake service at ${origin}`, roles: input.roles ?? ['service_connector'], ...(input.projectId === undefined ? {} : { projectId: input.projectId }) }, tx, null);
      await mapExternalActor(ctx, { provider: 'intake', issuer: origin, subject: connectionId, actorId: actor.id }, tx);
      const rows = await tx.query<R>(`insert into ${S}.intake_connections (tenant_id, project_id, connection_id, origin, credential_fingerprint, actor_id, local_roles, required_scopes, supported_versions, updated_at, updated_by) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) returning *`,
        [ctx.tenantId, actor.home_project_id ?? ctx.projectId, connectionId, origin, input.credentialFingerprint, actor.id, localRoles, [...input.requiredScopes], [...input.supportedVersions], ctx.now, ctx.actor.id]);
      await record(tx, ctx, 'federation.intake_registered', ref('actor', actor.id), { connectionId, origin }, 'federation.changed');
      return toConnection(rows[0] as R);
    });
  }
  async function listIntakeConnections(ctx: ServiceContext): Promise<IntakeConnection[]> {
    need(ctx, 'identity:admin');
    return (await sql.query<R>(`select * from ${S}.intake_connections where tenant_id=$1 order by connection_id`, [ctx.tenantId])).map(toConnection);
  }
  /**
   * Verifies the connection against the live intake service with the existing adapter (pinned credential fingerprint,
   * capability contract, required scopes). Without the host's credential port the result is an explicit `unavailable`.
   */
  async function verifyIntakeConnection(ctx: ServiceContext, connectionId: string): Promise<{ status: 'verified' | 'failed' | 'unavailable'; reason: string; connection: IntakeConnection }> {
    if (!covers(ctx.capabilities, 'identity:issue_token')) await h.needNow(ctx, 'identity:admin'); else await h.needNow(ctx, 'identity:issue_token');
    const row = (await sql.query<R>(`select * from ${S}.intake_connections where tenant_id=$1 and connection_id=$2`, [ctx.tenantId, connectionId]))[0];
    invariant(row !== undefined, 'not_found', 'Not found');
    const save = async (verified: { version: string; digest: string } | null, error: string | null): Promise<IntakeConnection> => toConnection((await sql.query<R>(`update ${S}.intake_connections set verified_at=$3, upstream_version=coalesce($4, upstream_version), upstream_scope_digest=coalesce($5, upstream_scope_digest), last_error=$6, updated_at=$7 where tenant_id=$1 and connection_id=$2 returning *`,
      [ctx.tenantId, connectionId, verified === null ? null : clock().toISOString(), verified?.version ?? null, verified?.digest ?? null, error, clock().toISOString()]))[0] as R);
    if (ports.intakeCredentials === undefined) return { status: 'unavailable', reason: 'No intake credential port is configured on this host', connection: await save(null, 'unavailable: credential port not configured') };
    const mapping: IntakeServiceMapping = { tenantId: row.tenant_id, projectId: row.project_id, connectionId, origin: row.origin, credentialFingerprint: row.credential_fingerprint, actorId: row.actor_id, localRoles: row.local_roles, requiredScopes: row.required_scopes, supportedVersions: row.supported_versions, epoch: row.epoch, enabled: row.enabled };
    try {
      const verified = await verifyIntakeService(mapping, ports.intakeCredentials, clock().toISOString(), ports.intakeTransport ?? fetch);
      invariant(verified.actor.id === row.actor_id && verified.tenantId === ctx.tenantId, 'verification_unavailable', 'Verified identity does not match the mapping');
      const connection = await save({ version: verified.upstreamVersion, digest: verified.upstreamScopeDigest }, null);
      await sql.tx((tx) => record(tx, ctx, 'federation.intake_verified', ref('actor', row.actor_id as string), { connectionId, upstreamVersion: verified.upstreamVersion }));
      return { status: 'verified', reason: 'verified', connection };
    } catch (error) {
      const code = error instanceof DomainError ? error.code : 'verification_unavailable';
      return { status: ['verification_unavailable', 'verification_timeout', 'verification_cancelled'].includes(code) ? 'unavailable' : 'failed', reason: code, connection: await save(null, code) };
    }
  }
  /** Token for the connection's mapped service identity; only after a successful verification within the last 15 minutes. */
  async function issueIntakeServiceToken(ctx: ServiceContext, input: { connectionId: string; purpose: string; ttlSeconds?: number }): Promise<IssuedToken> {
    const row = (await sql.query<R>(`select * from ${S}.intake_connections where tenant_id=$1 and connection_id=$2 and enabled`, [ctx.tenantId, String(input?.connectionId)]))[0];
    await h.issuerGate(ctx, row?.project_id ?? ctx.projectId);
    invariant(row !== undefined && ID.test(row.actor_id), 'not_found', 'Not found');
    invariant(row.verified_at !== null && clock().getTime() - new Date(row.verified_at).getTime() <= 900000, 'forbidden', 'The intake connection has not been verified recently');
    return k.mint({ actorId: row.actor_id, tenantId: ctx.tenantId, projectId: row.project_id, purpose: input.purpose, ttlSeconds: input.ttlSeconds ?? 300, kind: 'service' });
  }

  return { mapExternalActor: (ctx: ServiceContext, input: Parameters<typeof mapExternalActor>[1]) => mapExternalActor(ctx, input), listActorMappings, removeActorMapping, resolveExternalActor, configureOidcProvider, listOidcProviders, startOidcLogin, completeOidcLogin, registerIntakeConnection, listIntakeConnections, verifyIntakeConnection, issueIntakeServiceToken };
}
