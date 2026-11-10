# E01 Identity, Authorization and Policy — engine API

Service layer of this repository (`src/engine/`). Kit: `src/service-kit.ts` version 1.0.1,
sha256 `95475a907267ba1fdd54b557aabe5645c37add9788a5b2d0854d9accfd5d8ea5` (this repository is the kit's source of truth).
Schema `e01_identity`. Capability prefix `identity`. Depends on no other engine.

Status words used below: **implemented** (code exists), **tested** (exercised by `tests/engine*.test.ts` on real
PostgreSQL 16 and real local sockets), **not verified** (no live third party was contacted). Nothing here has had an
independent security review.

## 1. Entry points

```ts
import { createEngine, migrate, routes, manifest, SCHEMA, migrations, DEFAULT_ROLES, DEFAULT_PURPOSES, ORG_WIDE } from '@accountability/identity-policy/engine';
import { start, configFromEnv } from '@accountability/identity-policy/serve';

await migrate(sql);                                       // runMigrations(sql, 'e01_identity', migrations)
const engine = createEngine({ sql, ports?, config? });    // IdentityEngine: StandardEngine & AuthorizationPort & the methods below
const handler = createHttpHandler({ name: 'E01', version: manifest.version, routes: routes(engine), verify: engine.verifier() });
```

`config` (`EngineConfig`, all optional):

| Field | Default | Meaning |
|---|---|---|
| `issuer` | `e01-identity` | `iss` of issued tokens |
| `keyEncryptionKey` | none | ≥ 32 characters. Seals signing keys, OIDC client secrets and PKCE verifiers (AES-256-GCM, HKDF-SHA256). Without it every token issuance and OIDC call throws `unavailable`; verification and reads still work |
| `accessTokenTtlSeconds` / `serviceTokenTtlSeconds` | 600 / 900 | Hard range for any token: 30–3600 s |
| `agentTokenMaxTtlSeconds` | 900 | Upper bound for agent tokens (default lifetime 600 s) |
| `sessionTtlSeconds` / `sessionIdleSeconds` | 43200 / 7200 | Absolute and idle session lifetime |
| `revocationCacheMs` | 2000 | Per-token cache of revocation answers, clamped to 0–5000 |
| `scryptN` | 32768 | scrypt cost (r = 8, p = 1), stored with each hash |
| `passwordMinLength` | 12 | |
| `lockout` | `{ maxFailures: 5, baseLockSeconds: 30, maxLockSeconds: 900, windowSeconds: 900 }` | Exponential lock after repeated failures |
| `bootstrapToken` | none | When set, bootstrap requires it. The HTTP bootstrap route refuses without it |
| `allowOrganizationCreation` | true | `false` disables `createOrganization` |
| `maxGrantSeconds` / `maxAgentGrantSeconds` | 30 days / 24 h | Longest grant |
| `oidcAllowInsecureLoopback` | false | Tests only: OIDC endpoints and redirect URIs on loopback HTTP |
| `clock` | `() => new Date()` | |

`ports` (`EnginePorts`, all optional): `intakeCredentials(connectionId, signal) => Promise<string>` (host secret store
for the managed intake credential; absent ⇒ `verifyIntakeConnection` returns `unavailable`), `intakeTransport`
(`CapabilityTransport`, default `fetch`), `oidcFetch` (default `fetch`). No kit port from another engine is needed.

### Standalone server

`npm run serve` (`node src/engine/serve.ts`). Environment:

| Variable | Required | Meaning |
|---|---|---|
| `DATABASE_URL` | yes | PostgreSQL; migrations run at start |
| `PORT`, `HOST` | no | Default `8080`, `127.0.0.1` |
| `IDENTITY_KEY_ENCRYPTION_KEY` | for issuing tokens | see `keyEncryptionKey` |
| `IDENTITY_BOOTSTRAP_TOKEN` | for HTTP bootstrap | see `bootstrapToken` |
| `IDENTITY_ISSUER`, `IDENTITY_ACCESS_TOKEN_TTL_SECONDS`, `IDENTITY_SESSION_TTL_SECONDS`, `IDENTITY_SESSION_IDLE_SECONDS`, `IDENTITY_REVOCATION_CACHE_MS` | no | as config |
| `IDENTITY_KEY_ROTATION_DAYS` | no | Default 30: maintenance (every 5 minutes) rotates an older active signing key |
| `IDENTITY_ALLOW_ORGANIZATION_CREATION=false`, `IDENTITY_OIDC_ALLOW_INSECURE_LOOPBACK=true` | no | as config |
| `DATABASE_POOL_MAX` | no | Default 10 |

This engine does not read `IDENTITY_PUBLIC_KEYS` / `IDENTITY_JWKS_FILE`: it is where those values come from
(`GET /v1/keys`, field `keys` = map kid → SPKI PEM, exactly the `IDENTITY_PUBLIC_KEYS` format). It uses no object
store and runs no kit jobs; `start()` runs `host.maintenance` on a timer instead. The standalone server has no
intake credential port (intake verification reports `unavailable`); an embedding host supplies one.

## 2. Model

- **Organization** = tenant (`tenantId`). Carries `branding`, `defaultLocale`, `languages`, `jurisdiction`,
  `policyConfig` (opaque JSON; recognised key: `agentGrantableActions: string[]`) and a monotonically increasing
  **policy version**.
- **Project**: `kind` is free text (`organizational`, `publishing`, `satirical`, `campaign`, …) with its own
  `identityProfile` JSON. `status` `active | archived`.
- **Actors**: `human` (optional local login + scrypt password), `service` (client secret, shown once, stored as SHA-256 of
  256 random bits) and `agent` (durable identity with no credential at all). Humans may belong to several
  organizations; services and agents belong to exactly one.
- **Memberships**: per organization and project; project `*` (`ORG_WIDE`) is organization-wide. Effective roles in a
  project = organization-wide ∪ project roles. `status` `active | suspended | removed`, optional `expiresAt`.
- **Roles**: per-organization data `name → capabilities[]` + `actorKinds[]`, versioned (`role_versions`). Every new
  organization receives a copy of `DEFAULT_ROLES`: owner, admin, investigator, evidence_manager, correspondent, editor,
  producer, reviewer, rights_manager, release_manager, finance, auditor, participant_support, agent_researcher,
  agent_drafter, agent_producer, service_orchestrator, service_event_reader, service_connector.
- **Purposes**: per-organization data `name → capabilities[]`. Seeded from `DEFAULT_PURPOSES`: research, correspondence,
  editorial, production, release, rights, participant_support, evidence_management, finance, administration, audit,
  workspace, operations. A token is issued for exactly one purpose.
- **Compartments**: per project; membership per actor, optional expiry.
- **Grants**: one exact capability, one actor, one purpose, optional resource, bounds JSON, validity window, revocable.

### Capability rules

- Token capabilities = (current role capabilities ∩ purpose capabilities) ∪ capabilities of the actor's valid grants
  for that purpose, optionally narrowed by a requested list.
- `x:*` never covers the kit's sensitive actions (`disclose_identity, contact, send, publish, approve, spend, grant,
  admin, export, withdraw, events`) nor this engine's `identity:issue_token`. They must be named exactly.
- The `research` purpose contains no sensitive capability: a research token cannot disclose identities, contact, send,
  publish, approve, export or spend, whatever the holder's roles.
- No default role except `participant_support` (`intake:disclose_identity`) and `rights_manager`
  (`consent:disclose_identity`) can disclose protected identities. The owner role cannot; it needs an explicit grant.
- Agents: role-derived sensitive capabilities are dropped; `admin`, `grant`, `issue_token`, `events` and any action
  containing `secret`, `credential` or `password` are never held, by role or grant; `approve`, `publish`,
  `disclose_identity` are withheld unless the organization lists the action in `policyConfig.agentGrantableActions`.
  Agent role definitions may not name sensitive capabilities.
- Only an owner may assign, remove or define roles carrying `identity:admin` or `identity:grant`, define purposes,
  change `policyConfig`, configure sign-in providers, federate an administrator identity, or revoke an administrator.
  An organization always keeps at least one active human owner. Grants cannot carry `identity:admin`,
  `identity:grant` or `identity:issue_token`, and cannot be issued to oneself.

### Capabilities used by this engine

`identity:read` (directory reads, search, inspect, explain for others), `identity:audit`, `identity:admin` (all
directory mutations), `identity:grant` (create/revoke grants), `identity:issue_token` (exact; issue service and agent
tokens), `identity:export`, `identity:events`. Every administrative mutation also passes a current-state decision
(`authorize`) for the caller, so a stale or forged context cannot administer.

### Policy version and revocation

Every role, purpose, membership, compartment, grant, project-status and policy-config change increments the
organization's policy version and emits `policy.changed`. Changes that can reduce an actor's access also record a
minimum policy version for the affected actors (the member whose membership or compartment changed; every holder of a
changed role; every member when a purpose changes; the grantee of a revoked grant). A token whose `pv` is lower is
revoked: holders obtain a fresh token (sessions and service credentials are unaffected).

`isRevoked(claims)` is true when: the `jti` was revoked in the token's organization; the organization is suspended;
the project is archived; the actor is unknown, disabled or of another kind; the session (`sid`) is revoked or expired;
or `pv` is below the actor's minimum. The answer is cached per `jti` for `revocationCacheMs` (default 2 s, maximum 5 s)
in each process; a revocation made through the same process clears its cache at once. Other processes — including
engines verifying offline with only the public keys — honour it after that cache window at the latest **only if they
call this engine's `isRevoked` / `authorize`**; pure offline verification honours revocation only at token expiry
(≤ 3600 s, default 600 s). A storage failure throws, which the kit verifier turns into denial.

## 3. Service methods

Types (`Organization`, `Project`, `ActorInfo`, `Member`, `RoleInfo`, `PurposeInfo`, `GrantInfo`, `SessionRecord`,
`IssuedToken`, `SessionInfo`, `AccessDecision`, `ActorMapping`, `OidcProviderInfo`, `IntakeConnection`) are exported from
`src/engine/index.ts` / `federation.ts`. `ctx` is a kit `ServiceContext`.

```ts
type IssuedToken = { token: string; tokenId: string; expiresAt: string; actorId: string; tenantId: string; projectId: string; purpose: string; roles: string[]; capabilities: string[]; compartments: string[]; policyVersion: string };
type SessionInfo = { sessionId: string; refreshToken: string; actorId: string; expiresAt: string; boundTenantId: string | null };
type AccessDecision = { allowed: boolean; reason: string; policyVersion: string; actorId: string; tenantId: string; projectId: string; purpose: string; capability: string; resource: string | null;
  via: { kind: 'role'; roles: string[] } | { kind: 'grant'; grantId: string; bounds: Json; expiresAt: string } | null;
  trail: { rule: string; outcome: 'pass' | 'fail' | 'info'; detail: string }[] };
```

### Unauthenticated / host entry points (no `ctx`)

```ts
bootstrapFirstAdministrator(input: { login; password; displayName; organization: OrganizationInput; bootstrapToken? }, options?: { requireToken?: boolean }): Promise<{ organization; project; actorId }>
isBootstrapped(): Promise<boolean>
login(input: { login: string; password: string }): Promise<SessionInfo>
sessionDirectory(refreshToken: string): Promise<{ actorId; sessionId; expiresAt; organizations: { organization: { id; name; branding; defaultLocale }; purposes: string[]; projects: { id; name; kind; roles: string[] }[] }[] }>
issueAccessToken(input: { refreshToken; tenantId; projectId; purpose; capabilities?: string[]; ttlSeconds? }): Promise<IssuedToken>
logout(refreshToken: string): Promise<void>
authenticateService(input: { serviceId; secret; projectId; purpose; capabilities?: string[]; ttlSeconds? }): Promise<IssuedToken>
startOidcLogin(input: { tenantId; providerId; redirectUri }): Promise<{ authorizationUrl; state; expiresAt }>
completeOidcLogin(input: { state; code }): Promise<SessionInfo>
publicKeys(): Promise<Record<string, string>>                 // kid → SPKI PEM (active + retired-but-still-verifying)
jwks(): Promise<{ issuer; keys: Record<string, string>; jwks: { keys: Json[] } }>
verifier(): TokenVerifier                                     // current keys (5 s cache, reload on unknown kid) + isRevoked
isRevoked(claims: TokenClaims): Promise<boolean>              // for createTokenVerifier({ isRevoked })
health(): Promise<{ ok; detail }>
host.rotateSigningKey(): Promise<{ kid; retired: string[] }>  // trusted in-process callers only
host.revokeSigningKey(kid: string): Promise<void>
host.maintenance(options?: { rotateKeysOlderThanSeconds? }): Promise<{ rotated: string | null }>
host.issueServiceToken(input: { tenantId; serviceId; projectId; purpose; capabilities?; ttlSeconds? }): Promise<IssuedToken>
```

`OrganizationInput = { id?; name; branding?; defaultLocale?; languages?; jurisdiction?; policyConfig?; project?: { id?; name; kind?; identityProfile? } }`
(the first project defaults to id `main`). Bootstrap refuses (`conflict`) once any organization exists; concurrent
attempts are serialized. Login failures are counted per login name, existing or not; unknown logins take the same
scrypt time. Refresh tokens are opaque `<sessionId>.<secret>`, stored hashed, not rotated.

### Decisions (kit `AuthorizationPort`)

```ts
authorize(ctx, request: { capability: string; resource?: string; compartment?: string }): Promise<AccessDecision>
explain(ctx, actorId: string, capability: string, resource?: string, options?: { purpose?; projectId?; compartment? }): Promise<AccessDecision>
whoami(ctx): Promise<{ actor; tenantId; projectId; purpose; roles; capabilities; compartments; policyVersion; tokenId }>
```

`authorize` decides for the calling context on current state and never throws for a denial. Order: capability shape →
organization and project active → actor known with an active membership → actor enabled and of the presented kind →
token not revoked, `pv` not stale, capability carried by the token → agent limits → purpose defined → compartment
(`compartment`, or `resource: 'compartment:<id>'`) → current role within the purpose, else a valid grant (purpose,
window, bounds not exhausted, resource match by equality or `urefMatches`). Reasons: `role`, `grant`,
`invalid_capability`, `invalid_context`, `organization_unavailable`, `project_unavailable`, `no_membership`,
`actor_disabled`, `actor_kind_mismatch`, `token_revoked`, `stale_policy_version`, `not_in_token`, `agent_forbidden`,
`unknown_purpose`, `compartment_denied`, `capability_not_granted`, `sensitive_capability_not_granted`,
`authorization_unavailable` (storage failure). A denied sensitive capability is audited (`access.denied`); a denied
`*:disclose_identity` also emits `disclosure.denied`. `explain` evaluates any actor of the caller's organization
without a token (`identity:read` unless asking about oneself).

### Directory (`identity:read` to read, `identity:admin` to change)

```ts
createOrganization(ctx, input: OrganizationInput & { owner?: { login; password; displayName } }): Promise<{ organization; project; ownerActorId }>
getOrganization(ctx): Promise<Organization>
updateOrganization(ctx, patch: { name?; branding?; defaultLocale?; languages?; jurisdiction?; policyConfig? }): Promise<Organization>
listMyOrganizations(ctx): Promise<(same shape as sessionDirectory().organizations)>
createProject(ctx, input: { id?; name; kind?; identityProfile?; idempotencyKey? }): Promise<Project>
updateProject(ctx, projectId, patch: { name?; kind?; identityProfile?; status?: 'active' | 'archived' }): Promise<Project>
listProjects(ctx): Promise<Project[]>
createUser(ctx, input: { login; password; displayName; projectId?; roles?; idempotencyKey? }): Promise<ActorInfo>
setMembership(ctx, input: { actorId? | login?; projectId?; roles: string[]; expiresAt?: string | null; status?: 'active' | 'suspended'; idempotencyKey? }): Promise<Member>
removeMember(ctx, input: { actorId; projectId? }): Promise<void>
listMembers(ctx, options?: { projectId?; kind?; includeOrganizationWide? }): Promise<Member[]>
listUsers(ctx) / listAgents(ctx) / listServiceIdentities(ctx): Promise<ActorInfo[]>
getActor(ctx, actorId): Promise<ActorInfo | null>
resetPassword(ctx, input: { actorId; newPassword }): Promise<void>
changePassword(ctx, input: { currentPassword; newPassword }): Promise<void>      // ends every session of the caller
createAgent(ctx, input: { name; description?; projectId?; roles: string[]; profile?; idempotencyKey? }): Promise<ActorInfo>
createServiceIdentity(ctx, input: { name; description?; projectId?; roles: string[]; profile? }): Promise<{ service: ActorInfo; secret: string }>
rotateServiceSecret(ctx, serviceId): Promise<{ secret: string }>
listRoles(ctx): Promise<RoleInfo[]>;  roleHistory(ctx, name): Promise<{ version; capabilities; actorKinds; deleted; policyVersion; at; actorId }[]>
defineRole(ctx, input: { name; description?; capabilities: string[]; actorKinds?: ('human'|'agent'|'service')[]; deleted?; idempotencyKey? }): Promise<RoleInfo>
listPurposes(ctx): Promise<PurposeInfo[]>;  definePurpose(ctx, input: { name; description?; capabilities: string[] }): Promise<PurposeInfo>
createCompartment(ctx, input: { id; description?; projectId? }): Promise<{ id; projectId; description }>
setCompartmentMember(ctx, input: { compartmentId; actorId; member: boolean; projectId?; expiresAt? }): Promise<void>
listCompartments(ctx, options?: { projectId? }): Promise<{ id; projectId; description; members: string[] }[]>
counts(ctx): Promise<{ projects; members; agents; services; roles; activeGrants; compartments }>
exportDirectory(ctx): Promise<{ organization; projects; roles; purposes; members; grants; exportedAt; policyVersion }>   // identity:export
```

Visibility: callers without `identity:admin` see only their token's project (members, grants, counts, search, audit),
only projects they belong to, and only compartments they are members of. A project, actor, grant, session or
compartment outside the caller's organization or visibility is `not_found` / `null` / absent — never an error that
confirms it exists. `createOrganization` gives the caller no access to the new organization when `owner` is supplied.
`resetPassword` is refused for an account that also belongs to another organization. `setMembership` by `login`
answers `not_found` for an unknown login (this reveals to an administrator whether a login exists).
Idempotency keys are supported where listed; commands that return or accept secrets
(`createServiceIdentity`, `createOrganization`, password and token calls) are not idempotent by key.

### Tokens for services and agents

```ts
issueServiceToken(ctx, input: { serviceId; projectId?; purpose; capabilities?; ttlSeconds? }): Promise<IssuedToken>
issueAgentToken(ctx, input: { agentId; projectId?; purpose; capabilities: string[]; ttlSeconds?; onBehalfOf?: string; compartments?: string[] }): Promise<IssuedToken>
```

Caller needs `identity:issue_token` (exact; the seeded `service_orchestrator` role has it under purpose `operations`) or
`identity:admin`; another project needs `identity:admin`. Agent tokens take an explicit, non-empty capability list:
if any entry is not available to the agent for that purpose the whole request is `forbidden` (nothing is silently
dropped). `onBehalfOf` additionally caps the agent's role capabilities by that human's current role capabilities.
Lifetime 30 s – `agentTokenMaxTtlSeconds`. Issuance is audited (`token.issued`) without token material.
Tokens carry capability names only — never provider secrets or database credentials; this engine stores none
besides its own sealed signing keys and OIDC client secrets, which no API returns.

### Grants (`identity:grant` to create/revoke)

```ts
createGrant(ctx, input: { actorId; capability; purpose; projectId?; resource?; bounds?; reason; notBefore?; expiresAt; idempotencyKey? }): Promise<GrantInfo>
revokeGrant(ctx, input: { grantId; reason }): Promise<GrantInfo>
listGrants(ctx, options?: { actorId?; capability?; projectId?; includeInactive? }): Promise<GrantInfo[]>
checkGrant(ctx, input: { actorId?; capability; purpose?; resource?; recipient?; amount?; grantId? }): Promise<{ valid; reason; grant: GrantInfo | null; remainingUses; remainingAmount; policyVersion }>
useGrant(ctx, input: { grantId; useKey; units?; amount?; recipient?; resource? }): Promise<{ grant; remainingUses; remainingAmount }>
```

`GrantInfo.state`: `active | pending | expired | revoked | exhausted`. `bounds` is stored and returned verbatim; the
engine itself enforces `maxUses` (number), `maxAmount` (number), `recipients` (string[]) and `resources` (string[]);
any other key (currency, channel, …) is for the consuming engine to enforce. `useGrant` is called by the grantee,
consumes atomically (row lock), is idempotent by `useKey`, and throws `grant_invalid` when a bound would be exceeded.
Other engines consult grants through `authorize` (which names the grant and its bounds in `via`) or `checkGrant`.

### Revocation

```ts
revokeToken(ctx, input: { tokenId; reason?; actorId?; expiresAt? }): Promise<void>     // own token: anyone; others: identity:admin
listSessions(ctx, options?: { actorId?; includeEnded? }): Promise<SessionRecord[]>
revokeSession(ctx, input: { sessionId; reason? }): Promise<void>
revokeActor(ctx, input: { actorId; reason; disable?: boolean }): Promise<void>
reinstateActor(ctx, input: { actorId; reason }): Promise<void>
rotateSigningKey(ctx): Promise<{ kid; retired }>;  revokeSigningKey(ctx, kid): Promise<void>   // owner of the first (platform) organization only
```

Token revocations are per organization (another organization revoking the same id has no effect).
`revokeActor` ends the actor's outstanding tokens in the caller's organization; with `disable` it suspends the actor's
memberships there and, when the actor's home is this organization and it belongs to no other, disables the account
and ends its sessions. A retired signing key keeps verifying for 3720 s (longest token + margin); a revoked key stops at once.

### Federation

```ts
mapExternalActor(ctx, input: { provider; issuer; subject; audience?; actorId }): Promise<ActorMapping>
listActorMappings(ctx, options?: { actorId?; provider? }): Promise<ActorMapping[]>;  removeActorMapping(ctx, mappingId): Promise<void>
resolveExternalActor(ctx, input: { provider; issuer; subject; audience? }): Promise<{ actorId; kind; status } | null>
configureOidcProvider(ctx, input: { id; issuer; clientId; clientSecret?: string | null; scopes?; redirectUris: string[]; discoveryUrl?; enabled?; maxSessionAgeSeconds? }): Promise<OidcProviderInfo>
listOidcProviders(ctx): Promise<OidcProviderInfo[]>
registerIntakeConnection(ctx, input: { connectionId; origin; credentialFingerprint; requiredScopes; supportedVersions; localRoles?; roles?; projectId? }): Promise<IntakeConnection>
listIntakeConnections(ctx): Promise<IntakeConnection[]>
verifyIntakeConnection(ctx, connectionId): Promise<{ status: 'verified' | 'failed' | 'unavailable'; reason; connection }>
issueIntakeServiceToken(ctx, input: { connectionId; purpose; ttlSeconds? }): Promise<IssuedToken>
```

- **OIDC** (`oidc.ts`): discovery document (issuer must match exactly), authorization code + PKCE S256, client
  authentication `client_secret_basic` (or public client), id-token verification against the issuer's JWKS (RS256, PS256,
  ES256, EdDSA; `iss`, `aud`/`azp`, `exp`, `iat`, `nonce`), single-use hashed `state` valid 10 minutes. The verified
  identity then passes through the existing `createHumanFederationProvider` (`src/human-federation.ts`) with the
  organization's `oidc` actor mappings: exact issuer + subject + client, authentication age ≤ `maxSessionAgeSeconds`.
  No automatic provisioning; id-token claims supply no roles or scope. The session is bound to the provider's
  organization. Provider URLs must be HTTPS and resolve to public addresses (checked before each request; redirects
  are not followed; 10 s timeout; 256 kB limit). Issuers must be HTTPS URLs.
  *Tested against a local fake issuer over HTTP; not verified against any real identity provider.* Not implemented:
  `private_key_jwt`, encrypted id tokens, RP-initiated logout, back-channel logout, userinfo, refresh of upstream tokens.
- **Intake** (`intake-service-adapter.ts`, reused unchanged): a connection becomes one service identity (no local
  secret) plus the mapping `intake / <origin> / <connectionId>`; `verifyIntakeConnection` runs `verifyIntakeService`
  (pinned credential fingerprint, capability contract, required scopes) and `issueIntakeServiceToken` works only within
  15 minutes of a successful verification. Intake users federate with `mapExternalActor({ provider: 'intake', issuer:
  origin, subject })`. *Tested against a local server speaking intake's capability contract through a controlled
  transport; not verified against a deployed intake engine.* Intake's protected-identity dual control is not replicated
  or overridden here.

### Standard surface

```ts
inspect(ctx, ref): Promise<Inspection | null>   // E01:organization|project|actor|user|agent|service|role|grant|compartment:<id>
search(ctx, { q, limit? }): Promise<SearchHit[]>   // projects, members, roles, grants, compartments (substring match)
audit(ctx, options?): Promise<AuditRecord[]>       // identity:audit; whole organization for identity:admin, else the token's project
events(ctx, options?): Promise<EngineEvent[]>      // identity:events; the caller's organization only
applyUpstreamChange(ctx, change): Promise<{ affected: [] }>   // identity:events; no-op
health()
```

## 4. HTTP routes

Standard: `GET /healthz`, `GET /v1/manifest` (public), `GET /v1/inspect?ref=`, `GET /v1/search?q=`, `GET /v1/audit`,
`GET /v1/events`, `POST /v1/upstream-changes`.

Public (no bearer token): `GET /v1/keys` · `GET|POST /v1/bootstrap` · `POST /v1/sessions` (login) ·
`POST /v1/sessions/directory` · `POST /v1/sessions/logout` · `POST /v1/tokens` · `POST /v1/tokens/service` ·
`POST /v1/oidc/start` · `POST /v1/oidc/callback`.

Catalog API: `POST /v1/policy/evaluate` (`authorize`) · `POST /v1/capability-grants` · `POST /v1/grants/:id/revoke` ·
`GET /v1/access/explain?actorId=&capability=&resource=&purpose=&projectId=&compartment=`.

Others: `GET /v1/whoami` · `GET /v1/capability-grants` · `POST /v1/capability-grants/check` · `POST /v1/grants/:id/use` ·
`GET|PATCH /v1/organization` · `POST /v1/organizations` · `GET /v1/my/organizations` · `GET|POST /v1/projects` ·
`PATCH /v1/projects/:id` · `GET /v1/counts` · `GET /v1/export` · `GET|POST /v1/users` · `GET /v1/actors/:id` ·
`POST /v1/users/:id/password` · `POST /v1/password` · `GET|PUT /v1/members` · `POST /v1/members/remove` ·
`GET|POST /v1/agents` · `POST /v1/agents/:id/tokens` · `GET|POST /v1/services` · `POST /v1/services/:id/secret` ·
`POST /v1/services/:id/tokens` · `GET /v1/roles` · `PUT /v1/roles/:name` · `GET /v1/roles/:name/history` ·
`GET /v1/purposes` · `PUT /v1/purposes/:name` · `GET|POST /v1/compartments` · `PUT /v1/compartments/:id/members` ·
`POST /v1/tokens/revoke` · `GET /v1/sessions` · `POST /v1/sessions/:id/revoke` · `POST /v1/actors/:id/revoke` ·
`POST /v1/actors/:id/reinstate` · `POST /v1/keys/rotate` · `POST /v1/keys/:kid/revoke` · `GET|POST /v1/actor-mappings` ·
`POST /v1/actor-mappings/resolve` · `DELETE /v1/actor-mappings/:id` · `GET /v1/oidc/providers` ·
`PUT /v1/oidc/providers/:id` · `GET|POST /v1/intake/connections` · `POST /v1/intake/connections/:id/verify` ·
`POST /v1/intake/connections/:id/tokens`.

Bodies are the method inputs as JSON; path parameters fill the id field. Errors follow the kit (`{ error: { code,
message, requestId } }`; 404 bodies carry no detail). The kit masks every ≥ 500 status as `internal`, so
`unavailable` conditions (for example a missing key-encryption key) appear over HTTP as 500 and are visible in
`/healthz`.

## 5. Events

Subject is `E01:<kind>:<id>`; payloads carry ids and versions, never credentials.

| Type | Subject kind | When |
|---|---|---|
| `organization.created`, `organization.updated` | organization | |
| `project.created`, `project.updated` | project | |
| `actor.created`, `actor.updated` | actor | user, agent or service created; service secret rotated |
| `membership.changed` | actor | membership set, suspended or removed |
| `role.changed` | role | definition version created or deleted |
| `purpose.changed` | purpose | |
| `compartment.changed` | compartment | created or membership changed |
| `policy.changed` | organization | every policy-version increment: `{ policyVersion, cause, actors }` — drop caches for those actors (all, when in doubt) |
| `grant.issued`, `grant.revoked`, `grant.used` | grant | |
| `token.revoked` | actor | one token id revoked |
| `session.revoked` | session (or actor for a password reset) | |
| `actor.revoked`, `actor.reinstated` | actor | |
| `key.rotated` | signing_key | recorded in the first (platform) organization |
| `disclosure.denied` | actor | `authorize` denied a `*:disclose_identity` |
| `mapping.changed`, `federation.changed` | actor / oidc_provider | |

Consumes none. `applyUpstreamChange` returns `{ affected: [] }`.

## 6. Tests and what they prove

`npm run check` with `TEST_DATABASE_URL` (CI job `check` has a `postgres:16` service). Service-layer suites, all on a
real disposable PostgreSQL database per test:

- `tests/engine.test.ts` — default catalog; bootstrap once (also concurrent, and token-gated); scrypt storage; lockout
  for known and unknown logins; password change and reset; one-organization/project/purpose tokens; research implies
  nothing sensitive; fail-closed cases (unknown actor, foreign tenant, wrong project, unknown purpose, kind mismatch,
  malformed context, storage failure, tampered/forged/expired tokens, revoked token, revoked and expired session,
  missing compartment, disabled actor); role, membership, expiry and removal taking effect on the next `authorize`
  with the policy version; owner-only escalation rules; idempotent replay; audit chain integrity.
- `tests/engine-access.test.ts` — two organizations isolated through every read, search, inspect, counts, export,
  audit, events and every cross-organization write; grants (exactness, purpose binding, resource, recipients, uses and
  amount bounds, concurrent use, expiry, revocation, token death on revocation); service and agent identities and
  tokens; signing keys sealed at rest, rotation with old tokens verifying until the window ends, key revocation,
  wrong key-encryption key, concurrent owner removal, archived projects.
- `tests/engine-federation.test.ts` — SSRF guard; full OIDC code + PKCE flow against a local issuer over HTTP
  including seven tampered-response modes, state replay, cross-flow code, organization-bound sessions and mapping
  removal; intake adapter against a local HTTP server.
- `tests/engine-http.test.ts` — the standalone server (`start`) end to end over real sockets.

Earlier library suites (membership, revocations, resource policy, stored capability, federation mapping, intake
adapter, kit) are unchanged and still run.

## 7. Not implemented, not verified, known limits

- No live identity provider, intake deployment or hosted environment was used. No independent security review.
- No MFA, WebAuthn, password-reset-by-email, account self-registration or invitation emails (this engine sends nothing).
- Refresh tokens are not rotated on use; a stolen refresh token works until the session expires, idles out or is revoked.
- Login lockout is per login name, so a third party can lock an account for the lock period (30 s doubling to 15 min).
  There is no per-network-address throttle: the kit's HTTP layer does not expose the peer address.
- Revocation reaches other engines only through `isRevoked` / `authorize` calls or token expiry (see §2).
- Database row-level-security policies are not created; isolation is enforced in every query of this service layer.
  The catalog's "redacted projections" and "rate limits" for other engines' data are not provided here.
- The SSRF guard resolves names before the request; it does not pin the resolved address for the connection.
- The earlier library modules (`membership.ts`, `revocations.ts`, `resource-policy.ts`, `stored-capability.ts`,
  `membership-http.ts`, `membership-session.ts`) remain exported and tested but are a separate persistence model
  (the evidence engine's unit-of-work store); the service layer does not read or write their state. Of the earlier
  code the service layer reuses `human-federation.ts`, `intake-service-adapter.ts` and `tokenHash`.
- The kit event feed withholds events while any older transaction on the same PostgreSQL server is open, so a long
  transaction in any database of the server delays `events()`.
- `policyConfig` and `jurisdiction` are stored opaquely; only `agentGrantableActions` is interpreted.
