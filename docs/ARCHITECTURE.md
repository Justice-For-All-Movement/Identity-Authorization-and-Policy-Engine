# Identity and policy architecture

The engine exports country-neutral TypeScript authorization primitives. An authenticated adapter supplies a trusted Context with actor, tenant, project, purpose and current time. Role authorization rejects cross-scope access. Human identities are required for administration and public release authority.

Capabilities are HMAC-SHA256 signed and bind actor, tenant, project, purpose, resource IDs, policy revision, actor revocation epoch and a maximum one-hour validity period. Consumers must obtain current epochs, policies and revoked IDs from trusted storage at the action gateway. A valid signature alone is insufficient authority. Keep signing keys in deployment key custody.

Capability issuance and verification validate the complete runtime schema before granting authority. Identifiers, actions, revisions, epochs and resource arrays are bounded; resource IDs must be nonempty and unique; verifier expectations and revocation lists are also bounded. Verification requires the signed payload to use the engine's canonical JSON encoding and returns detached data. Malformed signed data fails with the engine's authorization error contract instead of surfacing parser or type errors. These checks do not replace current policy, epoch and revocation reads at the consuming action gateway.

The initial package is a library; it does not provide identity federation, credential issuance UI or a live service. Opt-in durable modules below use an Identity-owned operational database; hosting and federation remain pending. Shared contracts are exported at ./contracts and will be consumed through pinned engine packages. Runtime IDs are bounded opaque strings and references use immutable positive integer revisions.

Tests use only fictional scopes and temporary signing keys. No real deployment identity or research is included.

The public role authorizer validates bounded nonblank tenant/project/principal IDs, known actor kinds and a bounded array of role strings before consulting role grants. Static credential authentication requires one unambiguous explicitly enabled identity, a nonnegative safe integer epoch and the same scoped actor shape; shared credentials across enabled identities fail closed instead of selecting the first mapping. Returned identity data remains detached. These are runtime input/configuration checks, not live identity proofing, membership refresh or a replacement for the trusted host context.

## Managed intake service adapter

`verifyIntakeService` validates one deployment-configured intake connection using its pinned managed credential and authenticated capability contract. The source returns no organization/client identity; an arbitrary upstream token therefore cannot establish a local tenant. The adapter refuses a credential whose fingerprint differs from the trusted mapping and never maps upstream scope strings into local roles. It returns only a local service identity with explicitly configured non-owner roles. Responses are bounded, redirects denied, engine versions pinned and required scopes checked. Tokens remain in credential/transport callbacks and are excluded from returned identity data.

This is managed service verification. End-user login/federation and host provisioning remain separate work; the opt-in durable policy modules are described below. The host must trust mapping/key custody and independently authenticate incoming users before allowing a connection to be used.

## Human federation mapping

`createHumanFederationProvider` accepts only the result of a host-supplied federation verifier. The verifier remains responsible for protocol, signature, key-rotation, nonce and credential handling. The engine requires exact bounded claims, current authentication and expiry times, and an unambiguous enabled issuer/subject/audience mapping before returning a local human actor ID. Provider claims cannot supply local tenant, project, roles or actor IDs. The existing membership-session adapter then reloads current stored membership and authorization for every request.

This is a provider-neutral source boundary for IAP-004, not an OpenID Connect or SAML implementation, automatic member provisioning, account linking, recovery, a listening host or live federation qualification. An owner must separately provision the mapped local member through the durable membership administration path.

Managed verification now snapshots configuration before any callback and applies one cancellable 10-second default deadline (configurable 10–30000ms) across credential lookup, transport and body reads. The credential callback receives the same AbortSignal as transport. JSON UTF8, 64KiB and 4096-chunk limits apply; late responses are discarded and callback diagnostics sanitized. This is a local callback/Fetch boundary, not a qualified deployed network or authentication service. Ten new synthetic callback/native-Fetch groups exercise mapping mutation, credential/body stalls, abort, zero-byte chunk floods, bounded malformed input, copied chunks, sanitized errors and monotonic expiry. Final-head CI is recorded in the PR.

The default transport remains host-configured HTTPS Fetch with manual redirects. This change does not add an SSRF-resistant DNS/egress gateway or independently prove the remote organization: trusted deployment mapping and credential custody remain mandatory. Timeouts/cancellation stop acceptance and subsequent stages, but cannot forcibly terminate arbitrary host callbacks or undo their side effects. Monotonic deadline checks reject synchronous overruns at stage boundaries; they do not preempt blocked JavaScript. A host must reverify using current mapping after revocation; an earlier returned service identity is a historical snapshot, not current authorization.

## Durable revocation administration

[Revocations](REVOCATIONS.md) adds an opt-in Identity-owned operational database for policy/actor epoch changes, exact capability revocation and transactional audit/outbox. Verification reads current state and a post-load live clock under the same project lock. Host authentication, fixed administrator configuration and signing-key custody remain external trust boundaries. This is partial IAP-005 work, not federation, dynamic membership, a deployed gateway or distributed action fencing.

## Independent database sessions

POSTGRES_TESTS.md defines disposable PostgreSQL17 CI for revocation contenders, observed lock waits, current expiry/revocation, lost acknowledgements and restricted roles. This is distinct from embedded tests and production identity/key/deployment qualification. Actual final-head CI is required; no local network execution is claimed.

## Persistent project membership

[Membership](MEMBERSHIP.md) supplies bounded dynamic roles, disable/re-enable, current stored human-owner administration before cached acknowledgements and last-owner/permanent-kind protection in the Identity-owned DB. Own-principal action resolution discards incoming roles, reloads stored policy under the project lock and returns an explicit policy revision/member epoch snapshot. This is additional partial IAP-005 work, not authentication, a deployed gateway, automatic capability epoch synchronization, compartment policy or distributed action fencing. Fixed-list RevocationRegistry admission remains a separate interface.

MembershipRegistry.verifyCapability now observes current enabled membership roles/kind and stored HMAC capability revocation state under one Identity project lock/transaction, with a shared internal checker preserving RevocationRegistry admission. No separate read/verify gap exists within that observation. This does not bind later external execution, synchronize membership and capability epochs or provide host authentication. See MEMBERSHIP.md.

POSTGRES_TESTS.md additionally defines four direct combined membership/capability contention cases, including real public mutation transactions held before COMMIT and directly observed backend waits. Integration sources are strictly typechecked before their separate CI execution; local embedded tests remain distinct from actual network and production acceptance.

## Current human session integration port

[Membership session](MEMBERSHIP_SESSION.md) connects a trusted host-authenticated human ID/session CSRF to current stored roles through MembershipRegistry.resolve on each invocation. It fixes scope/purpose/action and awaits begun SQL, denying late snapshots. The returned Context remains historical, not capability verification or a downstream action fence. Listening-host authentication and consuming-handler integration remain separate qualification.

## Private membership administration adapter

[Membership HTTP](MEMBERSHIP_HTTP.md) connects the accepted current human-session adapter to private membership read/set/disable operations. The owning registry rechecks stored human-owner authority under its mutation lock before cached acknowledgements. Bootstrap/credentials/revocation configuration and external action dispatch remain outside these routes. Twelve restricted-migration/native-Fetch groups cover current authority before/after session resolution, replay/lost acknowledgements, rollback, deadlines and cancellation. Installed-package/current-head CI evidence and production host acceptance remain separate.

Membership HTTP's twelve groups also pass installed compiled public exports, with all63 local ordinary tests/typecheck/build/registry/strict integration compile green. CI40712556437 confirms63 ordinary and twelve existing PostgreSQL17 groups on expanded source, logs inspected; final-head CI remains required after evidence changes. Host authentication/CSRF/current clocks/listening and SQL limits remain separate acceptance.

Optional resource restrictions now intersect exact resource member/purpose/action policies with current stored membership under one owning SQL lock. Existing role/capability/session/HTTP paths are unchanged; consuming action gateways must explicitly opt into resolveResource. This is partial IAP-006, not automatic compartment enforcement or external action fencing. See RESOURCE_POLICIES.md.

Resource-policy session evidence separately covers actual resource-aware resolution after committed member/purpose/action restrictions and stored member disable/demotion, current-owner admission before cached policy acknowledgement, and policy CAS/lost COMMIT acknowledgement with retained history and fresh-pool replay. Seven new plus twelve prior PostgreSQL17 groups passed CI40900061441; see POSTGRES_TESTS.md and resource-policy-postgres-verification.json. This changes no runtime authority and does not qualify downstream external action fencing or production deployment.


