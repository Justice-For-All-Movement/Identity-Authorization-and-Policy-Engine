# Identity, Authorization and Policy Engine

Reusable tenant/project authorization, authenticated actor mapping, purpose-scoped signed capabilities and revocation. Deployment-specific policies and research belong in downstream applications.

```sh
npm ci
npm run check
npm run build
```

Initial library capabilities: trusted actor contexts, role authorization, human authority for administrative/release operations, signed purpose/resource grants, expiry, policy revisions and revocation epochs. Every unit of the plan in [registry/prs.json](registry/prs.json) is implemented; the remaining live steps that need the owner's accounts are listed in [docs/OWNER_STEPS.md](docs/OWNER_STEPS.md).

See [architecture](docs/ARCHITECTURE.md). Tests use fictional scopes and temporary keys. The Public Accountability Machine consumes this engine after its dependency contract is ready.

## Service layer

The engine now ships a persisted service (`src/engine/`, package exports `./engine` and `./serve`): organizations,
projects, human/service/agent identities, memberships, versioned roles and purposes, compartments, password and OIDC
sign-in, sessions, short-lived purpose-scoped access tokens, signing-key storage and rotation, purpose grants,
revocation, explainable access decisions (`authorize`, `explain`) and federation of the intake identity boundary.
Full surface, limits and verification status: [docs/ENGINE_API.md](docs/ENGINE_API.md).

```sh
# run (PostgreSQL required; migrations run at start)
DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/db \
IDENTITY_KEY_ENCRYPTION_KEY=<at least 32 random characters> \
IDENTITY_BOOTSTRAP_TOKEN=<one-time secret> PORT=8080 npm run serve

# test (service-layer suites create and drop their own databases; skipped visibly without the variable)
TEST_DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/postgres npm run check
```

```ts
import { createEngine, migrate, routes } from '@accountability/identity-policy/engine';
await migrate(sql);
const identity = createEngine({ sql, config: { keyEncryptionKey } });
const verify = identity.verifier();                       // kit TokenVerifier: current keys + revocation
const decision = await identity.authorize(ctx, { capability: 'release:publish', resource });   // kit AuthorizationPort
```

Other engines verify tokens with the public keys from `GET /v1/keys` (`keys` is the `IDENTITY_PUBLIC_KEYS` map).
Also: who-can-access and revocation-impact views, field-level redacted projections, shared rate limits, invitations,
password reset through a host delivery port, organization-required two-factor sign-in and database row policies.

Tested against real PostgreSQL and local fake providers. Live evidence so far: public deployment checks against the
hosted deployment and an identity provider's public metadata (see `npm run verify:live`, `npm run verify:oidc-provider`
and [docs/OWNER_STEPS.md](docs/OWNER_STEPS.md)); signed-in live checks need the owner's settings.
