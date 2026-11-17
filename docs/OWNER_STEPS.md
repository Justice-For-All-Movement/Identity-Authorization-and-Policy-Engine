# Owner steps

Everything in the plan ([registry/prs.json](../registry/prs.json)) that can be built and tested without the owner's
accounts is implemented, tested on real PostgreSQL in CI, and documented in [ENGINE_API.md](ENGINE_API.md). The items
below need the owner's credentials, accounts or decisions. Each is built up to that boundary and checked by an opt-in
script that skips (and succeeds) while its settings are absent. Only setting **names** appear here; values belong in
the deployment's or GitHub's secret settings, never in this repository.

## 1. Signed-in live acceptance of the hosted deployment (IAP-007, IAP-008)

Public checks already pass against the hosted deployment that embeds this engine. For the signed-in checks (session,
read-only token, offline signature check, decisions, redacted projection, token revocation, sign-out):

1. Create a dedicated, low-privilege person in the deployment (for example with only the `auditor` role) whose
   password is used for nothing else.
2. In GitHub → this repository → Settings → Secrets and variables → Actions:
   - variable `IDENTITY_LIVE_BASE_URL` — the engine's base URL (for an embedding host, its mount point, e.g. `…/api/e/identity`)
   - optional variables `IDENTITY_LIVE_EXPECT_ISSUER`, `IDENTITY_LIVE_TENANT_ID`, `IDENTITY_LIVE_PROJECT_ID`
   - secrets `IDENTITY_LIVE_LOGIN`, `IDENTITY_LIVE_PASSWORD`, and `IDENTITY_LIVE_TOTP_SECRET` if that person uses two-factor sign-in
3. Actions → **Live verification** → Run workflow. It also runs weekly. Locally: `npm run verify:live` with the same
   environment variables.

## 2. Identity-provider sign-in (IAP-004)

The OIDC relying party is implemented and tested against a local issuer; provider metadata compatibility is checked by
`npm run verify:oidc-provider`. To go live:

1. Register a client at the chosen provider with redirect URI `<deployment>/…/oidc/callback` (the host's page that
   posts `state` and `code` to `POST /v1/oidc/callback`), grant type authorization code, PKCE S256, client
   authentication `client_secret_basic`.
2. Repository variable `IDENTITY_LIVE_OIDC_ISSUER` (the provider's issuer URL) to run the compatibility check.
3. As an organization owner: `PUT /v1/oidc/providers/:id` with the issuer, client id, client secret and redirect URI,
   then `POST /v1/actor-mappings` to map each person's provider subject to their account (no automatic provisioning).
4. Sign in once through a browser and confirm the session (a person must do this; it cannot be automated here).

## 3. Password-reset delivery (IAP-004)

The reset flow is complete except delivery. Choose a mail or messaging service (a free tier is enough) and run a small
receiver that verifies the signature and sends the message, then set on the identity deployment:

- `IDENTITY_PASSWORD_RESET_WEBHOOK_URL`
- `IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET` (at least 32 random characters, shared with the receiver)

An embedding host can instead pass its own `passwordResetDelivery` port. Until then `POST /v1/password-resets`
answers unavailable and administrators reset passwords (`POST /v1/users/:id/password`).

## 4. Optional decisions

- `policyConfig.requireMfa: true` per organization, to require two-factor sign-in for local passwords.
- A restricted database role for reporting or support access (row policies already apply to it; see ENGINE_API §3,
  "Database row policies"). Creating roles on the hosted database is an owner action.
- Re-pin this engine in the embedding application to pick up these features (the hosted deployment runs an earlier pin).
- Independent security review (not a blocker under AGENTS.md).

Nothing above costs money by itself; none of it has been done on the owner's behalf.
