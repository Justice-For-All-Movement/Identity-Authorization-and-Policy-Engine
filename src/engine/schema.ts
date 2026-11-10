// E01 schema and the seeded (per-organization, editable) role and purpose catalogs.
import type { Migration } from '../service-kit.ts';

export const SCHEMA = 'e01_identity';
/** Project id used for organization-wide rows (memberships, grants). Never a real project id. */
export const ORG_WIDE = '*';

export const migrations: readonly Migration[] = [{ id: '001_identity_core', sql: `
create table {s}.deployment (key text primary key, value jsonb not null);
create table {s}.organizations (
  id text primary key, name text not null, branding jsonb not null default '{}', default_locale text not null default 'en',
  languages text[] not null default '{}', jurisdiction jsonb not null default '{}', policy_config jsonb not null default '{}',
  policy_version bigint not null default 1, status text not null default 'active' check (status in ('active','suspended')),
  created_at timestamptz not null, updated_at timestamptz not null, created_by text not null
);
create table {s}.projects (
  tenant_id text not null references {s}.organizations(id), id text not null, name text not null,
  kind text not null default 'organizational', identity_profile jsonb not null default '{}',
  status text not null default 'active' check (status in ('active','archived')),
  created_at timestamptz not null, updated_at timestamptz not null, created_by text not null,
  primary key (tenant_id, id)
);
create table {s}.actors (
  id text primary key, kind text not null check (kind in ('human','agent','service')), display_name text not null,
  home_tenant_id text not null, home_project_id text, description text not null default '', profile jsonb not null default '{}',
  status text not null default 'active' check (status in ('active','disabled')),
  secret_hash text, created_at timestamptz not null, updated_at timestamptz not null, created_by text not null
);
create index actors_home on {s}.actors (home_tenant_id, kind);
create table {s}.credentials (
  actor_id text primary key references {s}.actors(id), login text not null unique, password_hash text not null,
  changed_at timestamptz not null
);
create table {s}.auth_attempts (key text primary key, failures int not null, last_failed_at timestamptz not null, locked_until timestamptz);
create table {s}.memberships (
  tenant_id text not null, project_id text not null, actor_id text not null references {s}.actors(id),
  roles text[] not null, status text not null default 'active' check (status in ('active','suspended','removed')),
  expires_at timestamptz, revision int not null default 1, created_at timestamptz not null, updated_at timestamptz not null, updated_by text not null,
  primary key (tenant_id, project_id, actor_id)
);
create index memberships_actor on {s}.memberships (actor_id);
create table {s}.roles (
  tenant_id text not null, name text not null, description text not null default '', capabilities text[] not null,
  actor_kinds text[] not null, version int not null default 1, seeded boolean not null default false, deleted boolean not null default false,
  updated_at timestamptz not null, updated_by text not null, primary key (tenant_id, name)
);
create table {s}.role_versions (
  tenant_id text not null, name text not null, version int not null, capabilities text[] not null, actor_kinds text[] not null,
  deleted boolean not null, policy_version bigint not null, at timestamptz not null, actor_id text not null, primary key (tenant_id, name, version)
);
create table {s}.purposes (
  tenant_id text not null, name text not null, description text not null default '', capabilities text[] not null,
  updated_at timestamptz not null, updated_by text not null, primary key (tenant_id, name)
);
create table {s}.compartments (
  tenant_id text not null, project_id text not null, id text not null, description text not null default '',
  created_at timestamptz not null, created_by text not null, primary key (tenant_id, project_id, id)
);
create table {s}.compartment_members (
  tenant_id text not null, project_id text not null, compartment_id text not null, actor_id text not null,
  expires_at timestamptz, added_at timestamptz not null, added_by text not null,
  primary key (tenant_id, project_id, compartment_id, actor_id)
);
create table {s}.grants (
  id text primary key, tenant_id text not null, project_id text not null, actor_id text not null, capability text not null,
  purpose text not null, resource text, bounds jsonb not null default '{}', reason text not null default '',
  not_before timestamptz not null, expires_at timestamptz not null, uses int not null default 0, amount_used numeric not null default 0,
  revoked_at timestamptz, revoked_by text, revoke_reason text, created_at timestamptz not null, created_by text not null
);
create index grants_actor on {s}.grants (tenant_id, actor_id, capability);
create table {s}.grant_uses (grant_id text not null, use_key text not null, units int not null, amount numeric not null, at timestamptz not null, primary key (grant_id, use_key));
create table {s}.sessions (
  id text primary key, actor_id text not null, refresh_hash text not null, bound_tenant_id text, method text not null,
  created_at timestamptz not null, last_used_at timestamptz not null, expires_at timestamptz not null,
  revoked_at timestamptz, revoked_by text, revoke_reason text
);
create index sessions_actor on {s}.sessions (actor_id);
create table {s}.token_revocations (tenant_id text not null, jti text not null, actor_id text, token_expires_at timestamptz not null, revoked_at timestamptz not null, revoked_by text not null, reason text not null default '', primary key (tenant_id, jti));
create table {s}.actor_revocations (tenant_id text not null, actor_id text not null, min_policy_version bigint not null, reason text not null default '', at timestamptz not null, primary key (tenant_id, actor_id));
create table {s}.signing_keys (
  kid text primary key, public_pem text not null, private_sealed text not null,
  status text not null check (status in ('active','retired','revoked')), created_at timestamptz not null, retired_at timestamptz, verify_until timestamptz
);
create table {s}.actor_mappings (
  id text primary key, tenant_id text not null, provider text not null, issuer text not null, subject text not null, audience text not null default '',
  actor_id text not null, enabled boolean not null default true, created_at timestamptz not null, created_by text not null,
  unique (tenant_id, provider, issuer, subject, audience)
);
create table {s}.oidc_providers (
  tenant_id text not null, id text not null, issuer text not null, client_id text not null, client_secret_sealed text,
  scopes text[] not null, redirect_uris text[] not null, discovery_url text, enabled boolean not null default true,
  max_session_age_seconds int not null default 600, updated_at timestamptz not null, updated_by text not null, primary key (tenant_id, id)
);
create table {s}.oidc_states (
  state_hash text primary key, tenant_id text not null, provider_id text not null, verifier_sealed text not null, nonce text not null,
  redirect_uri text not null, created_at timestamptz not null, expires_at timestamptz not null, consumed_at timestamptz
);
create table {s}.intake_connections (
  tenant_id text not null, project_id text not null, connection_id text not null, origin text not null, credential_fingerprint text not null,
  actor_id text not null, local_roles text[] not null, required_scopes text[] not null, supported_versions text[] not null,
  epoch int not null default 1, enabled boolean not null default true, verified_at timestamptz, upstream_version text, upstream_scope_digest text,
  last_error text, updated_at timestamptz not null, updated_by text not null, primary key (tenant_id, connection_id)
);
` }];

export const ENGINES = ['orchestration', 'identity', 'intake', 'correspondence', 'discovery', 'evidence', 'processing', 'knowledge', 'investigation', 'editorial', 'production', 'consent', 'release', 'resources', 'workspace'] as const;
const all = (suffix: string): string[] => ENGINES.map((e) => `${e}:${suffix}`);
const eng = (name: string, ...sensitive: string[]): string[] => [`${name}:*`, ...sensitive.map((a) => `${name}:${a}`)];
const read = (...names: string[]): string[] => names.map((n) => `${n}:read`);
const DIR = ['identity:read', 'workspace:*', 'orchestration:read'];

export type RoleSeed = Readonly<{ name: string; description: string; kinds: readonly ('human' | 'agent' | 'service')[]; capabilities: readonly string[] }>;
/**
 * Default catalog copied into every new organization as editable data. Engine wildcards (`x:*`) never cover the
 * sensitive actions, so each of those is listed exactly and only where the role's work needs it. No default role
 * holds `*:disclose_identity` except participant_support (intake) and rights_manager (consent): an owner must
 * issue an explicit, time-bounded grant to disclose a protected identity.
 */
export const DEFAULT_ROLES: readonly RoleSeed[] = [
  { name: 'owner', kinds: ['human'], description: 'Organization owner: full administration, approval, release and spending authority.',
    capabilities: [...all('*'), ...ENGINES.flatMap((e) => ['contact', 'send', 'publish', 'approve', 'spend', 'grant', 'admin', 'export', 'withdraw'].map((a) => `${e}:${a}`))] },
  { name: 'admin', kinds: ['human'], description: 'Manages members, projects, compartments, agents and workspace settings; no content authority.',
    capabilities: [...eng('identity', 'admin', 'export'), ...eng('orchestration', 'admin'), ...eng('workspace', 'admin'), ...eng('resources', 'admin')] },
  { name: 'investigator', kinds: ['human'], description: 'Researches: discovery, evidence, processing, knowledge and investigation.',
    capabilities: [...DIR, 'discovery:*', 'evidence:*', 'processing:*', 'knowledge:*', 'investigation:*', ...read('intake', 'correspondence', 'consent', 'resources', 'editorial')] },
  { name: 'evidence_manager', kinds: ['human'], description: 'Custody of evidence, including export.',
    capabilities: [...DIR, ...eng('evidence', 'export'), 'processing:*', ...read('knowledge', 'consent', 'investigation')] },
  { name: 'correspondent', kinds: ['human'], description: 'Contacts people and institutions and sends correspondence.',
    capabilities: [...DIR, ...eng('correspondence', 'contact', 'send'), 'intake:read', 'intake:contact', ...read('consent', 'evidence', 'investigation', 'knowledge')] },
  { name: 'editor', kinds: ['human'], description: 'Edits and approves editorial work and claims.',
    capabilities: [...DIR, ...eng('editorial', 'approve'), ...eng('knowledge', 'approve'), ...read('investigation', 'evidence', 'production', 'consent')] },
  { name: 'producer', kinds: ['human'], description: 'Produces renders and assets.',
    capabilities: [...DIR, 'production:*', ...read('editorial', 'evidence', 'knowledge', 'consent', 'resources')] },
  { name: 'reviewer', kinds: ['human'], description: 'Reviews and approves; cannot author, publish or contact.',
    capabilities: [...DIR, ...read('evidence', 'knowledge', 'investigation', 'editorial', 'production', 'consent', 'release'), 'knowledge:approve', 'investigation:approve', 'editorial:approve', 'production:approve'] },
  { name: 'rights_manager', kinds: ['human'], description: 'Consent, permissions and rights, including withdrawal handling.',
    capabilities: [...DIR, ...eng('consent', 'approve', 'withdraw', 'disclose_identity'), ...read('intake', 'evidence', 'editorial', 'production', 'release')] },
  { name: 'release_manager', kinds: ['human'], description: 'Approves, publishes and withdraws releases.',
    capabilities: [...DIR, ...eng('release', 'approve', 'publish', 'withdraw', 'export'), ...read('production', 'editorial', 'consent', 'knowledge')] },
  { name: 'finance', kinds: ['human'], description: 'Budgets and spending.',
    capabilities: [...DIR, ...eng('resources', 'approve', 'spend', 'export')] },
  { name: 'auditor', kinds: ['human'], description: 'Read-only access and audit trails; no export.',
    capabilities: [...all('read'), ...all('audit')] },
  { name: 'participant_support', kinds: ['human'], description: 'Supports intake participants; may contact them and see protected identities.',
    capabilities: [...DIR, ...eng('intake', 'contact', 'disclose_identity'), 'consent:*', 'consent:withdraw', 'correspondence:read'] },
  { name: 'agent_researcher', kinds: ['agent'], description: 'Research agent: no disclosure, contact, publication, approval or spending.',
    capabilities: ['discovery:*', 'processing:*', 'knowledge:*', 'investigation:*', 'evidence:*', 'workspace:*', 'orchestration:read'] },
  { name: 'agent_drafter', kinds: ['agent'], description: 'Drafting agent: drafts editorial text and correspondence; never sends.',
    capabilities: ['editorial:*', 'correspondence:read', 'correspondence:draft', ...read('knowledge', 'evidence', 'investigation'), 'workspace:*'] },
  { name: 'agent_producer', kinds: ['agent'], description: 'Production agent: renders and assets.',
    capabilities: ['production:*', ...read('editorial', 'evidence', 'knowledge'), 'workspace:*'] },
  { name: 'service_orchestrator', kinds: ['service'], description: 'Orchestration service: runs engine work, reads event feeds and issues bounded agent tokens.',
    capabilities: [...all('*'), ...all('events'), 'identity:issue_token'] },
  { name: 'service_event_reader', kinds: ['service'], description: 'Reads engine event feeds only.', capabilities: all('events') },
  { name: 'service_connector', kinds: ['service'], description: 'Federated upstream service connection (for example intake): read-only by default.',
    capabilities: ['intake:read', 'identity:read'] },
];

export type PurposeSeed = Readonly<{ name: string; description: string; capabilities: readonly string[] }>;
/** A token is issued for exactly one purpose; its capabilities are (role capabilities ∩ purpose capabilities) ∪ purpose-matching grants. */
export const DEFAULT_PURPOSES: readonly PurposeSeed[] = [
  { name: 'research', description: 'Investigation and analysis. Carries no disclosure, contact, publication, approval, export or spending authority.',
    capabilities: ['discovery:*', 'evidence:*', 'processing:*', 'knowledge:*', 'investigation:*', ...read('intake', 'correspondence', 'consent', 'resources', 'editorial', 'identity', 'orchestration'), 'workspace:*'] },
  { name: 'correspondence', description: 'Contacting people and sending correspondence.',
    capabilities: [...eng('correspondence', 'contact', 'send'), 'intake:read', 'intake:contact', ...read('consent', 'evidence', 'investigation', 'knowledge', 'identity', 'orchestration'), 'workspace:*'] },
  { name: 'editorial', description: 'Writing, editing and approving editorial work.',
    capabilities: [...eng('editorial', 'approve'), ...eng('knowledge', 'approve'), 'investigation:approve', ...read('investigation', 'evidence', 'production', 'consent', 'identity', 'orchestration', 'correspondence'), 'workspace:*'] },
  { name: 'production', description: 'Producing and approving renders.',
    capabilities: [...eng('production', 'approve'), ...read('editorial', 'evidence', 'knowledge', 'consent', 'resources', 'identity', 'orchestration'), 'workspace:*'] },
  { name: 'release', description: 'Approving, publishing and withdrawing releases.',
    capabilities: [...eng('release', 'approve', 'publish', 'withdraw', 'export'), ...read('production', 'editorial', 'consent', 'knowledge', 'identity', 'orchestration'), 'workspace:*'] },
  { name: 'rights', description: 'Consent and rights management.',
    capabilities: [...eng('consent', 'approve', 'withdraw', 'disclose_identity'), ...read('intake', 'evidence', 'editorial', 'production', 'release', 'identity', 'orchestration'), 'workspace:*'] },
  { name: 'participant_support', description: 'Supporting intake participants.',
    capabilities: [...eng('intake', 'contact', 'disclose_identity'), 'consent:*', 'consent:withdraw', ...read('correspondence', 'identity', 'orchestration'), 'workspace:*'] },
  { name: 'evidence_management', description: 'Evidence custody and export.',
    capabilities: [...eng('evidence', 'export'), 'processing:*', ...read('knowledge', 'consent', 'investigation', 'identity', 'orchestration'), 'workspace:*'] },
  { name: 'finance', description: 'Budgets and spending.', capabilities: [...eng('resources', 'approve', 'spend', 'export'), ...read('orchestration', 'identity'), 'workspace:*'] },
  { name: 'administration', description: 'Organization administration.',
    capabilities: [...eng('identity', 'admin', 'grant', 'export'), ...eng('orchestration', 'admin'), ...eng('workspace', 'admin'), ...eng('resources', 'admin')] },
  { name: 'audit', description: 'Read-only review and audit trails.', capabilities: [...all('read'), ...all('audit')] },
  { name: 'workspace', description: 'General browsing in the workspace: read-only across engines.', capabilities: [...all('read'), 'workspace:*'] },
  { name: 'operations', description: 'Service-to-service operation: engine work, event feeds and bounded agent-token issuance.',
    capabilities: [...all('*'), ...all('events'), 'identity:issue_token'] },
];
