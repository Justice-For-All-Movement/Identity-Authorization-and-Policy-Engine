// Shared types and pure policy helpers for the E01 service layer.
import { DomainError, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { SENSITIVE_ACTIONS, requireCapability } from '../service-kit.ts';
import type { ServiceContext, Sql, TokenClaims } from '../service-kit.ts';
import type { CapabilityTransport } from '../intake-service-adapter.ts';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type R = Record<string, any>;
export type ActorKind = 'human' | 'agent' | 'service';
export type IdentityClaims = TokenClaims & Readonly<{ sid?: string }>;

export type EngineConfig = Readonly<{
  /** `iss` of issued tokens. Default `e01-identity`. */
  issuer?: string;
  /** Secret (≥ 32 chars) sealing signing keys and client secrets at rest. Without it tokens cannot be issued. */
  keyEncryptionKey?: string;
  accessTokenTtlSeconds?: number;
  serviceTokenTtlSeconds?: number;
  agentTokenMaxTtlSeconds?: number;
  sessionTtlSeconds?: number;
  sessionIdleSeconds?: number;
  /** Revocation answers are cached per token for this long (default 2000 ms, hard maximum 5000 ms). */
  revocationCacheMs?: number;
  scryptN?: number;
  passwordMinLength?: number;
  lockout?: Readonly<{ maxFailures?: number; baseLockSeconds?: number; maxLockSeconds?: number; windowSeconds?: number }>;
  /** When set, `bootstrapFirstAdministrator` requires this value. The HTTP bootstrap route is disabled without it. */
  bootstrapToken?: string;
  allowOrganizationCreation?: boolean;
  maxGrantSeconds?: number;
  maxAgentGrantSeconds?: number;
  /** Test/development only: permit OIDC issuers' endpoints on loopback HTTP. Never enable in a hosted deployment. */
  oidcAllowInsecureLoopback?: boolean;
  clock?: () => Date;
}>;
export type EnginePorts = Readonly<{
  /** Reads the managed intake credential for a connection from the host's secret store. Never returned to callers. */
  intakeCredentials?: (connectionId: string, signal: AbortSignal) => Promise<string>;
  intakeTransport?: CapabilityTransport;
  oidcFetch?: typeof fetch;
}>;
export type EngineDeps = Readonly<{ sql: Sql; ports?: EnginePorts; config?: EngineConfig }>;

export type DecisionStep = Readonly<{ rule: string; outcome: 'pass' | 'fail' | 'info'; detail: string }>;
export type AccessDecision = Readonly<{
  allowed: boolean; reason: string; policyVersion: string;
  actorId: string; tenantId: string; projectId: string; purpose: string; capability: string; resource: string | null;
  via: Readonly<{ kind: 'role'; roles: readonly string[] } | { kind: 'grant'; grantId: string; bounds: Json; expiresAt: string }> | null;
  trail: readonly DecisionStep[];
}>;
export type IssuedToken = Readonly<{ token: string; tokenId: string; expiresAt: string; actorId: string; tenantId: string; projectId: string; purpose: string; roles: readonly string[]; capabilities: readonly string[]; compartments: readonly string[]; policyVersion: string }>;
export type SessionInfo = Readonly<{ sessionId: string; refreshToken: string; actorId: string; expiresAt: string; boundTenantId: string | null }>;

export const ID = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
export const CAP = /^[a-z][a-z0-9_]*:([a-z][a-z0-9_]*|\*)$/;
export const EXACT_CAP = /^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$/;
/** Never satisfied by `identity:*`, in addition to the kit's sensitive actions. */
export const ENGINE_EXACT_ACTIONS: readonly string[] = ['issue_token'];
/** Agents never hold these actions, by role or by grant, in any engine. */
export const AGENT_FORBIDDEN_ACTIONS: readonly string[] = ['admin', 'grant', 'issue_token', 'events'];
/** Agents hold other sensitive actions only through an explicit grant; these stay human/service-only by default. */
export const AGENT_DEFAULT_DENIED: readonly string[] = ['approve', 'publish', 'disclose_identity'];

export const actionOf = (capability: string): string => capability.slice(capability.indexOf(':') + 1);
export const isSensitive = (capability: string): boolean => { const a = actionOf(capability); return SENSITIVE_ACTIONS.includes(a) || ENGINE_EXACT_ACTIONS.includes(a); };
export function agentForbidden(capability: string): boolean {
  const a = actionOf(capability);
  return AGENT_FORBIDDEN_ACTIONS.includes(a) || /secret|credential|password/.test(a);
}
/** True when the set grants `capability`. A wildcard never grants a sensitive action and `x:*` is only granted by `x:*`. */
export function covers(set: readonly string[], capability: string): boolean {
  if (set.includes(capability)) return true;
  if (capability.endsWith(':*') || isSensitive(capability)) return false;
  return set.includes(`${capability.slice(0, capability.indexOf(':'))}:*`);
}
export function intersect(a: readonly string[], b: readonly string[]): string[] {
  return [...new Set([...a.filter((x) => covers(b, x)), ...b.filter((x) => covers(a, x))])].sort();
}
export function validId(value: unknown, label: string): string {
  invariant(typeof value === 'string' && ID.test(value), 'invalid_input', `${label} must match ${ID.source}`);
  return value;
}
export function validCaps(value: unknown, exact = false): string[] {
  invariant(Array.isArray(value) && value.length <= 400 && value.every((c) => typeof c === 'string' && (exact ? EXACT_CAP : CAP).test(c)), 'invalid_input', exact ? 'Exact capabilities (`engine:action`) required' : 'Capabilities must be `engine:action` or `engine:*`');
  return [...new Set(value as string[])].sort();
}
export function text(value: unknown, label: string, max = 300): string {
  invariant(typeof value === 'string' && value.trim().length > 0 && value.length <= max, 'invalid_input', `${label} is required (at most ${max} characters)`);
  return value.trim();
}
export function jsonObject(value: unknown, label: string): { [key: string]: Json } {
  if (value === undefined || value === null) return {};
  invariant(typeof value === 'object' && !Array.isArray(value) && JSON.stringify(value).length <= 20000, 'invalid_input', `${label} must be a JSON object of at most 20 kB`);
  return JSON.parse(JSON.stringify(value)) as { [key: string]: Json };
}
export const iso = (value: unknown): string => new Date(value as string | Date).toISOString();
export const isoOrNull = (value: unknown): string | null => (value === null || value === undefined ? null : iso(value));
export function futureTime(value: unknown, label: string, now: Date, maxSeconds: number): Date {
  invariant(typeof value === 'string' && Number.isFinite(Date.parse(value)), 'invalid_input', `${label} must be an ISO timestamp`);
  const at = new Date(value);
  invariant(at.getTime() > now.getTime() && at.getTime() - now.getTime() <= maxSeconds * 1000, 'invalid_input', `${label} must be in the future and within ${maxSeconds} seconds`);
  return at;
}
/** Capability check that honours the engine's exact-only actions. Fails closed. */
export function need(ctx: ServiceContext, capability: string): void {
  requireCapability(ctx, capability);
  if (!covers(ctx.capabilities, capability)) throw new DomainError('forbidden', `Missing capability ${capability}`);
  invariant(typeof ctx.actor?.id === 'string' && ctx.actor.id.length > 0, 'unauthenticated', 'Authenticated actor required');
}
export const denied = (message = 'Invalid credentials'): DomainError => new DomainError('unauthenticated', message);
