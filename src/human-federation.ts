import { DomainError, invariant, nonempty, validTime } from "./contracts.ts";
import type {
  HumanSessionProvider,
  SessionMetadata,
} from "./membership-session.ts";

export type HumanFederationClaims = Readonly<{
  issuer: string;
  subject: string;
  audience: string;
  authenticatedAt: string;
  expiresAt: string;
  requestId: string;
  csrfToken: string;
}>;

export type HumanFederationVerifier = Readonly<{
  verify(
    metadata: SessionMetadata,
    signal: AbortSignal,
  ): Promise<HumanFederationClaims | null>;
}>;

export type HumanFederationMapping = Readonly<{
  issuer: string;
  subject: string;
  audience: string;
  actorId: string;
  enabled: boolean;
}>;

export type HumanFederationPolicy = Readonly<{
  mappings: readonly HumanFederationMapping[];
  maxSessionAgeSeconds: number;
}>;

function exactClaims(value: unknown): asserts value is HumanFederationClaims {
  invariant(
    value !== null && typeof value === "object" && !Array.isArray(value),
    "authentication_unavailable",
    "Federated session unavailable",
  );
  const keys = Object.keys(value).sort();
  invariant(
    keys.length === 7 &&
      [
        "audience",
        "authenticatedAt",
        "csrfToken",
        "expiresAt",
        "issuer",
        "requestId",
        "subject",
      ].every((key, index) => keys[index] === key),
    "authentication_unavailable",
    "Federated session unavailable",
  );
}

function issuer(value: unknown): string {
  nonempty(value, "Federation issuer", 512);
  const parsed = new URL(value);
  invariant(
    parsed.protocol === "https:" &&
      !parsed.username &&
      !parsed.password &&
      !parsed.search &&
      !parsed.hash &&
      parsed.href === value,
    "invalid_policy",
    "Exact HTTPS federation issuer required",
  );
  return value;
}

function absoluteTime(value: unknown): number {
  invariant(
    typeof value === "string" &&
      value.length <= 64 &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value),
    "authentication_unavailable",
    "Absolute federation timestamp required",
  );
  return validTime(value);
}

/**
 * Maps a verifier-authenticated issuer/subject pair to one local human actor.
 * The verifier owns protocol and cryptographic validation. No provider claim can
 * supply local scope or roles; the membership session adapter reloads those.
 */
export function createHumanFederationProvider(
  verifier: HumanFederationVerifier,
  configuration: HumanFederationPolicy,
  clock: () => string,
): HumanSessionProvider {
  let mappings: readonly HumanFederationMapping[];
  try {
    invariant(
      verifier !== null &&
        typeof verifier === "object" &&
        typeof verifier.verify === "function" &&
        configuration !== null &&
        typeof configuration === "object" &&
        Array.isArray(configuration.mappings) &&
        configuration.mappings.length > 0 &&
        configuration.mappings.length <= 1024 &&
        Number.isSafeInteger(configuration.maxSessionAgeSeconds) &&
        configuration.maxSessionAgeSeconds >= 1 &&
        configuration.maxSessionAgeSeconds <= 86400 &&
        typeof clock === "function",
      "invalid_policy",
      "Bounded federation policy required",
    );
    mappings = structuredClone(configuration.mappings);
  } catch {
    throw new DomainError("invalid_policy", "Bounded federation policy required");
  }
  const verify = verifier.verify.bind(verifier),
    maxAge = configuration.maxSessionAgeSeconds;
  const seen = new Set<string>();
  try {
    for (const mapping of mappings) {
      invariant(
        mapping &&
          typeof mapping === "object" &&
          Object.keys(mapping).length === 5 &&
          typeof mapping.enabled === "boolean",
        "invalid_policy",
        "Exact federation mappings required",
      );
      const trustedIssuer = issuer(mapping.issuer);
      for (const value of [mapping.subject, mapping.audience])
        nonempty(value, "Federation mapping", 256);
      nonempty(mapping.actorId, "Federation actor", 128);
      const key = JSON.stringify([
        trustedIssuer,
        mapping.subject,
        mapping.audience,
      ]);
      invariant(
        !seen.has(key),
        "invalid_policy",
        "Federation mapping must be unambiguous",
      );
      seen.add(key);
    }
  } catch {
    throw new DomainError("invalid_policy", "Invalid federation mapping");
  }
  return {
    async authenticate(metadata, signal) {
      let interrupt = () => {};
      try {
        invariant(
          !signal.aborted,
          "authentication_unavailable",
          "Federated session unavailable",
        );
        const interrupted = new Promise<never>((_resolve, reject) => {
          interrupt = () =>
            reject(
              new DomainError(
                "authentication_unavailable",
                "Federated session unavailable",
              ),
            );
          signal.addEventListener("abort", interrupt, { once: true });
        });
        const pending = Promise.resolve().then(() => verify(metadata, signal));
        const claims = structuredClone(
          await Promise.race([pending, interrupted]),
        );
        invariant(
          !signal.aborted,
          "authentication_unavailable",
          "Federated session unavailable",
        );
        if (claims === null) return null;
        exactClaims(claims);
        const claimsIssuer = issuer(claims.issuer);
        for (const value of [
          claims.subject,
          claims.audience,
          claims.requestId,
        ])
          nonempty(value, "Federated claim", 256);
        invariant(
          /^[A-Za-z0-9_-]{32,256}$/.test(claims.csrfToken),
          "authentication_unavailable",
          "Federated session unavailable",
        );
        const now = absoluteTime(clock()),
          authenticatedAt = absoluteTime(claims.authenticatedAt),
          expiresAt = absoluteTime(claims.expiresAt);
        invariant(
          authenticatedAt <= now &&
            now < expiresAt &&
            now - authenticatedAt <= maxAge * 1000,
          "authentication_unavailable",
          "Federated session unavailable",
        );
        const mapping = mappings.find(
          (candidate) =>
            candidate.enabled &&
            candidate.issuer === claimsIssuer &&
            candidate.subject === claims.subject &&
            candidate.audience === claims.audience,
        );
        invariant(
          mapping,
          "authentication_unavailable",
          "Federated session unavailable",
        );
        return {
          actorId: mapping.actorId,
          requestId: claims.requestId,
          csrfToken: claims.csrfToken,
        };
      } catch {
        throw new DomainError(
          "authentication_unavailable",
          "Federated session unavailable",
        );
      } finally {
        signal.removeEventListener("abort", interrupt);
      }
    },
  };
}
