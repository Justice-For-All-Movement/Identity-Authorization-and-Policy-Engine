import type { UnitOfWork } from "@accountability/evidence/database";
import { verifyCapability } from "./index.ts";
import type { Action, Capability } from "./index.ts";
import { canonical, digest, invariant, nonempty, validTime } from "./contracts.ts";
import type { Context } from "./contracts.ts";
import type { RevocationState } from "./revocations.ts";
function plainRecord(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}
function boundedId(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= 128;
}
export function validateRevocationState(
  value: unknown,
): asserts value is RevocationState {
  invariant(
    plainRecord(value) &&
      Object.keys(value).length === 3 &&
      ["policyRevision", "actorEpochs", "revokedIds"].every((key) =>
        Object.hasOwn(value, key),
      ),
    "invalid_revocation_state",
    "Exact revocation state required",
  );
  invariant(
    Number.isSafeInteger(value.policyRevision) &&
      (value.policyRevision as number) > 0,
    "invalid_revocation_state",
    "Positive policy revision required",
  );
  invariant(
    Array.isArray(value.actorEpochs) && value.actorEpochs.length <= 1024,
    "invalid_revocation_state",
    "Bounded actor epochs required",
  );
  const actorIds: string[] = [];
  for (const entry of value.actorEpochs) {
    invariant(
      plainRecord(entry) &&
        Object.keys(entry).length === 2 &&
        Object.hasOwn(entry, "actorId") &&
        Object.hasOwn(entry, "epoch") &&
        boundedId(entry.actorId) &&
        Number.isSafeInteger(entry.epoch) &&
        (entry.epoch as number) > 0,
      "invalid_revocation_state",
      "Valid actor epoch required",
    );
    actorIds.push(entry.actorId);
  }
  invariant(
    new Set(actorIds).size === actorIds.length,
    "invalid_revocation_state",
    "Distinct actor epochs required",
  );
  invariant(
    Array.isArray(value.revokedIds) &&
      value.revokedIds.length <= 4096 &&
      value.revokedIds.every(boundedId) &&
      new Set(value.revokedIds).size === value.revokedIds.length,
    "invalid_revocation_state",
    "Bounded distinct capability revocations required",
  );
  invariant(
    Buffer.byteLength(canonical(value)) <= 1024 * 1024,
    "invalid_revocation_state",
    "Revocation state byte budget exceeded",
  );
}
// Internal only: caller owns the project lock, principal admission and copied key lifetime.
export async function verifyStoredCapability(
  tx: UnitOfWork,
  c: Context,
  token: string,
  action: Action,
  resourceId: string,
  key: Uint8Array,
  clock: () => string,
): Promise<Capability> {
  const row = await tx.get<RevocationState>(
    "identity-revocations",
    digest({ aggregate: "identity-revocations" }),
  );
  invariant(row, "not_initialized", "Revocations unavailable");
  invariant(
    Number.isSafeInteger(row.revision) && row.revision > 0,
    "invalid_revocation_state",
    "Positive revocation record revision required",
  );
  validateRevocationState(row.value);
  const state = row.value;
  const now = clock();
  invariant(
    validTime(now) >= validTime(c.now),
    "invalid_time",
    "Trusted clock regressed",
  );
  const cap = verifyCapability(
    token,
    { ...c, now },
    {
      action,
      resourceId,
      policyRevision: state.policyRevision,
      actorEpoch:
        state.actorEpochs.find((a) => a.actorId === c.actor.id)?.epoch ?? 0,
      revokedIds: state.revokedIds,
    },
    key,
  );
  // Signed data is still validated before it leaves this boundary.
  invariant(
    Object.keys(cap).length === 11 &&
      [
        "tenantId",
        "projectId",
        "id",
        "actorId",
        "action",
        "purpose",
        "resourceIds",
        "policyRevision",
        "actorEpoch",
        "notBefore",
        "expiresAt",
      ].every((k) => Object.hasOwn(cap, k)),
    "invalid_capability",
    "Exact capability profile required",
  );
  nonempty(cap.id, "Capability", 128);
  invariant(
    cap.resourceIds.length > 0 &&
      cap.resourceIds.length <= 128 &&
      new Set(cap.resourceIds).size === cap.resourceIds.length &&
      validTime(cap.expiresAt) - validTime(cap.notBefore) > 0 &&
      validTime(cap.expiresAt) - validTime(cap.notBefore) <= 3600000,
    "invalid_capability",
    "Bounded capability profile required",
  );
  for (const id of cap.resourceIds) nonempty(id, "Resource", 128);
  return cap;
}
