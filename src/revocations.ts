import {
  validateRevocationState,
  verifyStoredCapability,
} from "./stored-capability.ts";
import { scoped } from "@accountability/evidence/database";
import type { Database, UnitOfWork } from "@accountability/evidence/database";
import { ACTIONS, authorize } from "./index.ts";
import type { Action, Capability } from "./index.ts";
import {
  canonical,
  digest,
  invariant,
  nonempty,
  requireScope,
  validTime,
} from "./contracts.ts";
import type { Context, Json, Scope } from "./contracts.ts";
export type RevocationState = Readonly<{
  policyRevision: number;
  actorEpochs: readonly Readonly<{ actorId: string; epoch: number }>[];
  revokedIds: readonly string[];
}>;
export type RevocationSnapshot = Readonly<{
  revision: number;
  state: RevocationState;
}>;
export type RevocationCommand =
  | { type: "advance-policy" }
  | { type: "advance-actor"; actorId: string }
  | { type: "revoke-capability"; id: string };
export type RevocationPolicy = Scope &
  Readonly<{ administratorIds: readonly string[] }>;
const KIND = "identity-revocations",
  KEY = digest({ aggregate: "identity-revocations" });
const json = (value: unknown): Json => JSON.parse(canonical(value));
function increment(value: number) {
  invariant(
    Number.isSafeInteger(value) &&
      value >= 0 &&
      value < Number.MAX_SAFE_INTEGER,
    "revision_exhausted",
    "Monotonic revision exhausted",
  );
  return value + 1;
}
/** Dedicated Identity DB. Context authentication and signing-key custody belong to the host. */
export class RevocationRegistry {
  readonly #db: Database;
  readonly #policy: RevocationPolicy;
  readonly #clock: () => string;
  constructor(db: Database, policy: RevocationPolicy, clock: () => string) {
    this.#db = db;
    this.#policy = structuredClone(policy);
    this.#clock = clock;
    nonempty(policy.tenantId, "Tenant", 128);
    nonempty(policy.projectId, "Project", 128);
    invariant(
      typeof clock === "function" &&
        policy.administratorIds.length > 0 &&
        policy.administratorIds.length <= 128 &&
        new Set(policy.administratorIds).size ===
          policy.administratorIds.length,
      "invalid_policy",
      "Bounded distinct trusted administrators required",
    );
    for (const id of policy.administratorIds)
      nonempty(id, "Administrator", 128);
  }
  #admin(c: Context) {
    requireScope(c, this.#policy);
    authorize(c, "admin");
    validTime(c.now);
    invariant(
      this.#policy.administratorIds.includes(c.actor.id),
      "admin_denied",
      "Listed human administrator required",
    );
  }
  async #get(tx: UnitOfWork): Promise<RevocationSnapshot> {
    const r = await tx.get<RevocationState>(KIND, KEY);
    invariant(r, "not_initialized", "Revocations unavailable");
    invariant(
      Number.isSafeInteger(r.revision) && r.revision > 0,
      "invalid_revocation_state",
      "Positive revocation record revision required",
    );
    const state = structuredClone(r.value);
    validateRevocationState(state);
    return { revision: r.revision, state };
  }
  async initialize(
    context: Context,
    commandId: string,
  ): Promise<RevocationSnapshot> {
    const c = structuredClone(context);
    this.#admin(c);
    return scoped(this.#db, c, async (tx) => {
      await tx.audit("identity.revocations.initialize.checked", {});
      return tx.idempotent(
        commandId,
        json({
          operation: "initialize-revocations",
          purpose: c.purpose,
          actorKind: c.actor.kind,
        }),
        async () => {
          invariant(
            !(await tx.get(KIND, KEY)),
            "already_initialized",
            "Revocations cannot be reset",
          );
          const state: RevocationState = {
            policyRevision: 1,
            actorEpochs: [],
            revokedIds: [],
          };
          const saved = await tx.put(KIND, KEY, 0, json(state));
          await tx.enqueue(
            "identity.revocations.initialized",
            { revision: saved.revision },
            digest({ event: "identity.revocations.initialized" }),
          );
          return json({ revision: saved.revision, state });
        },
      );
    }) as Promise<unknown> as Promise<RevocationSnapshot>;
  }
  async read(context: Context): Promise<RevocationSnapshot> {
    const c = structuredClone(context);
    this.#admin(c);
    return scoped(this.#db, c, (tx) => this.#get(tx));
  }
  async apply(
    context: Context,
    expectedRevision: number,
    supplied: RevocationCommand,
    commandId: string,
  ): Promise<RevocationSnapshot> {
    const c = structuredClone(context),
      command = structuredClone(supplied);
    this.#admin(c);
    invariant(
      Number.isSafeInteger(expectedRevision) && expectedRevision > 0,
      "invalid_revision",
      "Exact positive revision required",
    );
    const fields =
      command.type === "advance-policy"
        ? ["type"]
        : command.type === "advance-actor"
          ? ["type", "actorId"]
          : command.type === "revoke-capability"
            ? ["type", "id"]
            : [];
    invariant(
      fields.length > 0 &&
        Object.keys(command).length === fields.length &&
        fields.every((k) => Object.hasOwn(command, k)),
      "invalid_command",
      "Exact revocation command required",
    );
    if (command.type === "advance-actor")
      nonempty(command.actorId, "Actor", 128);
    if (command.type === "revoke-capability")
      nonempty(command.id, "Capability", 128);
    return scoped(this.#db, c, async (tx) => {
      // Acquire the same project lock as verification, before any cached response.
      await tx.audit("identity.revocations.command.checked", {
        type: command.type,
      });
      await this.#get(tx);
      return tx.idempotent(
        commandId,
        json({
          operation: "change-revocations",
          expectedRevision,
          command,
          purpose: c.purpose,
          actorKind: c.actor.kind,
        }),
        async () => {
          const before = await this.#get(tx);
          invariant(
            before.revision === expectedRevision,
            "revision_conflict",
            "Revocations changed",
          );
          let policyRevision = before.state.policyRevision;
          const actorEpochs = structuredClone([...before.state.actorEpochs]),
            revokedIds = [...before.state.revokedIds];
          if (command.type === "advance-policy")
            policyRevision = increment(policyRevision);
          if (command.type === "advance-actor") {
            const index = actorEpochs.findIndex(
              (a) => a.actorId === command.actorId,
            );
            const epoch = increment(index < 0 ? 0 : actorEpochs[index]!.epoch);
            if (index < 0) {
              invariant(
                actorEpochs.length < 1024,
                "registry_full",
                "Actor epoch budget exhausted",
              );
              actorEpochs.push({ actorId: command.actorId, epoch });
            } else actorEpochs[index] = { actorId: command.actorId, epoch };
          }
          if (command.type === "revoke-capability") {
            invariant(
              revokedIds.length < 4096 && !revokedIds.includes(command.id),
              "revocation_denied",
              "Revocation already recorded or budget exhausted",
            );
            revokedIds.push(command.id);
          }
          const state: RevocationState = {
            policyRevision,
            actorEpochs,
            revokedIds,
          };
          invariant(
            Buffer.byteLength(canonical(state)) <= 1024 * 1024,
            "registry_full",
            "Revocation byte budget exhausted",
          );
          const saved = await tx.put(KIND, KEY, expectedRevision, json(state));
          await tx.audit(
            "identity.revocations.changed",
            json({ revision: saved.revision, command }),
          );
          await tx.enqueue(
            "identity.revocations.changed",
            json({ revision: saved.revision, command }),
            digest({ revision: saved.revision, aggregate: KEY }),
          );
          return json({ revision: saved.revision, state });
        },
      );
    }) as Promise<unknown> as Promise<RevocationSnapshot>;
  }
  async verify(
    context: Context,
    token: string,
    expected: Readonly<{ action: Action; resourceId: string }>,
    secret: Uint8Array,
  ): Promise<Capability> {
    const c = structuredClone(context),
      action = expected.action,
      resourceId = expected.resourceId;
    requireScope(c, this.#policy);
    authorize(c, action);
    nonempty(c.actor.id, "Actor", 128);
    nonempty(resourceId, "Resource", 128);
    validTime(c.now);
    invariant(
      ACTIONS.includes(action) &&
        typeof token === "string" &&
        token.length <= 10000 &&
        secret instanceof Uint8Array &&
        secret.byteLength >= 32 &&
        secret.byteLength <= 4096,
      "invalid_capability",
      "Bounded signed capability required",
    );
    const key = Uint8Array.from(secret);
    try {
      return await scoped(this.#db, c, async (tx) => {
        await tx.audit("identity.capability.checked", { action, resourceId });
        return verifyStoredCapability(
          tx,
          c,
          token,
          action,
          resourceId,
          key,
          this.#clock,
        );
      });
    } finally {
      key.fill(0);
    }
  }
}
