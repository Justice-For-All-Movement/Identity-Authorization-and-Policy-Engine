import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { Database } from "@accountability/evidence/database";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import { MembershipRegistry } from "../src/membership.ts";
import { RevocationRegistry } from "../src/revocations.ts";
import { issueCapability } from "../src/index.ts";
import type { Capability } from "../src/index.ts";
import { c, actor, fixture } from "./member-capability-fixture.ts";
const expected = { action: "process" as const, resourceId: "document" };
async function setup(t: test.TestContext) {
  const f = await fixture(t),
    key = randomBytes(32);
  const revocations = new RevocationRegistry(
    f.db,
    { ...f.policy, administratorIds: ["owner"] },
    () => f.clock.now,
  );
  await revocations.initialize(c, "revocations-init");
  await f.registry.apply(
    c,
    1,
    { type: "set-member", id: "reader", kind: "human", roles: ["researcher"] },
    "reader",
  );
  const profile: Capability = {
    tenantId: c.tenantId,
    projectId: c.projectId,
    id: "grant",
    actorId: "reader",
    action: "process",
    purpose: c.purpose,
    resourceIds: ["document"],
    policyRevision: 1,
    actorEpoch: 0,
    notBefore: c.now,
    expiresAt: "2026-01-01T00:10:00Z",
  };
  return {
    ...f,
    key,
    revocations,
    profile,
    token: issueCapability(c, profile, key),
  };
}
test("current membership roles and signed revocations are checked together without caller role authority", async (t) => {
  const f = await setup(t);
  const result = await f.registry.verifyCapability(
    actor("reader"),
    f.token,
    expected,
    f.key,
  );
  assert.deepEqual(result, {
    membershipRevision: 2,
    memberEpoch: 1,
    capability: f.profile,
  });
  await f.registry.apply(
    c,
    2,
    { type: "set-member", id: "reader", kind: "human", roles: ["viewer"] },
    "demote",
  );
  await assert.rejects(
    f.registry.verifyCapability(
      actor("reader", "human", ["owner"]),
      f.token,
      expected,
      f.key,
    ),
    { code: "forbidden" },
  );
  await f.registry.apply(
    c,
    3,
    { type: "disable-member", id: "reader" },
    "disable",
  );
  await assert.rejects(
    f.registry.verifyCapability(
      actor("reader", "human", ["owner"]),
      f.token,
      expected,
      f.key,
    ),
    { code: "member_denied" },
  );
});
test("policy, actor and exact token revocations deny the integrated check", async (t) => {
  const f = await setup(t);
  await f.revocations.apply(
    c,
    1,
    { type: "revoke-capability", id: "grant" },
    "revoke",
  );
  await assert.rejects(
    f.registry.verifyCapability(actor("reader"), f.token, expected, f.key),
    { code: "revoked_capability" },
  );
  const next = issueCapability(c, { ...f.profile, id: "another" }, f.key);
  await f.revocations.apply(
    c,
    2,
    { type: "advance-actor", actorId: "reader" },
    "epoch",
  );
  await assert.rejects(
    f.registry.verifyCapability(actor("reader"), next, expected, f.key),
    { code: "revoked_capability" },
  );
  const current = issueCapability(
    c,
    { ...f.profile, id: "current", actorEpoch: 1 },
    f.key,
  );
  await f.registry.verifyCapability(actor("reader"), current, expected, f.key);
  await f.revocations.apply(c, 3, { type: "advance-policy" }, "policy");
  await assert.rejects(
    f.registry.verifyCapability(actor("reader"), current, expected, f.key),
    { code: "revoked_capability" },
  );
  await scoped(f.db, c, async (tx) =>
    assert.ok(verifyAudit(await tx.audits())),
  );
});
test("exact scope/kind/purpose/resource/profile and key bounds fail closed", async (t) => {
  const f = await setup(t);
  for (const context of [
    { ...actor("reader"), projectId: "foreign" },
    actor("reader", "service"),
    { ...actor("reader"), purpose: "different" },
  ])
    await assert.rejects(
      f.registry.verifyCapability(context, f.token, expected, f.key),
    );
  await assert.rejects(
    f.registry.verifyCapability(
      actor("reader"),
      f.token,
      { ...expected, extra: true } as never,
      f.key,
    ),
  );
  await assert.rejects(
    f.registry.verifyCapability(
      actor("reader"),
      f.token,
      { ...expected, resourceId: "foreign" },
      f.key,
    ),
  );
  await assert.rejects(
    f.registry.verifyCapability(
      actor("reader"),
      f.token,
      expected,
      new Uint8Array(31),
    ),
  );
  assert.throws(
    () => issueCapability(c, { ...f.profile, extra: true } as Capability, f.key),
    { code: "invalid_capability" },
  );
  await f.registry.verifyCapability(actor("reader"), f.token, expected, f.key);
});
test("membership re-enable does not silently synchronize the separate capability epoch", async (t) => {
  const f = await setup(t);
  await f.registry.apply(
    c,
    2,
    { type: "disable-member", id: "reader" },
    "disable",
  );
  await f.registry.apply(
    c,
    3,
    { type: "set-member", id: "reader", kind: "human", roles: ["researcher"] },
    "reenable",
  );
  const result = await f.registry.verifyCapability(
    actor("reader"),
    f.token,
    expected,
    f.key,
  );
  assert.equal(result.memberEpoch, 3);
  assert.equal(result.capability.actorEpoch, 0);
  await f.revocations.apply(
    c,
    1,
    { type: "advance-actor", actorId: "reader" },
    "epoch",
  );
  await assert.rejects(
    f.registry.verifyCapability(actor("reader"), f.token, expected, f.key),
  );
});
test("context/key/expected fields are captured before awaits and post-load expiry denies", async (t) => {
  const f = await setup(t);
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>((r) => {
      entered = r;
    }),
    wait = new Promise<void>((r) => {
      release = r;
    });
  const db: Database = {
    transaction: (fn) =>
      f.db.transaction((q) =>
        fn({
          query: async <T>(sql: string, values?: unknown[]) => {
            const result = await q.query<T>(sql, values);
            if (sql.includes("FOR UPDATE")) {
              entered();
              await wait;
            }
            return result;
          },
        }),
      ),
    close: async () => {},
  };
  const context = structuredClone(actor("reader")),
    key = Uint8Array.from(f.key),
    wanted = { ...expected };
  const operation = new MembershipRegistry(
    db,
    f.policy,
    () => f.clock.now,
  ).verifyCapability(context, f.token, wanted, key);
  await ready;
  (context.actor as { id: string }).id = "wrong";
  key.fill(0);
  wanted.resourceId = "wrong";
  release();
  assert.deepEqual((await operation).capability, f.profile);
  f.clock.now = "2026-01-01T00:11:00Z";
  await assert.rejects(
    f.registry.verifyCapability(actor("reader"), f.token, expected, f.key),
    { code: "expired_capability" },
  );
});
test("both stored registries are mandatory; failed signature verification rolls back checked audit", async (t) => {
  const f = await fixture(t),
    key = randomBytes(32);
  await assert.rejects(
    f.registry.verifyCapability(
      c,
      "invalid",
      { action: "read", resourceId: "document" },
      key,
    ),
    { code: "not_initialized" },
  );
  const g = await setup(t);
  let before = 0;
  await scoped(g.db, c, async (tx) => {
    before = (await tx.audits()).length;
  });
  await assert.rejects(
    g.registry.verifyCapability(
      actor("reader"),
      g.token,
      expected,
      randomBytes(32),
    ),
  );
  await scoped(g.db, c, async (tx) =>
    assert.equal((await tx.audits()).length, before),
  );
});
