import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { RevocationRegistry } from "../src/revocations.ts";
import { issueCapability } from "../src/index.ts";
import type { Capability } from "../src/index.ts";
import type { Context } from "../src/contracts.ts";
import { digest } from "../src/contracts.ts";
const c: Context = {
  tenantId: "fiction",
  projectId: "identity",
  actor: { id: "owner", kind: "human", roles: ["owner"] },
  purpose: "private-review",
  requestId: "r",
  now: "2026-01-01T00:00:00Z",
};
const viewer: Context = {
  ...c,
  actor: { id: "reader", kind: "human", roles: ["viewer"] },
};
const profile: Capability = {
  tenantId: c.tenantId,
  projectId: c.projectId,
  id: "grant",
  actorId: "reader",
  action: "read",
  purpose: c.purpose,
  resourceIds: ["document"],
  policyRevision: 1,
  actorEpoch: 0,
  notBefore: c.now,
  expiresAt: "2026-01-01T00:10:00Z",
};
const expected = { action: "read" as const, resourceId: "document" };
async function fixture(t: test.TestContext) {
  const pg = new PGlite();
  await pg.exec(
    await readFile(
      new URL(
        "../migrations/001_foundation.sql",
        import.meta.resolve("@accountability/evidence/database"),
      ),
      "utf8",
    ),
  );
  await pg.exec(
    "CREATE ROLE identity_login LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; GRANT evidence_runtime TO identity_login; SET SESSION AUTHORIZATION identity_login",
  );
  const db: Database = {
    transaction: (fn) =>
      pg.transaction((q) =>
        fn({
          query: async <T>(sql: string, v?: unknown[]) => ({
            rows: (await q.query(sql, v)).rows as T[],
          }),
        }),
      ),
    close: () => pg.close(),
  };
  t.after(() => pg.close());
  const policy = {
    tenantId: c.tenantId,
    projectId: c.projectId,
    administratorIds: ["owner"],
  };
  const clock = { now: c.now },
    key = randomBytes(32),
    registry = new RevocationRegistry(db, policy, () => clock.now);
  await registry.initialize(c, "initialize");
  return {
    db,
    policy,
    clock,
    key,
    registry,
    token: issueCapability(c, profile, key),
  };
}
test("durable policy, actor and exact-capability revocations feed current signature verification", async (t) => {
  const f = await fixture(t);
  assert.deepEqual(
    await f.registry.verify(viewer, f.token, expected, f.key),
    profile,
  );
  await f.registry.apply(
    c,
    1,
    { type: "revoke-capability", id: "grant" },
    "revoke",
  );
  await assert.rejects(f.registry.verify(viewer, f.token, expected, f.key), {
    code: "revoked_capability",
  });
  const another = issueCapability(c, { ...profile, id: "another" }, f.key);
  await f.registry.verify(viewer, another, expected, f.key);
  await f.registry.apply(
    c,
    2,
    { type: "advance-actor", actorId: "reader" },
    "epoch",
  );
  await assert.rejects(f.registry.verify(viewer, another, expected, f.key), {
    code: "revoked_capability",
  });
  const current = issueCapability(
    c,
    { ...profile, id: "new", actorEpoch: 1 },
    f.key,
  );
  await f.registry.verify(viewer, current, expected, f.key);
  await f.registry.apply(c, 3, { type: "advance-policy" }, "policy");
  await assert.rejects(f.registry.verify(viewer, current, expected, f.key), {
    code: "revoked_capability",
  });
  assert.equal(
    (await new RevocationRegistry(f.db, f.policy, () => c.now).read(c)).state
      .policyRevision,
    2,
  );
  await scoped(f.db, c, async (tx) =>
    assert.ok(verifyAudit(await tx.audits())),
  );
});
test("current listed human authority gates bootstrap, reads, commands and cached responses", async (t) => {
  const f = await fixture(t);
  await f.registry.apply(c, 1, { type: "advance-policy" }, "change");
  for (const bad of [
    viewer,
    { ...c, actor: { ...c.actor, kind: "service" as const } },
    { ...c, actor: { ...c.actor, id: "unlisted" } },
    { ...c, projectId: "foreign" },
  ]) {
    await assert.rejects(f.registry.initialize(bad, "initialize"));
    await assert.rejects(f.registry.read(bad));
    await assert.rejects(
      f.registry.apply(bad, 1, { type: "advance-policy" }, "change"),
    );
  }
  await assert.rejects(
    new RevocationRegistry(
      f.db,
      { ...f.policy, administratorIds: ["replacement"] },
      () => c.now,
    ).apply(c, 1, { type: "advance-policy" }, "change"),
  );
  await assert.rejects(f.registry.initialize(c, "new-bootstrap"), {
    code: "already_initialized",
  });
  assert.equal((await f.registry.read(c)).revision, 2);
});
test("historical command acknowledgement replays without rolling back state or repeating outbox effects", async (t) => {
  const f = await fixture(t);
  const saved = await f.registry.apply(
    c,
    1,
    { type: "advance-policy" },
    "change",
  );
  await f.registry.apply(
    c,
    2,
    { type: "advance-actor", actorId: "__proto__" },
    "actor",
  );
  assert.deepEqual(
    await f.registry.apply(c, 1, { type: "advance-policy" }, "change"),
    saved,
  );
  assert.equal((await f.registry.read(c)).revision, 3);
  await assert.rejects(
    f.registry.apply(
      { ...c, purpose: "different" },
      1,
      { type: "advance-policy" },
      "change",
    ),
    { code: "idempotency_conflict" },
  );
  await assert.rejects(
    f.registry.apply(
      c,
      1,
      { type: "advance-actor", actorId: "reader" },
      "change",
    ),
    { code: "idempotency_conflict" },
  );
  await scoped(f.db, c, async (tx) =>
    assert.equal(
      (await tx.audits()).filter(
        (a) => a.type === "identity.revocations.changed",
      ).length,
      2,
    ),
  );
});
test("expected revision contenders serialize and fail closed on malformed commands", async (t) => {
  const f = await fixture(t);
  const results = await Promise.allSettled([
    f.registry.apply(c, 1, { type: "advance-policy" }, "a"),
    f.registry.apply(c, 1, { type: "advance-actor", actorId: "reader" }, "b"),
  ]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal((await f.registry.read(c)).revision, 2);
  for (const command of [
    { type: "reset" },
    { type: "advance-policy", extra: true },
    { type: "advance-actor", actorId: "" },
  ])
    await assert.rejects(f.registry.apply(c, 2, command as never, "bad"));
});
test("verification uses post-lock live expiry and current role/scope, never a cached grant", async (t) => {
  const f = await fixture(t);
  f.clock.now = "2026-01-01T00:11:00Z";
  await assert.rejects(f.registry.verify(viewer, f.token, expected, f.key), {
    code: "expired_capability",
  });
  f.clock.now = "2025-12-31T23:59:59Z";
  await assert.rejects(f.registry.verify(viewer, f.token, expected, f.key), {
    code: "invalid_time",
  });
  f.clock.now = c.now;
  await assert.rejects(
    f.registry.verify(
      { ...viewer, actor: { ...viewer.actor, roles: [] } },
      f.token,
      expected,
      f.key,
    ),
  );
  await assert.rejects(
    f.registry.verify(
      { ...viewer, projectId: "foreign" },
      f.token,
      expected,
      f.key,
    ),
  );
  assert.throws(() =>
    issueCapability(
      c,
      { ...profile, extra: "untrusted" } as Capability,
      f.key,
    ),
  );
  assert.deepEqual(
    await f.registry.verify(viewer, f.token, expected, f.key),
    profile,
  );
});
test("lost commit acknowledgement replays durable revocation, while post-outbox failure rolls back atomically", async (t) => {
  const f = await fixture(t);
  for (const afterCommit of [false, true]) {
    let injected = false;
    const db: Database = {
      transaction: async (fn) => {
        let marked = false;
        const value = await f.db.transaction((q) =>
          fn({
            query: async <T>(sql: string, v?: unknown[]) => {
              const result = await q.query<T>(sql, v);
              if (
                sql.includes("INSERT INTO public.evidence_outbox") &&
                v?.includes("identity.revocations.changed")
              ) {
                marked = true;
                if (!afterCommit) {
                  injected = true;
                  throw Error("fixture rollback");
                }
              }
              return result;
            },
          }),
        );
        if (afterCommit && marked && !injected) {
          injected = true;
          throw Error("fixture lost acknowledgement");
        }
        return value;
      },
      close: async () => {},
    };
    const registry = new RevocationRegistry(db, f.policy, () => c.now);
    await assert.rejects(
      registry.apply(
        c,
        1,
        { type: "revoke-capability", id: "grant" },
        "revocation",
      ),
    );
    assert.equal(injected, true);
    assert.equal((await f.registry.read(c)).revision, afterCommit ? 2 : 1);
    if (afterCommit) {
      await assert.rejects(f.registry.verify(viewer, f.token, expected, f.key));
      assert.equal(
        (
          await registry.apply(
            c,
            1,
            { type: "revoke-capability", id: "grant" },
            "revocation",
          )
        ).revision,
        2,
      );
    }
  }
});

test("clock is sampled after policy loading, and captured key/context survive caller mutation", async (t) => {
  const f = await fixture(t);
  let switched = false;
  const db: Database = {
    transaction: (fn) =>
      f.db.transaction((q) =>
        fn({
          query: async <T>(sql: string, v?: unknown[]) => {
            const r = await q.query<T>(sql, v);
            if (
              sql.includes("SELECT") &&
              sql.includes("FROM public.evidence_record")
            ) {
              switched = true;
              f.clock.now = "2026-01-01T00:11:00Z";
            }
            return r;
          },
        }),
      ),
    close: async () => {},
  };
  await assert.rejects(
    new RevocationRegistry(db, f.policy, () => f.clock.now).verify(
      viewer,
      f.token,
      expected,
      f.key,
    ),
    { code: "expired_capability" },
  );
  assert.equal(switched, true);
  f.clock.now = c.now;
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>((r) => {
      entered = r;
    }),
    wait = new Promise<void>((r) => {
      release = r;
    });
  const delayed: Database = {
    transaction: (fn) =>
      f.db.transaction((q) =>
        fn({
          query: async <T>(sql: string, v?: unknown[]) => {
            const r = await q.query<T>(sql, v);
            if (sql.includes("FOR UPDATE")) {
              entered();
              await wait;
            }
            return r;
          },
        }),
      ),
    close: async () => {},
  };
  const context = structuredClone(viewer),
    key = Uint8Array.from(f.key),
    wanted = { ...expected };
  const op = new RevocationRegistry(delayed, f.policy, () => c.now).verify(
    context,
    f.token,
    wanted,
    key,
  );
  await ready;
  (context.actor as { id: string }).id = "different";
  key.fill(0);
  wanted.resourceId = "different";
  release();
  assert.deepEqual(await op, profile);
});

test("exhausted epochs and bounded registries reject rather than wrap or discard old revocations", async (t) => {
  const f = await fixture(t),
    id = digest({ aggregate: "identity-revocations" });
  const cases = [
    {
      state: {
        policyRevision: Number.MAX_SAFE_INTEGER,
        actorEpochs: [],
        revokedIds: [],
      },
      command: { type: "advance-policy" },
      code: "revision_exhausted",
    },
    {
      state: {
        policyRevision: 1,
        actorEpochs: [{ actorId: "reader", epoch: Number.MAX_SAFE_INTEGER }],
        revokedIds: [],
      },
      command: { type: "advance-actor", actorId: "reader" },
      code: "revision_exhausted",
    },
    {
      state: {
        policyRevision: 1,
        actorEpochs: Array.from({ length: 1024 }, (_, i) => ({
          actorId: `actor-${i}`,
          epoch: 1,
        })),
        revokedIds: [],
      },
      command: { type: "advance-actor", actorId: "new" },
      code: "registry_full",
    },
    {
      state: {
        policyRevision: 1,
        actorEpochs: [],
        revokedIds: Array.from({ length: 4096 }, (_, i) => `grant-${i}`),
      },
      command: { type: "revoke-capability", id: "new" },
      code: "revocation_denied",
    },
  ];
  for (const item of cases) {
    const previous = await f.registry.read(c);
    await scoped(f.db, c, (tx) =>
      tx.put("identity-revocations", id, previous.revision, item.state),
    );
    const before = await f.registry.read(c);
    await assert.rejects(
      f.registry.apply(c, before.revision, item.command as never, "capacity"),
      { code: item.code },
    );
    assert.deepEqual(await f.registry.read(c), before);
  }
});
