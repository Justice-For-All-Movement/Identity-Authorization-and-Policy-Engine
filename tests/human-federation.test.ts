import test from "node:test";
import assert from "node:assert/strict";
import {
  createHumanFederationProvider,
  type HumanFederationClaims,
} from "../src/human-federation.ts";

const now = "2026-11-04T20:00:00.000Z";
const claims: HumanFederationClaims = {
  issuer: "https://identity.example/",
  subject: "provider-subject",
  audience: "private-console",
  authenticatedAt: "2026-11-04T19:55:00.000Z",
  expiresAt: "2026-11-04T20:05:00.000Z",
  requestId: "request-1",
  csrfToken: "c".repeat(40),
};
const policy = {
  mappings: [
    {
      issuer: claims.issuer,
      subject: claims.subject,
      audience: claims.audience,
      actorId: "local-human",
      enabled: true,
    },
  ],
  maxSessionAgeSeconds: 600,
};
const metadata = {
  url: "https://private.example/session",
  method: "GET",
  headers: new Headers({ cookie: "fictional" }),
};

test("trusted issuer subject and audience map to only a local actor identity", async () => {
  const provider = createHumanFederationProvider(
    { verify: async () => ({ ...claims }) },
    policy,
    () => now,
  );
  assert.deepEqual(
    await provider.authenticate(metadata, new AbortController().signal),
    {
      actorId: "local-human",
      requestId: claims.requestId,
      csrfToken: claims.csrfToken,
    },
  );
});

test("provider roles scope and unknown fields cannot cross the federation boundary", async () => {
  for (const injected of [
    { ...claims, roles: ["owner"] },
    { ...claims, tenantId: "foreign" },
    { ...claims, actorId: "owner" },
  ]) {
    const provider = createHumanFederationProvider(
      { verify: async () => injected as HumanFederationClaims },
      policy,
      () => now,
    );
    await assert.rejects(
      provider.authenticate(metadata, new AbortController().signal),
      { code: "authentication_unavailable" },
    );
  }
});

test("unmapped stale expired future and wrong-audience claims fail closed", async () => {
  const invalid = [
    { ...claims, subject: "unknown" },
    { ...claims, audience: "other-client" },
    { ...claims, authenticatedAt: "2026-11-04T19:49:59.999Z" },
    { ...claims, authenticatedAt: "2026-11-04T20:00:01.000Z" },
    { ...claims, expiresAt: now },
    { ...claims, authenticatedAt: "2026-11-04 19:55:00" },
  ];
  for (const value of invalid) {
    const provider = createHumanFederationProvider(
      { verify: async () => value },
      policy,
      () => now,
    );
    await assert.rejects(
      provider.authenticate(metadata, new AbortController().signal),
      { code: "authentication_unavailable" },
    );
  }
});

test("ambiguous disabled malformed and mutable mappings are rejected before use", async () => {
  const first = policy.mappings[0]!;
  for (const mappings of [
    [...policy.mappings, ...policy.mappings],
    [{ ...first, issuer: "http://identity.example/" }],
    [{ ...first, extra: "claim" }],
  ])
    assert.throws(
      () =>
        createHumanFederationProvider(
          { verify: async () => claims },
          { ...policy, mappings },
          () => now,
        ),
      { code: "invalid_policy" },
    );
  const disabled = createHumanFederationProvider(
    { verify: async () => claims },
    {
      ...policy,
      mappings: [{ ...first, enabled: false }],
    },
    () => now,
  );
  await assert.rejects(
    disabled.authenticate(metadata, new AbortController().signal),
    { code: "authentication_unavailable" },
  );
  const mutable = structuredClone(policy);
  const provider = createHumanFederationProvider(
    { verify: async () => claims },
    mutable,
    () => now,
  );
  mutable.mappings[0]!.actorId = "changed";
  assert.equal(
    (await provider.authenticate(metadata, new AbortController().signal))
      ?.actorId,
    "local-human",
  );
  assert.throws(
    () =>
      createHumanFederationProvider(
        { verify: async () => claims },
        {
          ...policy,
          mappings: [{ ...first, actorId: "a".repeat(129) }],
        },
        () => now,
      ),
    { code: "invalid_policy" },
  );
  assert.throws(
    () => createHumanFederationProvider({} as never, policy, () => now),
    { code: "invalid_policy" },
  );
  assert.throws(
    () =>
      createHumanFederationProvider(
        { verify: async () => claims },
        {
          ...policy,
          mappings: [
            { ...first, actorId: () => "invalid" },
          ] as never,
        },
        () => now,
      ),
    { code: "invalid_policy" },
  );
});

test("verifier refusal cancellation exceptions and invalid exact claims are sanitized", async () => {
  const refusal = createHumanFederationProvider(
    { verify: async () => null },
    policy,
    () => now,
  );
  assert.equal(
    await refusal.authenticate(metadata, new AbortController().signal),
    null,
  );
  const controller = new AbortController();
  controller.abort();
  let calls = 0;
  const cancelled = createHumanFederationProvider(
    {
      verify: async () => {
        calls++;
        return claims;
      },
    },
    policy,
    () => now,
  );
  await assert.rejects(cancelled.authenticate(metadata, controller.signal), {
    code: "authentication_unavailable",
  });
  assert.equal(calls, 0);
  for (const value of [
    { ...claims, csrfToken: "short" },
    { ...claims, expiresAt: "not-a-time" },
  ]) {
    const provider = createHumanFederationProvider(
      { verify: async () => value },
      policy,
      () => now,
    );
    await assert.rejects(provider.authenticate(metadata, new AbortController().signal), {
      code: "authentication_unavailable",
      message: "Federated session unavailable",
    });
  }
  const throwing = createHumanFederationProvider(
    {
      verify: async () => {
        throw Error("private provider diagnostic");
      },
    },
    policy,
    () => now,
  );
  await assert.rejects(
    throwing.authenticate(metadata, new AbortController().signal),
    (error) => {
      assert.equal(String(error).includes("private provider diagnostic"), false);
      return true;
    },
  );
});

test("active abort releases a caller when the verifier never acknowledges cancellation", async () => {
  let entered!: () => void;
  const ready = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const provider = createHumanFederationProvider(
    {
      verify: async () => {
        entered();
        return new Promise(() => {});
      },
    },
    policy,
    () => now,
  );
  const controller = new AbortController();
  const pending = provider.authenticate(metadata, controller.signal);
  await ready;
  controller.abort();
  await assert.rejects(pending, { code: "authentication_unavailable" });
});
