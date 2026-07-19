import { describe, expect, test } from "bun:test";
import { loadCanonicalContractRegistry } from "@libre-ai/contracts";

import type { Clock } from "../clock";
import {
  ABSOLUTE_LIFETIME_MS,
  IDLE_TIMEOUT_MS,
  REFUSAL_RETENTION_MS,
  SessionService,
} from "./lifecycle";
import { InMemorySessionStore } from "./store";

const registry = await loadCanonicalContractRegistry();

function fixedClock(start: string): Clock & { advance(ms: number): void } {
  let current = new Date(start).getTime();
  return {
    now(): Date {
      return new Date(current);
    },
    advance(ms: number): void {
      current += ms;
    },
  };
}

async function makeService(clock: Clock) {
  const store = new InMemorySessionStore();
  const service = await SessionService.create({
    clock,
    cookieDigestKey: new Uint8Array(32).fill(7),
    store,
  });
  return { service, store };
}

const IDENTITY = {
  membershipRevision: 3,
  oidc: {
    authenticatedAt: "2026-07-19T08:00:00.000Z",
    issuer: "https://issuer.test.libre-ai.fr",
    subjectDigest: "a".repeat(64),
  },
  roles: ["member"],
  tenantId: `ten_${"a".repeat(16)}`,
  userId: `usr_${"b".repeat(16)}`,
} as const;

describe("session creation", () => {
  test("creates a contract-conform active record storing digests only", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service, store } = await makeService(clock);

    const created = await service.createSession(IDENTITY);

    expect(created.cookieValue.length).toBeGreaterThanOrEqual(43);
    expect(created.csrfToken.length).toBeGreaterThanOrEqual(43);

    const record = store.dump()[0];
    expect(record).toBeDefined();
    expect(registry.validate("browser-session.v1.schema.json", record)).toEqual({
      ok: true,
      value: record,
    });
    const serialized = JSON.stringify(record);
    expect(serialized).not.toContain(created.cookieValue);
    expect(serialized).not.toContain(created.csrfToken);
    expect(record?.status).toBe("active");
    expect(record?.idleExpiresAt).toBe(
      new Date(clock.now().getTime() + IDLE_TIMEOUT_MS).toISOString(),
    );
    expect(record?.absoluteExpiresAt).toBe(
      new Date(clock.now().getTime() + ABSOLUTE_LIFETIME_MS).toISOString(),
    );
  });

  test("rejects identity facts that violate the locked contract shape", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service } = await makeService(clock);

    await expect(service.createSession({ ...IDENTITY, roles: [] })).rejects.toThrow(
      "auth.session_facts_invalid",
    );
    await expect(service.createSession({ ...IDENTITY, userId: "usr_UPPER" })).rejects.toThrow(
      "auth.session_facts_invalid",
    );
  });
});

describe("session resolution and expiry", () => {
  test("resolves an active session and slides only the idle expiry", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service } = await makeService(clock);
    const created = await service.createSession(IDENTITY);

    clock.advance(10 * 60 * 1000);
    const resolved = await service.resolveSession(created.cookieValue);
    if (!resolved.ok) throw new Error("expected active session");
    expect(resolved.record.lastSeenAt).toBe(clock.now().toISOString());
    expect(resolved.record.idleExpiresAt).toBe(
      new Date(clock.now().getTime() + IDLE_TIMEOUT_MS).toISOString(),
    );
    expect(resolved.record.absoluteExpiresAt).toBe(
      new Date(new Date("2026-07-19T08:00:00.000Z").getTime() + ABSOLUTE_LIFETIME_MS).toISOString(),
    );
  });

  test("unknown cookie refuses with auth.session_missing", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service } = await makeService(clock);
    await service.createSession(IDENTITY);

    const resolved = await service.resolveSession("f".repeat(43));
    expect(resolved).toEqual({ code: "auth.session_missing", ok: false });
  });

  test("idle expiry refuses and persists the expired state", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service, store } = await makeService(clock);
    const created = await service.createSession(IDENTITY);

    clock.advance(IDLE_TIMEOUT_MS + 1);
    const resolved = await service.resolveSession(created.cookieValue);
    expect(resolved).toEqual({ code: "auth.session_expired", ok: false });
    expect(store.dump()[0]?.status).toBe("expired");
  });

  test("absolute expiry refuses even under continuous activity", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service } = await makeService(clock);
    const created = await service.createSession(IDENTITY);

    const steps = Math.floor(ABSOLUTE_LIFETIME_MS / (20 * 60 * 1000));
    for (let index = 0; index < steps; index += 1) {
      clock.advance(20 * 60 * 1000);
      const kept = await service.resolveSession(created.cookieValue);
      if (!kept.ok) throw new Error(`unexpected refusal at step ${index}`);
    }
    clock.advance(21 * 60 * 1000);
    const resolved = await service.resolveSession(created.cookieValue);
    expect(resolved).toEqual({ code: "auth.session_expired", ok: false });
  });
});

describe("revocation and state machine", () => {
  test("revocation invalidates before any later resolution and keeps evidence fields", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service, store } = await makeService(clock);
    const created = await service.createSession(IDENTITY);

    await service.revokeSession(created.cookieValue, "auth.session_revoked");
    const record = store.dump()[0];
    expect(record?.status).toBe("revoked");
    expect(record?.revokedAt).toBe(clock.now().toISOString());
    expect(record?.revocationReason).toBe("auth.session_revoked");
    expect(registry.validate("browser-session.v1.schema.json", record).ok).toBeTrue();

    const resolved = await service.resolveSession(created.cookieValue);
    expect(resolved).toEqual({ code: "auth.session_revoked", ok: false });
  });

  test("revoked and expired sessions never reactivate", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service } = await makeService(clock);
    const created = await service.createSession(IDENTITY);
    await service.revokeSession(created.cookieValue, "auth.session_revoked");

    clock.advance(1000);
    const resolved = await service.resolveSession(created.cookieValue);
    expect(resolved.ok).toBeFalse();
    await expect(service.rotateSession(created.cookieValue)).rejects.toThrow(
      "auth.session_revoked",
    );
  });
});

describe("rotation", () => {
  test("rotation issues a new cookie and CSRF secret and retires the old cookie", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service, store } = await makeService(clock);
    const created = await service.createSession(IDENTITY);

    const rotated = await service.rotateSession(created.cookieValue);
    expect(rotated.cookieValue).not.toBe(created.cookieValue);
    expect(rotated.csrfToken).not.toBe(created.csrfToken);

    const before = await service.resolveSession(created.cookieValue);
    expect(before.ok).toBeFalse();
    const after = await service.resolveSession(rotated.cookieValue);
    expect(after.ok).toBeTrue();

    for (const record of store.dump()) {
      expect(registry.validate("browser-session.v1.schema.json", record).ok).toBeTrue();
    }
  });
});

describe("retention", () => {
  test("expired records remain for refusal evidence until expiry + 24h, then prune", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const { service, store } = await makeService(clock);
    const created = await service.createSession(IDENTITY);

    clock.advance(IDLE_TIMEOUT_MS + 1);
    await service.resolveSession(created.cookieValue);
    expect(store.dump()).toHaveLength(1);

    clock.advance(REFUSAL_RETENTION_MS - 1000);
    await service.pruneExpired();
    expect(store.dump()).toHaveLength(1);

    clock.advance(2000);
    await service.pruneExpired();
    expect(store.dump()).toHaveLength(0);
  });
});
