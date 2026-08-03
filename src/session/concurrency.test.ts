import { describe, expect, test } from "bun:test";

import type { Clock } from "../clock";
import { SessionService } from "./lifecycle";
import type { BrowserSessionRecord, SessionRevocationReason } from "./record";
import type { SessionRevokeOutcome, SessionSaveOutcome, SessionStore } from "./store";

// Stand-in for the durable adapters this port exists for (Postgres, Redis):
// a write is issued at one instant and lands at another. The test releases
// each landing explicitly, so the interleaving is deterministic rather than
// timing-dependent. `InMemorySessionStore` cannot express this class of
// defect at all — its write window is zero, which is exactly why the rest of
// the suite stays green while the session store loses updates in production.
class RemoteLatencySessionStore implements SessionStore {
  private readonly records = new Map<string, BrowserSessionRecord>();
  private readonly inFlight: Array<() => void> = [];
  private parkWrites = false;

  findByDigest(sessionDigest: string): Promise<BrowserSessionRecord | null> {
    for (const record of this.records.values()) {
      if (record.sessionDigest === sessionDigest) {
        return Promise.resolve(structuredClone(record));
      }
    }
    return Promise.resolve(null);
  }

  async save(
    record: BrowserSessionRecord,
    expectedRevision: number | null,
  ): Promise<SessionSaveOutcome> {
    await this.roundTrip();
    // A real store evaluates the precondition atomically when the write
    // lands, not when the caller issued it — so the writer that arrives
    // second sees the effect of the first.
    const current = this.records.get(record.id);
    const stale =
      expectedRevision === null
        ? current !== undefined
        : current === undefined || current.revision !== expectedRevision;
    if (stale) {
      return "revision_conflict";
    }
    this.records.set(record.id, structuredClone(record));
    return "stored";
  }

  async revoke(
    id: string,
    revocation: { revocationReason: SessionRevocationReason; revokedAt: string },
  ): Promise<SessionRevokeOutcome> {
    await this.roundTrip();
    const current = this.records.get(id);
    if (current === undefined) {
      return "absent";
    }
    if (current.status === "revoked") {
      return "already_revoked";
    }
    this.records.set(id, {
      ...current,
      revision: current.revision + 1,
      revocationReason: revocation.revocationReason,
      revokedAt: revocation.revokedAt,
      status: "revoked",
    });
    return "revoked";
  }

  removeByIds(ids: readonly string[]): Promise<void> {
    for (const id of ids) {
      this.records.delete(id);
    }
    return Promise.resolve();
  }

  list(): Promise<BrowserSessionRecord[]> {
    return Promise.resolve([...this.records.values()].map((record) => structuredClone(record)));
  }

  dump(): BrowserSessionRecord[] {
    return [...this.records.values()].map((record) => structuredClone(record));
  }

  holdWrites(): void {
    this.parkWrites = true;
  }

  releaseWrites(): void {
    this.parkWrites = false;
    for (const land of this.inFlight.splice(0)) {
      land();
    }
  }

  async waitForInFlight(count: number): Promise<void> {
    const deadline = Date.now() + 2000;
    while (this.inFlight.length < count) {
      if (Date.now() > deadline) {
        throw new Error(`only ${this.inFlight.length} of ${count} writes are in flight`);
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 1));
    }
  }

  // Lands the write issued at `index` (0 = first issued) and leaves the
  // others in flight.
  land(index: number): void {
    const write = this.inFlight[index];
    if (write === undefined) {
      throw new Error(`no write in flight at index ${index}`);
    }
    this.inFlight[index] = () => {};
    write();
  }

  private roundTrip(): Promise<void> {
    if (!this.parkWrites) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.inFlight.push(resolve);
    });
  }
}

interface ContentionOptions {
  // Refuse the absence precondition too, so nothing can be created at all.
  refuseCreation?: boolean;
  // The conflict on which the competing writer is a revocation.
  revokeOnConflict?: number;
  // The conflict on which the competing writer leaves the record outside
  // `browser-session.v1` — a migration dropping a role from the enumeration
  // while this request is in the middle of its retry budget.
  corruptOnConflict?: number;
}

// A durable adapter under sustained contention: a competing writer always
// gets there first, so every compare-and-swap issued against an existing
// record loses. On the conflict numbered `revokeOnConflict` that competing
// writer is a revocation, which is what makes the losing caller's read
// provably stale: the conflict is the store saying "the state you decided on
// is gone".
class ContendedSessionStore implements SessionStore {
  conflicts = 0;
  private readonly records = new Map<string, BrowserSessionRecord>();

  constructor(private readonly options: ContentionOptions = {}) {}

  findByDigest(sessionDigest: string): Promise<BrowserSessionRecord | null> {
    for (const record of this.records.values()) {
      if (record.sessionDigest === sessionDigest) {
        return Promise.resolve(structuredClone(record));
      }
    }
    return Promise.resolve(null);
  }

  save(record: BrowserSessionRecord, expectedRevision: number | null): Promise<SessionSaveOutcome> {
    const current = this.records.get(record.id);
    if (expectedRevision === null) {
      if (current !== undefined || this.options.refuseCreation === true) {
        return Promise.resolve("revision_conflict");
      }
      this.records.set(record.id, structuredClone(record));
      return Promise.resolve("stored");
    }
    if (current === undefined) {
      return Promise.resolve("revision_conflict");
    }
    this.conflicts += 1;
    const moved: BrowserSessionRecord = { ...current, revision: current.revision + 1 };
    if (
      this.options.revokeOnConflict !== undefined &&
      this.conflicts >= this.options.revokeOnConflict
    ) {
      moved.status = "revoked";
      moved.revokedAt = CONTENDED_REVOKED_AT;
      moved.revocationReason = "auth.session_revoked";
    }
    if (
      this.options.corruptOnConflict !== undefined &&
      this.conflicts >= this.options.corruptOnConflict
    ) {
      moved.roles = ["ADMIN"];
    }
    this.records.set(record.id, moved);
    return Promise.resolve("revision_conflict");
  }

  // Unconditional by contract: the competing writer above cannot starve it.
  revoke(
    id: string,
    revocation: { revocationReason: SessionRevocationReason; revokedAt: string },
  ): Promise<SessionRevokeOutcome> {
    const current = this.records.get(id);
    if (current === undefined) {
      return Promise.resolve("absent");
    }
    if (current.status === "revoked") {
      return Promise.resolve("already_revoked");
    }
    this.records.set(id, {
      ...current,
      revision: current.revision + 1,
      revocationReason: revocation.revocationReason,
      revokedAt: revocation.revokedAt,
      status: "revoked",
    });
    return Promise.resolve("revoked");
  }

  removeByIds(ids: readonly string[]): Promise<void> {
    for (const id of ids) {
      this.records.delete(id);
    }
    return Promise.resolve();
  }

  list(): Promise<BrowserSessionRecord[]> {
    return Promise.resolve([...this.records.values()].map((record) => structuredClone(record)));
  }

  dump(): BrowserSessionRecord[] {
    return [...this.records.values()].map((record) => structuredClone(record));
  }
}

const CONTENDED_REVOKED_AT = "2026-07-19T08:00:05.000Z";

function fixedClock(start: string): Clock & { advance(ms: number): void } {
  let current = new Date(start).getTime();
  return {
    advance(ms: number): void {
      current += ms;
    },
    now(): Date {
      return new Date(current);
    },
  };
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

async function makeService(clock: Clock, store: SessionStore): Promise<SessionService> {
  return await SessionService.create({
    clock,
    cookieDigestKey: new Uint8Array(32).fill(7),
    store,
  });
}

describe("revocation under concurrent writes", () => {
  test("a concurrent idle-window slide never resurrects a revoked session", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const store = new RemoteLatencySessionStore();
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);

    store.holdWrites();

    // Any ordinary authenticated request is a writer: it reads the active
    // record and slides the idle window back out.
    const ordinaryRequest = service.resolveSession(created.cookieValue);
    await store.waitForInFlight(1);

    // The revocation reads the same revision the slide is holding.
    const revocation = service.revokeSession(created.cookieValue, "auth.session_revoked");
    await store.waitForInFlight(2);

    // The revocation lands first, the slide lands on top of it.
    store.land(1);
    store.land(0);
    await Promise.all([ordinaryRequest, revocation]);
    store.releaseWrites();

    expect(store.dump()[0]?.status).toBe("revoked");
    expect(await service.resolveSession(created.cookieValue)).toEqual({
      code: "auth.session_revoked",
      ok: false,
    });
  });

  test("a revocation landing after a concurrent slide still succeeds", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const store = new RemoteLatencySessionStore();
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);

    store.holdWrites();
    const ordinaryRequest = service.resolveSession(created.cookieValue);
    await store.waitForInFlight(1);
    const revocation = service.revokeSession(created.cookieValue, "auth.session_revoked");
    await store.waitForInFlight(2);

    // Reverse order: the slide lands first, the revocation on top of it. The
    // ordinary request is served — it read a live session — and the logout
    // that arrives a moment later still closes it.
    store.land(0);
    store.land(1);
    const [resolved] = await Promise.all([ordinaryRequest, revocation]);
    store.releaseWrites();

    expect(resolved.ok).toBeTrue();
    expect(store.dump()[0]?.status).toBe("revoked");
    expect(await service.resolveSession(created.cookieValue)).toEqual({
      code: "auth.session_revoked",
      ok: false,
    });
  });

  test("a slide that runs out of attempts never authenticates against its stale read", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    // The revocation lands as the third slide attempt is refused: from that
    // conflict on, the record this caller read is known to be gone.
    const store = new ContendedSessionStore({ revokeOnConflict: 3 });
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);

    const resolved = await service.resolveSession(created.cookieValue);

    expect(store.conflicts).toBe(3);
    expect(store.dump()[0]?.status).toBe("revoked");
    // Giving up on the slide is fine. Authenticating on a read the store has
    // just declared stale is the bypass this PR exists to close.
    expect(resolved).toEqual({ code: "auth.session_revoked", ok: false });
  });

  test("a slide that runs out of attempts still authenticates a session that is still live", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    // Sustained contention with no revocation: the competing writer only ever
    // moves the revision.
    const store = new ContendedSessionStore();
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);

    const resolved = await service.resolveSession(created.cookieValue);

    expect(store.conflicts).toBe(3);
    expect(resolved.ok).toBeTrue();
    if (!resolved.ok) throw new Error("expected the live session to resolve");
    // The record handed back is the last read, not the state the caller
    // failed to write.
    const persisted = store.dump()[0];
    if (persisted === undefined) throw new Error("expected a stored record");
    expect(resolved.record.revision).toBe(persisted.revision);
    expect(resolved.record.status).toBe("active");
  });

  test("a slide that runs out of attempts never authenticates a record the contract rejects", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    // The record leaves `browser-session.v1` as the third slide attempt is
    // refused, so it is conform on every read the loop validates through
    // `persist()` and non-conform only on the read the decision is taken on.
    const store = new ContendedSessionStore({ corruptOnConflict: 3 });
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);

    const resolved = await service.resolveSession(created.cookieValue);

    expect(store.conflicts).toBe(3);
    // This is the one path that could still answer `ok: true` on a record
    // nothing downstream can use: abandoning the slide skips `persist()`, and
    // with it the only contract check the read path used to have.
    expect(resolved).toEqual({ code: "auth.session_missing", ok: false });
  });

  test("a revocation lands even when every compare-and-swap loses the race", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    // Sustained contention: some other writer always gets there first.
    const store = new ContendedSessionStore();
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);

    await service.revokeSession(created.cookieValue, "auth.session_revoked");

    // Revocation is monotone and terminal: it is the one write that must not
    // be refused because someone else wrote. Refusing it means the user
    // cannot log out.
    expect(store.dump()[0]?.status).toBe("revoked");
    expect(store.dump()[0]?.revocationReason).toBe("auth.session_revoked");
    expect(store.dump()[0]?.revokedAt).toBe(clock.now().toISOString());
    expect(await service.resolveSession(created.cookieValue)).toEqual({
      code: "auth.session_revoked",
      ok: false,
    });
  });

  test("a revocation bumps the revision, so a slide issued before it cannot land after it", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const store = new RemoteLatencySessionStore();
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);
    const before = store.dump()[0]?.revision;

    await service.revokeSession(created.cookieValue, "auth.session_revoked");

    // The unconditional revocation write is what keeps every concurrent
    // compare-and-swap honest: without the bump, a slide holding the
    // pre-revocation revision would still satisfy its precondition.
    expect(store.dump()[0]?.revision).toBe((before ?? 0) + 1);
  });

  test("creation fails closed when its absence precondition does not hold", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const store = new ContendedSessionStore({ refuseCreation: true });
    const service = await makeService(clock, store);

    // Handing back a cookie for a record that was never stored would mint a
    // credential authenticating nothing — and hide the broken adapter.
    await expect(service.createSession(IDENTITY)).rejects.toThrow("auth.session_persist_conflict");
    expect(store.dump()).toHaveLength(0);
  });

  test("rotation fails closed rather than hand back a cookie that was never stored", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const store = new ContendedSessionStore();
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);
    const digestBefore = store.dump()[0]?.sessionDigest;

    await expect(service.rotateSession(created.cookieValue)).rejects.toThrow(
      "auth.session_revision_mismatch",
    );

    // No half-rotation: the stored digest is untouched, so the cookie the
    // caller still holds is the one that keeps working.
    expect(store.dump()).toHaveLength(1);
    expect(store.dump()[0]?.sessionDigest).toBe(digestBefore);
    expect((await service.resolveSession(created.cookieValue)).ok).toBeTrue();
  });

  test("CSRF refresh fails closed rather than hand back a token that was never stored", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const store = new ContendedSessionStore();
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);
    const csrfDigestBefore = store.dump()[0]?.csrfSecretDigest;

    await expect(service.refreshCsrfSecret(created.cookieValue)).rejects.toThrow(
      "auth.session_revision_mismatch",
    );

    // A token whose digest never landed would fail every later CSRF check —
    // a logout the user cannot perform.
    expect(store.dump()[0]?.csrfSecretDigest).toBe(csrfDigestBefore);
  });

  test("a revocation stays idempotent once the record is revoked", async () => {
    const clock = fixedClock("2026-07-19T08:00:00.000Z");
    const store = new RemoteLatencySessionStore();
    const service = await makeService(clock, store);
    const created = await service.createSession(IDENTITY);

    store.holdWrites();
    const ordinaryRequest = service.resolveSession(created.cookieValue);
    await store.waitForInFlight(1);
    const revocation = service.revokeSession(created.cookieValue, "auth.session_revoked");
    await store.waitForInFlight(2);

    // The revocation lands, then a stale slide tries to overwrite it and is
    // refused; a second revocation over the already-revoked record is a
    // no-op that keeps the first revocation's evidence intact.
    store.land(1);
    store.land(0);
    await Promise.all([ordinaryRequest, revocation]);
    store.releaseWrites();
    const afterFirst = store.dump()[0];

    clock.advance(60 * 1000);
    await service.revokeSession(created.cookieValue, "auth.session_revoked_again");

    expect(store.dump()[0]).toEqual(afterFirst);
  });
});
