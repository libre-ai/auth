import { describe, expect, test } from "bun:test";

import type { Clock } from "../clock";
import { SessionService } from "./lifecycle";
import type { BrowserSessionRecord } from "./record";
import type { SessionSaveOutcome, SessionStore } from "./store";

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

    // Reverse order: the slide lands first, the revocation on top of it.
    // The slide leaves the revision untouched by design, so the revocation's
    // precondition still holds — a revocation is never refused because an
    // ordinary request happened to touch the session first.
    store.land(0);
    store.land(1);
    const [resolved, outcome] = await Promise.all([ordinaryRequest, revocation]);
    store.releaseWrites();

    expect(resolved.ok).toBeTrue();
    expect(outcome).toEqual({ ok: true });
    expect(store.dump()[0]?.status).toBe("revoked");
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
    // no-op success.
    store.land(1);
    store.land(0);
    await Promise.all([ordinaryRequest, revocation]);
    store.releaseWrites();

    expect(await revocation).toEqual({ ok: true });
    expect(await service.revokeSession(created.cookieValue, "auth.session_revoked")).toEqual({
      ok: true,
    });
  });
});
