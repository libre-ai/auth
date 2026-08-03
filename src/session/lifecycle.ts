import { loadCanonicalContractRegistry } from "@libre-ai/contracts";

import type { Clock } from "../clock";
import { hmacSha256Hex, importHmacKey, randomOpaqueValue, sha256Hex } from "./digest";
import type { BrowserSessionRecord, SessionIdentityFacts } from "./record";
import type { SessionSaveOutcome, SessionStore } from "./store";

export const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
export const ABSOLUTE_LIFETIME_MS = 12 * 60 * 60 * 1000;
export const REFUSAL_RETENTION_MS = 24 * 60 * 60 * 1000;

// Budget for the compare-and-swap writes only — revocation is not one of them
// (see `revokeSession`). A conflict means another writer moved the record
// between our read and our write, so the next attempt starts from the state
// that writer left behind. Contention on a single session row is bounded by
// the number of concurrent requests carrying the same cookie; a handful of
// attempts absorbs the honest cases without turning a contended row into an
// unbounded retry loop.
const MAX_WRITE_ATTEMPTS = 3;

export interface CreatedSession {
  cookieValue: string;
  csrfToken: string;
  record: BrowserSessionRecord;
}

export type SessionResolution =
  | { ok: true; record: BrowserSessionRecord }
  | { ok: false; code: "auth.session_missing" | "auth.session_expired" | "auth.session_revoked" };

interface SessionServiceOptions {
  clock: Clock;
  cookieDigestKey: Uint8Array;
  store: SessionStore;
}

type ContractRegistry = Awaited<ReturnType<typeof loadCanonicalContractRegistry>>;

export class SessionService {
  private constructor(
    private readonly clock: Clock,
    private readonly digestKey: CryptoKey,
    private readonly store: SessionStore,
    private readonly registry: ContractRegistry,
  ) {}

  static async create(options: SessionServiceOptions): Promise<SessionService> {
    const digestKey = await importHmacKey(options.cookieDigestKey);
    const registry = await loadCanonicalContractRegistry();
    return new SessionService(options.clock, digestKey, options.store, registry);
  }

  async createSession(facts: SessionIdentityFacts): Promise<CreatedSession> {
    const now = this.clock.now();
    const cookieValue = randomOpaqueValue();
    const csrfToken = randomOpaqueValue();
    const record: BrowserSessionRecord = {
      absoluteExpiresAt: new Date(now.getTime() + ABSOLUTE_LIFETIME_MS).toISOString(),
      createdAt: now.toISOString(),
      csrfSecretDigest: await sha256Hex(csrfToken),
      id: `urn:libre-ai:session:${randomOpaqueValue()}`,
      idleExpiresAt: new Date(now.getTime() + IDLE_TIMEOUT_MS).toISOString(),
      lastSeenAt: now.toISOString(),
      membershipRevision: facts.membershipRevision,
      oidc: { ...facts.oidc },
      revision: 0,
      roles: [...facts.roles],
      schemaVersion: "libre-ai.browser-session.v1",
      sessionDigest: await hmacSha256Hex(this.digestKey, cookieValue),
      status: "active",
      tenantId: facts.tenantId,
      userId: facts.userId,
    };
    if ((await this.persist(record, null)) !== "stored") {
      throw new Error("auth.session_persist_conflict");
    }
    return { cookieValue, csrfToken, record: structuredClone(record) };
  }

  async resolveSession(cookieValue: string): Promise<SessionResolution> {
    const sessionDigest = await hmacSha256Hex(this.digestKey, cookieValue);
    for (let attempt = 1; ; attempt += 1) {
      const stored = await this.store.findByDigest(sessionDigest);
      if (stored === null) {
        return { code: "auth.session_missing", ok: false };
      }
      if (stored.status === "revoked") {
        return { code: "auth.session_revoked", ok: false };
      }
      const now = this.clock.now();
      if (stored.status === "expired" || this.isExpired(stored, now)) {
        if (stored.status !== "expired") {
          // A conflict here means another writer already moved the record on
          // — including to `revoked`, which must not be overwritten by an
          // expiry marking. The refusal below stands either way.
          await this.persist(
            { ...stored, revision: stored.revision + 1, status: "expired" },
            stored.revision,
          );
        }
        return { code: "auth.session_expired", ok: false };
      }
      if (attempt > MAX_WRITE_ATTEMPTS) {
        // Sustained contention: the slide is abandoned, which only shortens
        // the idle window. The read is never abandoned. Every conflict we
        // observed was the store telling us another writer moved this record
        // — and a revocation is exactly that kind of move — so this iteration
        // re-read and re-ran the refusals above before authenticating.
        // Authenticating on a read a conflict had already invalidated is the
        // bypass this whole precondition exists to close.
        return { ok: true, record: stored };
      }
      // Sliding the idle window is server telemetry, not a client-locked
      // mutation: bumping the optimistic revision here would make every
      // If-Match precondition stale by construction. The revision is still
      // the write precondition — every authenticated request is a writer, so
      // without it this slide would silently overwrite a revocation decided
      // between our read and our write.
      const slid: BrowserSessionRecord = {
        ...stored,
        idleExpiresAt: new Date(now.getTime() + IDLE_TIMEOUT_MS).toISOString(),
        lastSeenAt: now.toISOString(),
      };
      if ((await this.persist(slid, stored.revision)) === "stored") {
        return { ok: true, record: slid };
      }
    }
  }

  async rotateSession(cookieValue: string): Promise<CreatedSession> {
    const resolved = await this.resolveSession(cookieValue);
    if (!resolved.ok) {
      throw new Error(resolved.code);
    }
    const witnessRevision = resolved.record.revision;
    const nextCookieValue = randomOpaqueValue();
    const nextCsrfToken = randomOpaqueValue();
    const record: BrowserSessionRecord = {
      ...resolved.record,
      csrfSecretDigest: await sha256Hex(nextCsrfToken),
      revision: witnessRevision + 1,
      sessionDigest: await hmacSha256Hex(this.digestKey, nextCookieValue),
    };
    // Fail closed rather than hand back a cookie whose digest was never
    // stored: the caller would set a credential that authenticates nothing,
    // while the old cookie stays live.
    if ((await this.persist(record, witnessRevision)) !== "stored") {
      throw new Error("auth.session_revision_mismatch");
    }
    return {
      cookieValue: nextCookieValue,
      csrfToken: nextCsrfToken,
      record: structuredClone(record),
    };
  }

  // Server-side only: gives the document renderer a fresh CSRF token
  // (digest replaced, cookie unchanged) so the raw secret never needs to
  // be stored or read back.
  async refreshCsrfSecret(cookieValue: string): Promise<{ csrfToken: string }> {
    const resolved = await this.resolveSession(cookieValue);
    if (!resolved.ok) {
      throw new Error(resolved.code);
    }
    const witnessRevision = resolved.record.revision;
    const csrfToken = randomOpaqueValue();
    const record: BrowserSessionRecord = {
      ...resolved.record,
      csrfSecretDigest: await sha256Hex(csrfToken),
      revision: witnessRevision + 1,
    };
    // Same reason as rotation: a token whose digest was never stored would
    // fail every later CSRF check.
    if ((await this.persist(record, witnessRevision)) !== "stored") {
      throw new Error("auth.session_revision_mismatch");
    }
    return { csrfToken };
  }

  // Revocation is the one write that is never a compare-and-swap. It is
  // monotone and terminal, so no concurrent writer can make it wrong, and
  // making it lose a race would mean a user who cannot log out while other
  // requests keep touching the session — the most critical write refused
  // under exactly the load that makes it urgent. The store applies it
  // unconditionally (bar the terminal state) and bumps the revision itself,
  // which is what makes every compare-and-swap issued before it conflict
  // instead of writing the pre-revocation state back.
  async revokeSession(cookieValue: string, reason: string): Promise<void> {
    const sessionDigest = await hmacSha256Hex(this.digestKey, cookieValue);
    const stored = await this.store.findByDigest(sessionDigest);
    // Nothing left for this cookie to authenticate: revocation is idempotent.
    if (stored === null || stored.status === "revoked") {
      return;
    }
    const revokedAt = this.clock.now().toISOString();
    // The store owns this write's revision, so the contract check runs on the
    // projection of what we ask it to write: a revocation reason that would
    // make the record violate `browser-session.v1` must not reach the durable
    // side just because this write skips `persist()`.
    this.assertContractConform({
      ...stored,
      revision: stored.revision + 1,
      revocationReason: reason,
      revokedAt,
      status: "revoked",
    });
    await this.store.revoke(stored.id, { revocationReason: reason, revokedAt });
  }

  async pruneExpired(): Promise<void> {
    const now = this.clock.now().getTime();
    const removable: string[] = [];
    for (const record of await this.store.list()) {
      if (now >= this.expiryReference(record) + REFUSAL_RETENTION_MS) {
        removable.push(record.id);
      }
    }
    if (removable.length > 0) {
      await this.store.removeByIds(removable);
    }
  }

  private isExpired(record: BrowserSessionRecord, now: Date): boolean {
    return (
      now.getTime() > new Date(record.idleExpiresAt).getTime() ||
      now.getTime() > new Date(record.absoluteExpiresAt).getTime()
    );
  }

  private expiryReference(record: BrowserSessionRecord): number {
    if (record.status === "revoked" && record.revokedAt !== undefined) {
      return new Date(record.revokedAt).getTime();
    }
    if (record.status === "expired") {
      return Math.min(
        new Date(record.idleExpiresAt).getTime(),
        new Date(record.absoluteExpiresAt).getTime(),
      );
    }
    return new Date(record.absoluteExpiresAt).getTime();
  }

  private assertContractConform(record: BrowserSessionRecord): void {
    const validation = this.registry.validate("browser-session.v1.schema.json", record);
    if (!validation.ok) {
      throw new Error("auth.session_facts_invalid");
    }
  }

  private async persist(
    record: BrowserSessionRecord,
    expectedRevision: number | null,
  ): Promise<SessionSaveOutcome> {
    this.assertContractConform(record);
    return await this.store.save(record, expectedRevision);
  }
}
