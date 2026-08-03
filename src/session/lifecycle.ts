import { loadCanonicalContractRegistry } from "@libre-ai/contracts";

import type { Clock } from "../clock";
import { hmacSha256Hex, importHmacKey, randomOpaqueValue, sha256Hex } from "./digest";
import type { BrowserSessionRecord, SessionIdentityFacts, SessionRevocationReason } from "./record";
import type { SessionSaveOutcome, SessionStore } from "./store";

export const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
export const ABSOLUTE_LIFETIME_MS = 12 * 60 * 60 * 1000;
export const REFUSAL_RETENTION_MS = 24 * 60 * 60 * 1000;

// The reason written when the caller's own is not one `browser-session.v1`
// accepts. Not a fallback for convenience: see `canonicalRevocationReason`.
export const CANONICAL_REVOCATION_REASON: SessionRevocationReason = "auth.session_revoked";

// `revocationReason` in browser-session.v1. The literal is a copy, so the
// tests pin it to its source rather than to itself: `a revocation with …
// closes the session` validates the record this produces through the contract
// registry, and fails if the canonical pattern moves away from this one.
const REVOCATION_REASON_PATTERN = /^auth\.[a-z0-9_.-]+$/;

/**
 * Total, and deliberately so. The type above narrows the shape for a
 * TypeScript caller; nothing narrows it for a JavaScript one, or for a
 * `string` widened at some other boundary. Refusing an unusable reason would
 * mean a revocation call that ends with the session still authenticating —
 * the exact failure this whole branch exists to remove — so the malformed
 * reason is replaced instead. Losing the caller's wording is a lesser harm
 * than losing the logout, and the wording is evidence, not a decision: no
 * refusal is ever taken on it.
 */
function canonicalRevocationReason(reason: SessionRevocationReason): SessionRevocationReason {
  return REVOCATION_REASON_PATTERN.test(reason) ? reason : CANONICAL_REVOCATION_REASON;
}

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
      if (!this.isContractConform(stored)) {
        // A stored record `browser-session.v1` no longer accepts: a row
        // written before a role left the enumeration, a migration in flight.
        // Nothing downstream can use it — it cannot be slid, rotated, or
        // projected to the browser — and until this gate the only thing
        // stopping it was `persist()` throwing out of a read. A refusal is
        // the fail-closed reading, and it reuses a code from the locked
        // table: for this cookie there is no usable session, which discloses
        // nothing an attacker could not already infer.
        //
        // It refuses rather than revokes on purpose. Revocation is terminal,
        // so auto-revoking here would turn a repairable data defect — a
        // migration halfway through a fleet — into an irreversible mass
        // logout. `revokeSession` still lands on such a record, so an
        // operator keeps the terminal move.
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
  //
  // Nothing on this path can refuse or throw of its own accord, and that is
  // the property, not a convenience: every refusal removed from here is a
  // caller that would otherwise have cleared a cookie for a logout the server
  // never performed. Only the adapter can still fail, and the boundary
  // answers a problem when it does rather than a 204.
  async revokeSession(cookieValue: string, reason: SessionRevocationReason): Promise<void> {
    // Canonicalised before the record is even read, so no decision below can
    // depend on the caller's spelling.
    const revocationReason = canonicalRevocationReason(reason);
    const sessionDigest = await hmacSha256Hex(this.digestKey, cookieValue);
    const stored = await this.store.findByDigest(sessionDigest);
    // Nothing left for this cookie to authenticate: revocation is idempotent.
    if (stored === null || stored.status === "revoked") {
      return;
    }
    // Only what this write produces is checked, and it is conform by
    // construction: a canonical reason, and a timestamp from the clock. The
    // stored record is deliberately not validated here — `revoke()` does not
    // rewrite it, and gating the logout on the conformity of fields this
    // write never touches is what left a legacy row unclosable.
    await this.store.revoke(stored.id, {
      revocationReason,
      revokedAt: this.clock.now().toISOString(),
    });
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

  private isContractConform(record: BrowserSessionRecord): boolean {
    return this.registry.validate("browser-session.v1.schema.json", record).ok;
  }

  private assertContractConform(record: BrowserSessionRecord): void {
    if (!this.isContractConform(record)) {
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
