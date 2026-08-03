import type { BrowserSessionRecord } from "./record";

export type SessionSaveOutcome = "stored" | "revision_conflict";

export type SessionRevokeOutcome = "revoked" | "already_revoked" | "absent";

export interface SessionStore {
  findByDigest(sessionDigest: string): Promise<BrowserSessionRecord | null>;
  /**
   * Compare-and-swap write. `expectedRevision` is the revision the caller
   * observed when it read the record: `null` requires the record to be absent
   * (creation), a number requires the stored record to still sit at exactly
   * that revision. A caller that lost the race gets `revision_conflict` and no
   * write.
   *
   * Adapters MUST evaluate the precondition and apply the write as one atomic
   * operation on the durable side, never as a read followed by an
   * unconditional write: every authenticated request is a writer here —
   * resolving a session slides the idle window — so a lost update silently
   * erases a concurrent revocation and the session keeps authenticating.
   *
   * ```sql
   * -- expectedRevision = n (update)
   * UPDATE browser_sessions SET … , revision = $2
   *  WHERE id = $1 AND revision = $3;              -- $3 = expectedRevision
   * -- 0 rows affected → "revision_conflict"
   *
   * -- expectedRevision = null (creation): an absence requirement, NOT
   * -- `WHERE revision IS NULL` — the row does not exist, so no predicate on
   * -- its columns can ever match and such an adapter creates nothing.
   * INSERT INTO browser_sessions (…) VALUES (…)
   *   ON CONFLICT (id) DO NOTHING;
   * -- 0 rows affected → "revision_conflict"
   * ```
   */
  save(record: BrowserSessionRecord, expectedRevision: number | null): Promise<SessionSaveOutcome>;
  /**
   * Terminal, monotone write: marks the record revoked whatever its current
   * revision. It is deliberately NOT a compare-and-swap — a concurrent writer
   * cannot make a revocation wrong, and refusing it would mean a user who
   * cannot log out while other requests keep touching the session.
   *
   * Adapters MUST apply it as one atomic operation, guard only the terminal
   * state, and **bump the revision themselves**. That bump is what makes every
   * compare-and-swap issued before it — an idle-window slide, a rotation —
   * conflict instead of writing the pre-revocation state back.
   *
   * ```sql
   * UPDATE browser_sessions
   *    SET status = 'revoked', revoked_at = $2, revocation_reason = $3,
   *        revision = revision + 1
   *  WHERE id = $1 AND status <> 'revoked';
   * -- 1 row → "revoked"; 0 rows → "already_revoked" (or "absent")
   * ```
   */
  revoke(
    id: string,
    revocation: { revocationReason: string; revokedAt: string },
  ): Promise<SessionRevokeOutcome>;
  /**
   * The one mutator without a precondition, and the only one that needs none:
   * it is a deletion of records the service has already found past their
   * refusal-evidence retention (`pruneExpired`), i.e. at least 24 hours past
   * the expiry of a terminal or long-dead session. It is not a state
   * transition, so it cannot resurrect anything or erase a decision; the worst
   * a race can do is delete a record another writer just touched, which leaves
   * the cookie authenticating nothing. Adapters MUST NOT widen it into a
   * general delete used by any other path.
   */
  removeByIds(ids: readonly string[]): Promise<void>;
  list(): Promise<BrowserSessionRecord[]>;
}

export class InMemorySessionStore implements SessionStore {
  private readonly records = new Map<string, BrowserSessionRecord>();

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
    const stale =
      expectedRevision === null
        ? current !== undefined
        : current === undefined || current.revision !== expectedRevision;
    if (stale) {
      return Promise.resolve("revision_conflict");
    }
    this.records.set(record.id, structuredClone(record));
    return Promise.resolve("stored");
  }

  revoke(
    id: string,
    revocation: { revocationReason: string; revokedAt: string },
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
