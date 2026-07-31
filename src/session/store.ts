import type { BrowserSessionRecord } from "./record";

export type SessionSaveOutcome = "stored" | "revision_conflict";

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
   * operation on the durable side (`UPDATE … WHERE revision = $n`, a Lua script
   * or `WATCH`/`MULTI`), never as a read followed by an unconditional write:
   * every authenticated request is a writer here — resolving a session slides
   * the idle window — so a lost update silently erases a concurrent revocation
   * and the session keeps authenticating.
   */
  save(record: BrowserSessionRecord, expectedRevision: number | null): Promise<SessionSaveOutcome>;
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
