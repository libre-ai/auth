import type { BrowserSessionRecord } from "./record";

export interface SessionStore {
  findByDigest(sessionDigest: string): Promise<BrowserSessionRecord | null>;
  save(record: BrowserSessionRecord): Promise<void>;
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

  save(record: BrowserSessionRecord): Promise<void> {
    this.records.set(record.id, structuredClone(record));
    return Promise.resolve();
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
