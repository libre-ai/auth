export interface OidcTransactionRecord {
  cookieDigest: string;
  expiresAtMs: number;
  nonce: string;
  state: string;
  verifier: string;
}

export interface OidcTransactionStore {
  save(record: OidcTransactionRecord): Promise<void>;
  consumeByDigest(cookieDigest: string): Promise<OidcTransactionRecord | null>;
}

export class InMemoryOidcTransactionStore implements OidcTransactionStore {
  private readonly records = new Map<string, OidcTransactionRecord>();

  save(record: OidcTransactionRecord): Promise<void> {
    this.records.set(record.cookieDigest, { ...record });
    return Promise.resolve();
  }

  consumeByDigest(cookieDigest: string): Promise<OidcTransactionRecord | null> {
    const record = this.records.get(cookieDigest);
    this.records.delete(cookieDigest);
    return Promise.resolve(record === undefined ? null : { ...record });
  }
}
