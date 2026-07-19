import { loadCanonicalContractRegistry } from "@libre-ai/contracts";

import type { Clock } from "../clock";
import { hmacSha256Hex, importHmacKey, randomOpaqueValue, sha256Hex } from "./digest";
import type { BrowserSessionRecord, SessionIdentityFacts } from "./record";
import type { SessionStore } from "./store";

export const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
export const ABSOLUTE_LIFETIME_MS = 12 * 60 * 60 * 1000;
export const REFUSAL_RETENTION_MS = 24 * 60 * 60 * 1000;

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
    await this.persist(record);
    return { cookieValue, csrfToken, record: structuredClone(record) };
  }

  async resolveSession(cookieValue: string): Promise<SessionResolution> {
    const record = await this.store.findByDigest(await hmacSha256Hex(this.digestKey, cookieValue));
    if (record === null) {
      return { code: "auth.session_missing", ok: false };
    }
    if (record.status === "revoked") {
      return { code: "auth.session_revoked", ok: false };
    }
    const now = this.clock.now();
    if (record.status === "expired" || this.isExpired(record, now)) {
      if (record.status !== "expired") {
        record.status = "expired";
        record.revision += 1;
        await this.persist(record);
      }
      return { code: "auth.session_expired", ok: false };
    }
    record.lastSeenAt = now.toISOString();
    record.idleExpiresAt = new Date(now.getTime() + IDLE_TIMEOUT_MS).toISOString();
    record.revision += 1;
    await this.persist(record);
    return { ok: true, record: structuredClone(record) };
  }

  async rotateSession(cookieValue: string): Promise<CreatedSession> {
    const resolved = await this.resolveSession(cookieValue);
    if (!resolved.ok) {
      throw new Error(resolved.code);
    }
    const record = resolved.record;
    const nextCookieValue = randomOpaqueValue();
    const nextCsrfToken = randomOpaqueValue();
    record.sessionDigest = await hmacSha256Hex(this.digestKey, nextCookieValue);
    record.csrfSecretDigest = await sha256Hex(nextCsrfToken);
    record.revision += 1;
    await this.persist(record);
    return {
      cookieValue: nextCookieValue,
      csrfToken: nextCsrfToken,
      record: structuredClone(record),
    };
  }

  async revokeSession(cookieValue: string, reason: string): Promise<void> {
    const record = await this.store.findByDigest(await hmacSha256Hex(this.digestKey, cookieValue));
    if (record === null || record.status === "revoked") {
      return;
    }
    record.status = "revoked";
    record.revokedAt = this.clock.now().toISOString();
    record.revocationReason = reason;
    record.revision += 1;
    await this.persist(record);
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

  private async persist(record: BrowserSessionRecord): Promise<void> {
    const validation = this.registry.validate("browser-session.v1.schema.json", record);
    if (!validation.ok) {
      throw new Error("auth.session_facts_invalid");
    }
    await this.store.save(record);
  }
}
