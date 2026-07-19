export interface BrowserSessionOidc {
  issuer: string;
  subjectDigest: string;
  authenticatedAt: string;
  assurance?: string;
}

export type BrowserSessionStatus = "active" | "revoked" | "expired";

export interface BrowserSessionRecord {
  schemaVersion: "libre-ai.browser-session.v1";
  id: string;
  sessionDigest: string;
  userId: string;
  tenantId: string;
  roles: string[];
  membershipRevision: number;
  oidc: BrowserSessionOidc;
  csrfSecretDigest: string;
  status: BrowserSessionStatus;
  createdAt: string;
  lastSeenAt: string;
  idleExpiresAt: string;
  absoluteExpiresAt: string;
  revokedAt?: string;
  revocationReason?: string;
  revision: number;
}

export interface SessionIdentityFacts {
  userId: string;
  tenantId: string;
  roles: readonly string[];
  membershipRevision: number;
  oidc: BrowserSessionOidc;
}
