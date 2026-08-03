export interface BrowserSessionOidc {
  issuer: string;
  subjectDigest: string;
  authenticatedAt: string;
  assurance?: string;
}

export type BrowserSessionStatus = "active" | "revoked" | "expired";

/**
 * The revocation-reason namespace of `browser-session.v1`
 * (`^auth\.[a-z0-9_.-]+$`), as far as the type system can carry it.
 *
 * It is a hint, not a proof: `auth.` followed by anything type-checks, and a
 * JavaScript consumer has no types at all. What it does buy is the mistake
 * that actually happens — `revokeSession(cookie, "user_logout")` no longer
 * compiles. It stays a template literal rather than a closed union because
 * the canonical contract deliberately leaves the namespace open; a union here
 * would be narrower than the contract it serves, and would turn every new
 * operational reason into a package break. The value that reaches the durable
 * side is canonicalised at the one place that writes it.
 */
export type SessionRevocationReason = `auth.${string}`;

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
  revocationReason?: SessionRevocationReason;
  revision: number;
}

export interface SessionIdentityFacts {
  userId: string;
  tenantId: string;
  roles: readonly string[];
  membershipRevision: number;
  oidc: BrowserSessionOidc;
}
