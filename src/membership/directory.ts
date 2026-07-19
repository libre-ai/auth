export interface MembershipFacts {
  membershipRevision: number;
  roles: readonly string[];
  tenantId: string;
  userId: string;
}

// Maps an OIDC (issuer, subject) digest to opaque identity facts. The
// durable source of membership belongs to WP-G2-D01; this port keeps I01
// testable and fail-closed: an unknown digest maps to nothing.
export interface MembershipDirectory {
  findBySubjectDigest(subjectDigest: string): Promise<MembershipFacts | null>;
}

export class InMemoryMembershipDirectory implements MembershipDirectory {
  private readonly entries = new Map<string, MembershipFacts>();

  register(subjectDigest: string, facts: MembershipFacts): void {
    this.entries.set(subjectDigest, { ...facts, roles: [...facts.roles] });
  }

  findBySubjectDigest(subjectDigest: string): Promise<MembershipFacts | null> {
    const facts = this.entries.get(subjectDigest);
    return Promise.resolve(facts === undefined ? null : { ...facts, roles: [...facts.roles] });
  }
}
