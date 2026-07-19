import type { Clock } from "../clock";
import type { MembershipDirectory } from "../membership/directory";
import { hmacSha256Hex, importHmacKey, randomOpaqueValue, sha256Hex } from "../session/digest";
import type { SessionIdentityFacts } from "../session/record";
import { encodeBase64Url, verifyIdToken } from "./jws";
import type { OidcTransactionStore } from "./transaction-store";

const encoder = new TextEncoder();

export const OIDC_TRANSACTION_LIFETIME_MS = 10 * 60 * 1000;

export interface StartedLogin {
  authorizationUrl: string;
  transactionCookieValue: string;
}

export type CompletedLogin =
  | { ok: true; facts: SessionIdentityFacts }
  | { ok: false; code: "auth.oidc_state_invalid" | "auth.oidc_claim_invalid" };

export type TokenEndpoint = (request: {
  audience: string;
  code: string;
  codeVerifier: string;
}) => Promise<{ ok: true; idToken: string } | { ok: false; code: string }>;

interface OidcLoginFlowOptions {
  audience: string;
  clock: Clock;
  directory: MembershipDirectory;
  issuer: string;
  jwks: () => Promise<{ keys: Array<JsonWebKey & { kid?: string }> }>;
  store: OidcTransactionStore;
  tokenEndpoint: TokenEndpoint;
  transactionDigestKey: Uint8Array;
}

// Confidential provider-neutral BFF login flow: Authorization Code with
// PKCE S256, bounded one-use server-side transaction state and exact-issuer
// verification. Only the digest of the transaction cookie is stored.
export class OidcLoginFlow {
  private constructor(
    private readonly options: Omit<OidcLoginFlowOptions, "transactionDigestKey">,
    private readonly digestKey: CryptoKey,
  ) {
    if (!options.issuer.startsWith("https://")) {
      throw new Error("auth.oidc_issuer_not_https");
    }
  }

  static async create(options: OidcLoginFlowOptions): Promise<OidcLoginFlow> {
    const { transactionDigestKey, ...rest } = options;
    return new OidcLoginFlow(rest, await importHmacKey(transactionDigestKey));
  }

  async start(): Promise<StartedLogin> {
    const state = randomOpaqueValue();
    const nonce = randomOpaqueValue();
    const verifier = randomOpaqueValue(48);
    const challenge = encodeBase64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(verifier))),
    );
    const transactionCookieValue = randomOpaqueValue();
    await this.options.store.save({
      cookieDigest: await hmacSha256Hex(this.digestKey, transactionCookieValue),
      expiresAtMs: this.options.clock.now().getTime() + OIDC_TRANSACTION_LIFETIME_MS,
      nonce,
      state,
      verifier,
    });

    const authorization = new URL("/authorize", this.options.issuer);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("client_id", this.options.audience);
    authorization.searchParams.set("scope", "openid");
    authorization.searchParams.set("state", state);
    authorization.searchParams.set("nonce", nonce);
    authorization.searchParams.set("code_challenge", challenge);
    authorization.searchParams.set("code_challenge_method", "S256");
    return { authorizationUrl: authorization.toString(), transactionCookieValue };
  }

  async complete(
    params: { code: string; state: string },
    transactionCookieValue: string,
  ): Promise<CompletedLogin> {
    const transaction = await this.options.store.consumeByDigest(
      await hmacSha256Hex(this.digestKey, transactionCookieValue),
    );
    const now = this.options.clock.now();
    if (
      transaction === null ||
      now.getTime() > transaction.expiresAtMs ||
      params.state.length === 0 ||
      params.state !== transaction.state
    ) {
      return { code: "auth.oidc_state_invalid", ok: false };
    }

    const exchanged = await this.options.tokenEndpoint({
      audience: this.options.audience,
      code: params.code,
      codeVerifier: transaction.verifier,
    });
    if (!exchanged.ok) {
      return { code: "auth.oidc_claim_invalid", ok: false };
    }

    const verified = await verifyIdToken({
      expectedAudience: this.options.audience,
      expectedIssuer: this.options.issuer,
      expectedNonce: transaction.nonce,
      idToken: exchanged.idToken,
      jwks: await this.options.jwks(),
      now,
    });
    if (!verified.ok) {
      return { code: "auth.oidc_claim_invalid", ok: false };
    }

    const subjectDigest = await sha256Hex(`${this.options.issuer}|${verified.claims.subject}`);
    const membership = await this.options.directory.findBySubjectDigest(subjectDigest);
    if (membership === null) {
      return { code: "auth.oidc_claim_invalid", ok: false };
    }

    return {
      facts: {
        membershipRevision: membership.membershipRevision,
        oidc: {
          authenticatedAt: now.toISOString(),
          issuer: this.options.issuer,
          subjectDigest,
        },
        roles: membership.roles,
        tenantId: membership.tenantId,
        userId: membership.userId,
      },
      ok: true,
    };
  }
}
