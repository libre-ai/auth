import type { Clock } from "../clock";
import { encodeBase64Url } from "../oidc/jws";
import { randomOpaqueValue, sha256Hex } from "../session/digest";

const encoder = new TextEncoder();

const AUTHORIZATION_CODE_LIFETIME_MS = 60 * 1000;
const ID_TOKEN_LIFETIME_SECONDS = 5 * 60;

export interface DevIssuerOptions {
  clock: Clock;
  issuer: string;
}

export interface AuthorizeRequest {
  audience: string;
  codeChallenge: string;
  nonce: string;
  subject: string;
}

export interface ExchangeRequest {
  audience: string;
  code: string;
  codeVerifier: string;
}

export type ExchangeResult =
  | { ok: true; idToken: string }
  | { ok: false; code: "auth.oidc_claim_invalid" };

interface PendingAuthorization {
  audience: string;
  codeChallenge: string;
  expiresAtMs: number;
  nonce: string;
  subject: string;
}

interface IdTokenOverrides {
  algorithm?: string;
  audience?: string;
  expiresAtSeconds?: number;
  issuedAtSeconds?: number;
  issuer?: string;
  keyId?: string;
  nonce?: string;
}

// Deterministic in-process development issuer (ADR-0002 section 2). It holds
// test-only key material, signs ES256 ID tokens and enforces the S256 PKCE
// binding plus one-use authorization codes. It contains no production
// identity and never leaves the process.
export class DevIssuer {
  private readonly pending = new Map<string, PendingAuthorization>();

  private constructor(
    private readonly clock: Clock,
    readonly issuer: string,
    private readonly keyPair: CryptoKeyPair,
    private readonly publicJwk: JsonWebKey & { kid: string },
  ) {}

  static async create(options: DevIssuerOptions): Promise<DevIssuer> {
    const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const {
      ext: _ext,
      key_ops: _keyOps,
      ...exported
    } = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const publicJwk: JsonWebKey & { kid: string } = {
      ...exported,
      alg: "ES256",
      kid: `dev-${randomOpaqueValue().slice(0, 16)}`,
      use: "sig",
    };
    return new DevIssuer(options.clock, options.issuer, keyPair, publicJwk);
  }

  jwks(): { keys: Array<JsonWebKey & { kid: string }> } {
    return { keys: [{ ...this.publicJwk }] };
  }

  authorize(request: AuthorizeRequest): { code: string } {
    const code = randomOpaqueValue();
    this.pending.set(code, {
      audience: request.audience,
      codeChallenge: request.codeChallenge,
      expiresAtMs: this.clock.now().getTime() + AUTHORIZATION_CODE_LIFETIME_MS,
      nonce: request.nonce,
      subject: request.subject,
    });
    return { code };
  }

  async exchangeCode(request: ExchangeRequest): Promise<ExchangeResult> {
    const pending = this.pending.get(request.code);
    this.pending.delete(request.code);
    if (
      pending === undefined ||
      pending.audience !== request.audience ||
      this.clock.now().getTime() > pending.expiresAtMs
    ) {
      return { code: "auth.oidc_claim_invalid", ok: false };
    }
    const challenge = encodeBase64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(request.codeVerifier))),
    );
    if (challenge !== pending.codeChallenge) {
      return { code: "auth.oidc_claim_invalid", ok: false };
    }
    const idToken = await this.signIdToken({
      audience: pending.audience,
      nonce: pending.nonce,
      subject: pending.subject,
    });
    return { idToken, ok: true };
  }

  async signIdToken(
    claims: { audience: string; nonce: string; subject: string },
    overrides: IdTokenOverrides = {},
  ): Promise<string> {
    const nowSeconds = Math.floor(this.clock.now().getTime() / 1000);
    const header = {
      alg: overrides.algorithm ?? "ES256",
      kid: overrides.keyId ?? this.publicJwk.kid,
      typ: "JWT",
    };
    const payload = {
      aud: overrides.audience ?? claims.audience,
      exp: overrides.expiresAtSeconds ?? nowSeconds + ID_TOKEN_LIFETIME_SECONDS,
      iat: overrides.issuedAtSeconds ?? nowSeconds,
      iss: overrides.issuer ?? this.issuer,
      nonce: overrides.nonce ?? claims.nonce,
      sub: claims.subject,
    };
    const signingInput = `${encodeJsonBase64Url(header)}.${encodeJsonBase64Url(payload)}`;
    const signature = await crypto.subtle.sign(
      { hash: "SHA-256", name: "ECDSA" },
      this.keyPair.privateKey,
      encoder.encode(signingInput),
    );
    return `${signingInput}.${encodeBase64Url(new Uint8Array(signature))}`;
  }

  async subjectDigest(subject: string): Promise<string> {
    return sha256Hex(`${this.issuer}|${subject}`);
  }
}

function encodeJsonBase64Url(value: unknown): string {
  return encodeBase64Url(encoder.encode(JSON.stringify(value)));
}
