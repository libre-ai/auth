const encoder = new TextEncoder();

const ALLOWED_ALGORITHMS = ["ES256", "RS256"] as const;
type AllowedAlgorithm = (typeof ALLOWED_ALGORITHMS)[number];

export interface VerifiedIdTokenClaims {
  audience: string;
  expiresAt: Date;
  issuedAt: Date;
  issuer: string;
  nonce: string;
  subject: string;
}

export type IdTokenVerification =
  | { ok: true; claims: VerifiedIdTokenClaims }
  | { ok: false; code: "auth.oidc_claim_invalid" };

export interface IdTokenVerificationInput {
  expectedAudience: string;
  expectedIssuer: string;
  expectedNonce: string;
  idToken: string;
  jwks: { keys: Array<JsonWebKey & { kid?: string }> };
  now: Date;
}

const REFUSED: IdTokenVerification = { code: "auth.oidc_claim_invalid", ok: false };

// Closed verification boundary: compact JWS with an asymmetric algorithm
// from the fixed allowlist only. `none`, HMAC and every other algorithm are
// rejected before any cryptographic work, so a captured public key can never
// be replayed as an HMAC secret and an unsigned token can never pass.
export async function verifyIdToken(input: IdTokenVerificationInput): Promise<IdTokenVerification> {
  const parts = input.idToken.split(".");
  if (parts.length !== 3) {
    return REFUSED;
  }
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = decodeJsonPart(headerPart);
  const payload = decodeJsonPart(payloadPart);
  const signature = decodeBase64Url(signaturePart);
  if (header === null || payload === null || signature === null) {
    return REFUSED;
  }

  const algorithm = header["alg"];
  if (typeof algorithm !== "string" || !isAllowedAlgorithm(algorithm)) {
    return REFUSED;
  }
  const keyId = header["kid"];
  if (typeof keyId !== "string" || keyId.length === 0) {
    return REFUSED;
  }
  const jwk = input.jwks.keys.find((candidate) => candidate.kid === keyId);
  if (jwk === undefined || !keyMatchesAlgorithm(jwk, algorithm)) {
    return REFUSED;
  }

  const key = await importVerificationKey(jwk, algorithm);
  if (key === null) {
    return REFUSED;
  }
  const verified = await crypto.subtle.verify(
    verifyParameters(algorithm),
    key,
    signature as unknown as BufferSource,
    encoder.encode(`${headerPart}.${payloadPart}`),
  );
  if (!verified) {
    return REFUSED;
  }

  const issuer = payload["iss"];
  const subject = payload["sub"];
  const audience = payload["aud"];
  const nonce = payload["nonce"];
  const expiresAt = payload["exp"];
  const issuedAt = payload["iat"];
  if (
    issuer !== input.expectedIssuer ||
    typeof subject !== "string" ||
    subject.length === 0 ||
    !audienceMatches(audience, input.expectedAudience) ||
    nonce !== input.expectedNonce ||
    typeof expiresAt !== "number" ||
    typeof issuedAt !== "number"
  ) {
    return REFUSED;
  }
  const nowSeconds = Math.floor(input.now.getTime() / 1000);
  if (nowSeconds >= expiresAt || issuedAt > nowSeconds) {
    return REFUSED;
  }

  return {
    claims: {
      audience: input.expectedAudience,
      expiresAt: new Date(expiresAt * 1000),
      issuedAt: new Date(issuedAt * 1000),
      issuer,
      nonce: input.expectedNonce,
      subject,
    },
    ok: true,
  };
}

function isAllowedAlgorithm(algorithm: string): algorithm is AllowedAlgorithm {
  return (ALLOWED_ALGORITHMS as readonly string[]).includes(algorithm);
}

function keyMatchesAlgorithm(jwk: JsonWebKey, algorithm: AllowedAlgorithm): boolean {
  if (jwk.alg !== undefined && jwk.alg !== algorithm) {
    return false;
  }
  if (algorithm === "ES256") {
    return jwk.kty === "EC" && jwk.crv === "P-256";
  }
  return jwk.kty === "RSA";
}

async function importVerificationKey(
  jwk: JsonWebKey,
  algorithm: AllowedAlgorithm,
): Promise<CryptoKey | null> {
  try {
    if (algorithm === "ES256") {
      return await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
    }
    return await crypto.subtle.importKey(
      "jwk",
      jwk,
      { hash: "SHA-256", name: "RSASSA-PKCS1-v1_5" },
      false,
      ["verify"],
    );
  } catch {
    return null;
  }
}

function verifyParameters(algorithm: AllowedAlgorithm): AlgorithmIdentifier | EcdsaParams {
  if (algorithm === "ES256") {
    return { hash: "SHA-256", name: "ECDSA" };
  }
  return { name: "RSASSA-PKCS1-v1_5" };
}

function audienceMatches(audience: unknown, expected: string): boolean {
  if (typeof audience === "string") {
    return audience === expected;
  }
  if (Array.isArray(audience)) {
    return audience.length > 0 && audience.every((entry) => typeof entry === "string")
      ? audience.includes(expected)
      : false;
  }
  return false;
}

function decodeJsonPart(part: string): Record<string, unknown> | null {
  const bytes = decodeBase64Url(part);
  if (bytes === null) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    return null;
  }
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
