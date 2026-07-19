import { beforeAll, describe, expect, test } from "bun:test";

import type { Clock } from "../clock";
import { DevIssuer } from "../dev-issuer/issuer";
import { decodeBase64Url, encodeBase64Url, verifyIdToken } from "./jws";

const ISSUER = "https://issuer.test.libre-ai.fr";
const AUDIENCE = "libre-ai-web";
const NONCE = "n".repeat(43);
const SUBJECT = "dev-user-1";

function fixedClock(start: string): Clock & { advance(ms: number): void } {
  let current = new Date(start).getTime();
  return {
    advance(ms: number): void {
      current += ms;
    },
    now(): Date {
      return new Date(current);
    },
  };
}

const clock = fixedClock("2026-07-19T09:00:00.000Z");
let issuer: DevIssuer;
let validToken: string;

beforeAll(async () => {
  issuer = await DevIssuer.create({ clock, issuer: ISSUER });
  validToken = await issuer.signIdToken({ audience: AUDIENCE, nonce: NONCE, subject: SUBJECT });
});

function verify(idToken: string, overrides: Partial<Parameters<typeof verifyIdToken>[0]> = {}) {
  return verifyIdToken({
    expectedAudience: AUDIENCE,
    expectedIssuer: ISSUER,
    expectedNonce: NONCE,
    idToken,
    jwks: issuer.jwks(),
    now: clock.now(),
    ...overrides,
  });
}

const REFUSED = { code: "auth.oidc_claim_invalid", ok: false } as const;

describe("ID token verification", () => {
  test("accepts a valid ES256 token and returns bounded claims", async () => {
    const result = await verify(validToken);
    if (!result.ok) throw new Error("expected verification success");
    expect(result.claims.issuer).toBe(ISSUER);
    expect(result.claims.subject).toBe(SUBJECT);
    expect(result.claims.audience).toBe(AUDIENCE);
    expect(result.claims.nonce).toBe(NONCE);
  });

  test("rejects alg=none even with an empty signature", async () => {
    const forged = await issuer.signIdToken(
      { audience: AUDIENCE, nonce: NONCE, subject: SUBJECT },
      { algorithm: "none" },
    );
    const [header, payload] = forged.split(".");
    expect(await verify(`${header}.${payload}.`)).toEqual(REFUSED);
    expect(await verify(forged)).toEqual(REFUSED);
  });

  test("rejects HMAC algorithm confusion using the public key as secret", async () => {
    const headerPart = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({ alg: "HS256", kid: issuer.jwks().keys[0]?.kid, typ: "JWT" }),
      ),
    );
    const nowSeconds = Math.floor(clock.now().getTime() / 1000);
    const payloadPart = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          aud: AUDIENCE,
          exp: nowSeconds + 300,
          iat: nowSeconds,
          iss: ISSUER,
          nonce: NONCE,
          sub: "attacker",
        }),
      ),
    );
    const publicKeyBytes = new TextEncoder().encode(JSON.stringify(issuer.jwks().keys[0]));
    const hmacKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes as unknown as BufferSource,
      { hash: "SHA-256", name: "HMAC" },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign(
      "HMAC",
      hmacKey,
      new TextEncoder().encode(`${headerPart}.${payloadPart}`),
    );
    const forged = `${headerPart}.${payloadPart}.${encodeBase64Url(new Uint8Array(signature))}`;
    expect(await verify(forged)).toEqual(REFUSED);
  });

  test.each([
    ["EdDSA", "EdDSA"],
    ["ES384", "ES384"],
    ["RS512", "RS512"],
    ["empty alg", ""],
  ])("rejects disallowed algorithm %s", async (_label, algorithm) => {
    const forged = await issuer.signIdToken(
      { audience: AUDIENCE, nonce: NONCE, subject: SUBJECT },
      { algorithm },
    );
    expect(await verify(forged)).toEqual(REFUSED);
  });

  test("rejects unknown kid and missing kid", async () => {
    const unknownKid = await issuer.signIdToken(
      { audience: AUDIENCE, nonce: NONCE, subject: SUBJECT },
      { keyId: "other-key" },
    );
    expect(await verify(unknownKid)).toEqual(REFUSED);

    const withoutKid = await issuer.signIdToken(
      { audience: AUDIENCE, nonce: NONCE, subject: SUBJECT },
      { keyId: "" },
    );
    expect(await verify(withoutKid)).toEqual(REFUSED);
  });

  test("rejects a tampered payload with a valid-shape signature", async () => {
    const [header, payload, signature] = validToken.split(".") as [string, string, string];
    const decoded = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(payload) ?? new Uint8Array()),
    );
    decoded.sub = "attacker";
    const tamperedPayload = encodeBase64Url(new TextEncoder().encode(JSON.stringify(decoded)));
    expect(await verify(`${header}.${tamperedPayload}.${signature}`)).toEqual(REFUSED);
  });

  test.each([
    ["issuer substitution", { issuer: "https://evil.example.org" }],
    ["audience substitution", { audience: "other-audience" }],
    ["nonce mismatch", { nonce: "m".repeat(43) }],
    [
      "expired token",
      { expiresAtSeconds: Math.floor(new Date("2026-07-19T08:59:00.000Z").getTime() / 1000) },
    ],
    [
      "future issuance",
      { issuedAtSeconds: Math.floor(new Date("2026-07-19T10:00:00.000Z").getTime() / 1000) },
    ],
  ])("rejects claim violation: %s", async (_label, overrides) => {
    const forged = await issuer.signIdToken(
      { audience: AUDIENCE, nonce: NONCE, subject: SUBJECT },
      overrides,
    );
    expect(await verify(forged)).toEqual(REFUSED);
  });

  test("rejects structurally invalid tokens", async () => {
    expect(await verify("only.two")).toEqual(REFUSED);
    expect(await verify("")).toEqual(REFUSED);
    expect(await verify("a.b.c.d")).toEqual(REFUSED);
    expect(await verify("!!!.###.$$$")).toEqual(REFUSED);
    const [header, , signature] = validToken.split(".") as [string, string, string];
    expect(
      await verify(`${header}.${encodeBase64Url(new TextEncoder().encode("[]"))}.${signature}`),
    ).toEqual(REFUSED);
  });

  test("replaying the same valid token against a rotated nonce fails", async () => {
    expect(await verify(validToken, { expectedNonce: "rotated".padEnd(43, "x") })).toEqual(REFUSED);
  });
});

describe("dev issuer PKCE code exchange", () => {
  test("one-use code bound to the S256 challenge", async () => {
    const verifier = "v".repeat(64);
    const challenge = encodeBase64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const { code } = issuer.authorize({
      audience: AUDIENCE,
      codeChallenge: challenge,
      nonce: NONCE,
      subject: SUBJECT,
    });

    const wrongVerifier = await issuer.exchangeCode({
      audience: AUDIENCE,
      code,
      codeVerifier: "w".repeat(64),
    });
    expect(wrongVerifier.ok).toBeFalse();

    const replayed = await issuer.exchangeCode({
      audience: AUDIENCE,
      code,
      codeVerifier: verifier,
    });
    expect(replayed.ok).toBeFalse();
  });

  test("valid exchange returns a verifiable token; expired codes refuse", async () => {
    const verifier = "p".repeat(64);
    const challenge = encodeBase64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const good = issuer.authorize({
      audience: AUDIENCE,
      codeChallenge: challenge,
      nonce: NONCE,
      subject: SUBJECT,
    });
    const exchanged = await issuer.exchangeCode({
      audience: AUDIENCE,
      code: good.code,
      codeVerifier: verifier,
    });
    if (!exchanged.ok) throw new Error("expected exchange success");
    expect((await verify(exchanged.idToken)).ok).toBeTrue();

    const stale = issuer.authorize({
      audience: AUDIENCE,
      codeChallenge: challenge,
      nonce: NONCE,
      subject: SUBJECT,
    });
    clock.advance(61 * 1000);
    const expired = await issuer.exchangeCode({
      audience: AUDIENCE,
      code: stale.code,
      codeVerifier: verifier,
    });
    expect(expired.ok).toBeFalse();
  });
});
