import { beforeEach, describe, expect, test } from "bun:test";

import type { Clock } from "../clock";
import { DevIssuer } from "../dev-issuer/issuer";
import { InMemoryMembershipDirectory } from "../membership/directory";
import { sha256Hex } from "../session/digest";
import { OIDC_TRANSACTION_LIFETIME_MS, OidcLoginFlow } from "./transaction";
import { InMemoryOidcTransactionStore } from "./transaction-store";

const ISSUER = "https://issuer.test.libre-ai.fr";
const AUDIENCE = "libre-ai-web";
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

let clock: ReturnType<typeof fixedClock>;
let issuer: DevIssuer;
let flow: OidcLoginFlow;
let directory: InMemoryMembershipDirectory;

beforeEach(async () => {
  clock = fixedClock("2026-07-19T09:00:00.000Z");
  issuer = await DevIssuer.create({ clock, issuer: ISSUER });
  directory = new InMemoryMembershipDirectory();
  directory.register(await issuer.subjectDigest(SUBJECT), {
    membershipRevision: 1,
    roles: ["member"],
    tenantId: `ten_${"a".repeat(16)}`,
    userId: `usr_${"b".repeat(16)}`,
  });
  flow = await OidcLoginFlow.create({
    audience: AUDIENCE,
    clock,
    directory,
    issuer: ISSUER,
    jwks: () => Promise.resolve(issuer.jwks()),
    store: new InMemoryOidcTransactionStore(),
    tokenEndpoint: (request) => issuer.exchangeCode(request),
    transactionDigestKey: new Uint8Array(32).fill(9),
  });
});

async function authorizeFromUrl(
  authorizationUrl: string,
): Promise<{ code: string; state: string }> {
  const url = new URL(authorizationUrl);
  const state = url.searchParams.get("state") ?? "";
  const { code } = issuer.authorize({
    audience: AUDIENCE,
    codeChallenge: url.searchParams.get("code_challenge") ?? "",
    nonce: url.searchParams.get("nonce") ?? "",
    subject: SUBJECT,
  });
  return { code, state };
}

describe("OIDC login flow", () => {
  test("start builds an S256 PKCE authorization URL on the exact issuer", async () => {
    const started = await flow.start();
    const url = new URL(started.authorizationUrl);
    expect(url.origin).toBe(ISSUER);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("client_id")).toBe(AUDIENCE);
    expect(url.searchParams.get("scope")).toBe("openid");
    expect((url.searchParams.get("state") ?? "").length).toBeGreaterThanOrEqual(43);
    expect((url.searchParams.get("nonce") ?? "").length).toBeGreaterThanOrEqual(43);
    expect((url.searchParams.get("code_challenge") ?? "").length).toBeGreaterThanOrEqual(43);
    expect(started.transactionCookieValue.length).toBeGreaterThanOrEqual(43);
  });

  test("complete succeeds once and maps the subject to opaque identity facts", async () => {
    const started = await flow.start();
    const { code, state } = await authorizeFromUrl(started.authorizationUrl);

    const completed = await flow.complete({ code, state }, started.transactionCookieValue);
    if (!completed.ok) throw new Error("expected completion");
    expect(completed.facts.userId).toBe(`usr_${"b".repeat(16)}`);
    expect(completed.facts.tenantId).toBe(`ten_${"a".repeat(16)}`);
    expect(completed.facts.oidc.issuer).toBe(ISSUER);
    expect(completed.facts.oidc.subjectDigest).toBe(await issuer.subjectDigest(SUBJECT));
    expect(completed.facts.oidc.subjectDigest).toBe(await sha256Hex(`${ISSUER}|${SUBJECT}`));
    expect(completed.facts.oidc.authenticatedAt).toBe(clock.now().toISOString());
  });

  test("the transaction is one-use: a second completion refuses", async () => {
    const started = await flow.start();
    const { code, state } = await authorizeFromUrl(started.authorizationUrl);
    expect((await flow.complete({ code, state }, started.transactionCookieValue)).ok).toBeTrue();
    expect(await flow.complete({ code, state }, started.transactionCookieValue)).toEqual({
      code: "auth.oidc_state_invalid",
      ok: false,
    });
  });

  test("state divergence, unknown cookie and stale transaction refuse", async () => {
    const started = await flow.start();
    const { code, state } = await authorizeFromUrl(started.authorizationUrl);

    expect(await flow.complete({ code, state }, "f".repeat(43))).toEqual({
      code: "auth.oidc_state_invalid",
      ok: false,
    });
    expect(
      await flow.complete({ code, state: "s".repeat(43) }, started.transactionCookieValue),
    ).toEqual({ code: "auth.oidc_state_invalid", ok: false });

    const second = await flow.start();
    const again = await authorizeFromUrl(second.authorizationUrl);
    clock.advance(OIDC_TRANSACTION_LIFETIME_MS + 1);
    expect(
      await flow.complete({ code: again.code, state: again.state }, second.transactionCookieValue),
    ).toEqual({ code: "auth.oidc_state_invalid", ok: false });
  });

  test("a cross-transaction nonce replay refuses at token verification", async () => {
    const first = await flow.start();
    const firstAuthorize = await authorizeFromUrl(first.authorizationUrl);
    const second = await flow.start();

    expect(
      await flow.complete(
        {
          code: firstAuthorize.code,
          state: new URL(second.authorizationUrl).searchParams.get("state") ?? "",
        },
        second.transactionCookieValue,
      ),
    ).toEqual({ code: "auth.oidc_claim_invalid", ok: false });
  });

  test("an unmapped subject fails closed", async () => {
    const orphanIssuer = issuer;
    const started = await flow.start();
    const url = new URL(started.authorizationUrl);
    const { code } = orphanIssuer.authorize({
      audience: AUDIENCE,
      codeChallenge: url.searchParams.get("code_challenge") ?? "",
      nonce: url.searchParams.get("nonce") ?? "",
      subject: "unknown-subject",
    });
    expect(
      await flow.complete(
        { code, state: url.searchParams.get("state") ?? "" },
        started.transactionCookieValue,
      ),
    ).toEqual({ code: "auth.oidc_claim_invalid", ok: false });
  });
});
