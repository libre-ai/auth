import { beforeEach, describe, expect, test } from "bun:test";
import { loadCanonicalContractRegistry } from "@libre-ai/contracts";

import type { Clock } from "../clock";
import { DevIssuer } from "../dev-issuer/issuer";
import { InMemoryMembershipDirectory } from "../membership/directory";
import { OidcLoginFlow } from "../oidc/transaction";
import { InMemoryOidcTransactionStore } from "../oidc/transaction-store";
import { IDLE_TIMEOUT_MS, SessionService } from "../session/lifecycle";
import { InMemorySessionStore } from "../session/store";
import { AuthHttpBoundary } from "./handlers";

const registry = await loadCanonicalContractRegistry();

const ORIGIN = "https://app.test.libre-ai.fr";
const ISSUER = "https://issuer.test.libre-ai.fr";
const AUDIENCE = "libre-ai-web";
const SUBJECT = "dev-user-1";
const IDEMPOTENCY = `idem_${"c".repeat(16)}`;

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
let boundary: AuthHttpBoundary;
let sessions: SessionService;

beforeEach(async () => {
  clock = fixedClock("2026-07-19T10:00:00.000Z");
  issuer = await DevIssuer.create({ clock, issuer: ISSUER });
  const directory = new InMemoryMembershipDirectory();
  directory.register(await issuer.subjectDigest(SUBJECT), {
    membershipRevision: 1,
    roles: ["member"],
    tenantId: `ten_${"a".repeat(16)}`,
    userId: `usr_${"b".repeat(16)}`,
  });
  sessions = await SessionService.create({
    clock,
    cookieDigestKey: new Uint8Array(32).fill(7),
    store: new InMemorySessionStore(),
  });
  boundary = new AuthHttpBoundary({
    allowedOrigin: ORIGIN,
    flow: await OidcLoginFlow.create({
      audience: AUDIENCE,
      clock,
      directory,
      issuer: ISSUER,
      jwks: () => Promise.resolve(issuer.jwks()),
      store: new InMemoryOidcTransactionStore(),
      tokenEndpoint: (request) => issuer.exchangeCode(request),
      transactionDigestKey: new Uint8Array(32).fill(9),
    }),
    sessions,
  });
});

function loginRequest(overrides: { body?: unknown; headers?: Record<string, string> } = {}) {
  return new Request(`${ORIGIN}/v1/auth/login`, {
    body: JSON.stringify(overrides.body ?? { returnPath: "/notebook" }),
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": IDEMPOTENCY,
      "If-Match": '"0"',
      Origin: ORIGIN,
      ...overrides.headers,
    },
    method: "POST",
  });
}

function cookieOf(response: Response, name: string): string {
  const raw = response.headers.getSetCookie().find((entry) => entry.startsWith(`${name}=`));
  if (raw === undefined) throw new Error(`missing cookie ${name}`);
  return raw;
}

function cookieValueOf(setCookie: string): string {
  return (setCookie.split(";")[0] ?? "").split("=")[1] ?? "";
}

async function login(): Promise<{ sessionCookie: string; response: Response }> {
  const startResponse = await boundary.handleLogin(loginRequest());
  const { authorizationUrl } = (await startResponse.json()) as { authorizationUrl: string };
  const transactionCookie = cookieValueOf(cookieOf(startResponse, "__Host-libre_ai_oidc"));
  const url = new URL(authorizationUrl);
  const { code } = issuer.authorize({
    audience: AUDIENCE,
    codeChallenge: url.searchParams.get("code_challenge") ?? "",
    nonce: url.searchParams.get("nonce") ?? "",
    subject: SUBJECT,
  });
  const callback = await boundary.handleCallback(
    new Request(
      `${ORIGIN}/v1/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(url.searchParams.get("state") ?? "")}`,
      { headers: { Cookie: `__Host-libre_ai_oidc=${transactionCookie}` } },
    ),
  );
  return {
    response: callback,
    sessionCookie: cookieValueOf(cookieOf(callback, "__Host-libre_ai_session")),
  };
}

async function expectProblem(response: Response, status: number, code: string): Promise<void> {
  expect(response.status).toBe(status);
  expect(response.headers.get("Content-Type")).toBe("application/problem+json");
  const body = (await response.json()) as { error: { code: string } };
  expect(registry.validate("problem-details.v1.schema.json", body).ok).toBeTrue();
  expect(body.error.code).toBe(code);
}

describe("POST /v1/auth/login", () => {
  test("returns the authorization URL and a bounded Lax transaction cookie", async () => {
    const response = await boundary.handleLogin(loginRequest());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { authorizationUrl: string };
    expect(body.authorizationUrl.startsWith(`${ISSUER}/authorize?`)).toBeTrue();
    const cookie = cookieOf(response, "__Host-libre_ai_oidc");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("Max-Age=600");
    expect(response.headers.get("Content-Security-Policy")).not.toBeNull();
  });

  test.each([
    ["missing Origin", { headers: { Origin: "" } }],
    ["cross origin", { headers: { Origin: "https://evil.example.org" } }],
    ["cross-site fetch metadata", { headers: { "Sec-Fetch-Site": "cross-site" } }],
  ])("refuses origin defence violation: %s", async (_label, overrides) => {
    const response = await boundary.handleLogin(loginRequest(overrides));
    await expectProblem(response, 403, "auth.csrf_invalid");
  });

  test.each([
    ["bad idempotency key", { headers: { "Idempotency-Key": "nope" } }],
    ["bad revision", { headers: { "If-Match": "0" } }],
  ])("refuses malformed mutation header: %s", async (_label, overrides) => {
    const response = await boundary.handleLogin(loginRequest(overrides));
    await expectProblem(response, 400, "auth.csrf_invalid");
  });

  test.each([
    ["protocol-relative", "//evil.example.org"],
    ["scheme", "https://evil.example.org"],
    ["missing leading slash", "notebook"],
    ["query injection", "/a?b=c"],
  ])("refuses open-redirect returnPath: %s", async (_label, returnPath) => {
    const response = await boundary.handleLogin(loginRequest({ body: { returnPath } }));
    await expectProblem(response, 400, "auth.oidc_state_invalid");
  });
});

describe("GET /v1/auth/callback", () => {
  test("valid callback answers 303 to the stored returnPath with a Strict session cookie", async () => {
    const { response } = await login();
    expect(response.status).toBe(303);
    expect(response.headers.get("Location")).toBe("/notebook");
    const session = cookieOf(response, "__Host-libre_ai_session");
    expect(session).toContain("Secure");
    expect(session).toContain("HttpOnly");
    expect(session).toContain("SameSite=Strict");
    expect(session).toContain("Path=/");
    expect(session).not.toContain("Domain");
    const cleared = cookieOf(response, "__Host-libre_ai_oidc");
    expect(cleared).toContain("Max-Age=0");
  });

  test("missing transaction cookie or short parameters refuse without identity disclosure", async () => {
    const noCookie = await boundary.handleCallback(
      new Request(`${ORIGIN}/v1/auth/callback?code=${"c".repeat(43)}&state=${"s".repeat(43)}`),
    );
    await expectProblem(noCookie, 400, "auth.oidc_state_invalid");

    const shortState = await boundary.handleCallback(
      new Request(`${ORIGIN}/v1/auth/callback?code=${"c".repeat(43)}&state=short`, {
        headers: { Cookie: `__Host-libre_ai_oidc=${"t".repeat(43)}` },
      }),
    );
    await expectProblem(shortState, 400, "auth.oidc_state_invalid");
  });
});

describe("GET /v1/auth/session", () => {
  test("returns the browser-safe projection without digests or membership internals", async () => {
    const { sessionCookie } = await login();
    const response = await boundary.handleGetSession(
      new Request(`${ORIGIN}/v1/auth/session`, {
        headers: { Cookie: `__Host-libre_ai_session=${sessionCookie}` },
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "absoluteExpiresAt",
      "idleExpiresAt",
      "revision",
      "roles",
      "tenantId",
      "userId",
    ]);
    expect(body["userId"]).toBe(`usr_${"b".repeat(16)}`);
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain(sessionCookie);
    expect(serialized).not.toContain("Digest");
  });

  test("missing, expired and revoked sessions answer generic 401 problems", async () => {
    const missing = await boundary.handleGetSession(new Request(`${ORIGIN}/v1/auth/session`));
    await expectProblem(missing, 401, "auth.session_missing");

    const { sessionCookie } = await login();
    clock.advance(IDLE_TIMEOUT_MS + 1);
    const expired = await boundary.handleGetSession(
      new Request(`${ORIGIN}/v1/auth/session`, {
        headers: { Cookie: `__Host-libre_ai_session=${sessionCookie}` },
      }),
    );
    await expectProblem(expired, 401, "auth.session_expired");
  });
});

describe("DELETE /v1/auth/session", () => {
  async function deleteRequest(
    sessionCookie: string,
    csrfToken: string,
    revision: number,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    return boundary.handleDeleteSession(
      new Request(`${ORIGIN}/v1/auth/session`, {
        headers: {
          Cookie: `__Host-libre_ai_session=${sessionCookie}`,
          "Idempotency-Key": IDEMPOTENCY,
          "If-Match": `"${revision}"`,
          Origin: ORIGIN,
          "Sec-Fetch-Site": "same-origin",
          "X-CSRF-Token": csrfToken,
          ...headers,
        },
        method: "DELETE",
      }),
    );
  }

  test("revokes the server record before clearing the cookie", async () => {
    const { sessionCookie } = await login();
    const { csrfToken } = await sessions.refreshCsrfSecret(sessionCookie);
    const current = await sessions.resolveSession(sessionCookie);
    if (!current.ok) throw new Error("expected active session");

    const response = await deleteRequest(sessionCookie, csrfToken, current.record.revision);
    expect(response.status).toBe(204);
    const cleared = cookieOf(response, "__Host-libre_ai_session");
    expect(cleared).toContain("Max-Age=0");

    const after = await boundary.handleGetSession(
      new Request(`${ORIGIN}/v1/auth/session`, {
        headers: { Cookie: `__Host-libre_ai_session=${sessionCookie}` },
      }),
    );
    await expectProblem(after, 401, "auth.session_revoked");
  });

  test("cross-origin, bad token and revision mismatch refuse without revoking", async () => {
    const { sessionCookie } = await login();
    const { csrfToken } = await sessions.refreshCsrfSecret(sessionCookie);
    const current = await sessions.resolveSession(sessionCookie);
    if (!current.ok) throw new Error("expected active session");
    const revision = current.record.revision;

    await expectProblem(
      await deleteRequest(sessionCookie, csrfToken, revision, {
        Origin: "https://evil.example.org",
      }),
      403,
      "auth.csrf_invalid",
    );
    await expectProblem(
      await deleteRequest(sessionCookie, "x".repeat(43), revision + 1),
      403,
      "auth.csrf_invalid",
    );
    await expectProblem(
      await deleteRequest(sessionCookie, csrfToken, revision + 10),
      412,
      "auth.session_revision_mismatch",
    );

    const still = await boundary.handleGetSession(
      new Request(`${ORIGIN}/v1/auth/session`, {
        headers: { Cookie: `__Host-libre_ai_session=${sessionCookie}` },
      }),
    );
    expect(still.status).toBe(200);
  });
});
