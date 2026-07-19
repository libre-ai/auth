import { beforeEach, describe, expect, test } from "bun:test";

import type { Clock } from "../clock";
import { DevIssuer } from "../dev-issuer/issuer";
import { AuthHttpBoundary } from "../http/handlers";
import { InMemoryMembershipDirectory } from "../membership/directory";
import { OidcLoginFlow } from "../oidc/transaction";
import { InMemoryOidcTransactionStore } from "../oidc/transaction-store";
import { SessionService } from "../session/lifecycle";
import { InMemorySessionStore } from "../session/store";

const ORIGIN = "https://app.test.libre-ai.fr";
const ISSUER = "https://issuer.test.libre-ai.fr";
const AUDIENCE = "libre-ai-web";
const SUBJECT = "dev-user-1";
const IDEMPOTENCY = `idem_${"d".repeat(16)}`;

function fixedClock(start: string): Clock {
  const current = new Date(start).getTime();
  return {
    now(): Date {
      return new Date(current);
    },
  };
}

let issuer: DevIssuer;
let boundary: AuthHttpBoundary;
let sessions: SessionService;
const captured: string[] = [];

beforeEach(async () => {
  captured.length = 0;
  const clock = fixedClock("2026-07-19T11:00:00.000Z");
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

// A logger that an operational sink would consume: it records the exact
// strings the boundary chooses to emit. The boundary must never hand secret
// material to any sink, so capturing everything and asserting absence is a
// faithful proxy for proxy/application log inspection.
function withCapturedConsole<T>(run: () => Promise<T>): Promise<T> {
  const original = {
    error: console.error,
    info: console.info,
    log: console.log,
    warn: console.warn,
  };
  const record = (...parts: unknown[]): void => {
    captured.push(
      parts.map((part) => (typeof part === "string" ? part : JSON.stringify(part))).join(" "),
    );
  };
  console.log = record;
  console.info = record;
  console.warn = record;
  console.error = record;
  return run().finally(() => {
    Object.assign(console, original);
  });
}

describe("secret redaction in emitted logs", () => {
  test("a full login/logout cycle emits no cookie, CSRF, code, verifier or token bytes", async () => {
    const secrets: string[] = [];

    await withCapturedConsole(async () => {
      const startResponse = await boundary.handleLogin(
        new Request(`${ORIGIN}/v1/auth/login`, {
          body: JSON.stringify({ returnPath: "/notebook" }),
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": IDEMPOTENCY,
            "If-Match": '"0"',
            Origin: ORIGIN,
          },
          method: "POST",
        }),
      );
      const authorizationUrl = ((await startResponse.json()) as { authorizationUrl: string })
        .authorizationUrl;
      const transactionCookie = (startResponse.headers.getSetCookie()[0] ?? "")
        .split(";")[0]
        ?.split("=")[1] as string;
      const url = new URL(authorizationUrl);
      const authorized = issuer.authorize({
        audience: AUDIENCE,
        codeChallenge: url.searchParams.get("code_challenge") ?? "",
        nonce: url.searchParams.get("nonce") ?? "",
        subject: SUBJECT,
      });
      secrets.push(transactionCookie, authorized.code);

      const callback = await boundary.handleCallback(
        new Request(
          `${ORIGIN}/v1/auth/callback?code=${authorized.code}&state=${url.searchParams.get("state")}`,
          { headers: { Cookie: `__Host-libre_ai_oidc=${transactionCookie}` } },
        ),
      );
      const sessionCookie = (callback.headers.getSetCookie()[0] ?? "")
        .split(";")[0]
        ?.split("=")[1] as string;
      const { csrfToken } = await sessions.refreshCsrfSecret(sessionCookie);
      secrets.push(sessionCookie, csrfToken);

      await boundary.handleGetSession(
        new Request(`${ORIGIN}/v1/auth/session`, {
          headers: { Cookie: `__Host-libre_ai_session=${sessionCookie}` },
        }),
      );
    });

    for (const line of captured) {
      for (const secret of secrets) {
        expect(secret.length).toBeGreaterThan(0);
        expect(line).not.toContain(secret);
      }
    }
  });

  test("a refusal never echoes the offending token or cookie", async () => {
    const forgedCookie = "z".repeat(64);
    await withCapturedConsole(async () => {
      await boundary.handleGetSession(
        new Request(`${ORIGIN}/v1/auth/session`, {
          headers: { Cookie: `__Host-libre_ai_session=${forgedCookie}` },
        }),
      );
    });
    for (const line of captured) {
      expect(line).not.toContain(forgedCookie);
    }
  });
});
