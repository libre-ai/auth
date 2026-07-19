// Qualification-only e2e harness for WP-G2-I01. It binds the real auth
// boundary to a local TLS listener (the __Host- cookie prefix and the
// HTTPS-issuer contract both require a secure origin), exposes the
// deterministic development issuer as a navigable /authorize endpoint and
// adds two harness-only controls: a server clock advance and a CSRF token
// delivery standing in for the rendered document. Nothing here is part of
// the exported package API.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Clock } from "../src/clock";
import { DevIssuer } from "../src/dev-issuer/issuer";
import { AuthHttpBoundary } from "../src/http/handlers";
import { InMemoryMembershipDirectory } from "../src/membership/directory";
import { OidcLoginFlow } from "../src/oidc/transaction";
import { InMemoryOidcTransactionStore } from "../src/oidc/transaction-store";
import { SessionService } from "../src/session/lifecycle";
import { InMemorySessionStore } from "../src/session/store";

const HOST = Bun.env["HOST"] ?? "127.0.0.1";
const PORT = Number(Bun.env["PORT"] ?? "4187");
const ORIGIN = `https://${HOST}:${PORT}`;
const SUBJECT = "dev-user-1";

function selfSignedCertificate(): { certPath: string; keyPath: string } {
  const directory = mkdtempSync(join(tmpdir(), "auth-web-e2e-"));
  const certPath = join(directory, "cert.pem");
  const keyPath = join(directory, "key.pem");
  const generated = Bun.spawnSync([
    "openssl",
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-keyout",
    keyPath,
    "-out",
    certPath,
    "-days",
    "1",
    "-nodes",
    "-subj",
    "/CN=127.0.0.1",
    "-addext",
    `subjectAltName=IP:${HOST}`,
  ]);
  if (generated.exitCode !== 0) {
    throw new Error("e2e.certificate_generation_failed");
  }
  return { certPath, keyPath };
}

function adjustableClock(): Clock & { advance(ms: number): void } {
  let offset = 0;
  return {
    advance(ms: number): void {
      offset += ms;
    },
    now(): Date {
      return new Date(Date.now() + offset);
    },
  };
}

const clock = adjustableClock();
const issuer = await DevIssuer.create({ clock, issuer: ORIGIN });
const directory = new InMemoryMembershipDirectory();
directory.register(await issuer.subjectDigest(SUBJECT), {
  membershipRevision: 1,
  roles: ["member"],
  tenantId: `ten_${"a".repeat(16)}`,
  userId: `usr_${"b".repeat(16)}`,
});
const sessions = await SessionService.create({
  clock,
  cookieDigestKey: crypto.getRandomValues(new Uint8Array(32)),
  store: new InMemorySessionStore(),
});
const boundary = new AuthHttpBoundary({
  allowedOrigin: ORIGIN,
  flow: await OidcLoginFlow.create({
    audience: "libre-ai-web",
    clock,
    directory,
    issuer: ORIGIN,
    jwks: () => Promise.resolve(issuer.jwks()),
    store: new InMemoryOidcTransactionStore(),
    tokenEndpoint: (request) => issuer.exchangeCode(request),
    transactionDigestKey: crypto.getRandomValues(new Uint8Array(32)),
  }),
  sessions,
});

const { certPath, keyPath } = selfSignedCertificate();

function readCookie(request: Request, name: string): string | null {
  for (const part of (request.headers.get("Cookie") ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name && rest.length > 0) {
      return rest.join("=");
    }
  }
  return null;
}

Bun.serve({
  fetch: async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.pathname === "/v1/auth/login" && request.method === "POST") {
      return boundary.handleLogin(request);
    }
    if (url.pathname === "/v1/auth/callback" && request.method === "GET") {
      return boundary.handleCallback(request);
    }
    if (url.pathname === "/v1/auth/session" && request.method === "GET") {
      return boundary.handleGetSession(request);
    }
    if (url.pathname === "/v1/auth/session" && request.method === "DELETE") {
      return boundary.handleDeleteSession(request);
    }
    if (url.pathname === "/authorize" && request.method === "GET") {
      const { code } = issuer.authorize({
        audience: "libre-ai-web",
        codeChallenge: url.searchParams.get("code_challenge") ?? "",
        nonce: url.searchParams.get("nonce") ?? "",
        subject: SUBJECT,
      });
      const location = new URL("/v1/auth/callback", ORIGIN);
      location.searchParams.set("code", code);
      location.searchParams.set("state", url.searchParams.get("state") ?? "");
      return new Response(null, { headers: { Location: location.toString() }, status: 302 });
    }
    if (url.pathname === "/e2e/clock/advance" && request.method === "POST") {
      const body = (await request.json()) as { ms?: number };
      clock.advance(typeof body.ms === "number" ? body.ms : 0);
      return Response.json({ ok: true });
    }
    if (url.pathname === "/e2e/csrf" && request.method === "GET") {
      const cookieValue = readCookie(request, "__Host-libre_ai_session");
      if (cookieValue === null) {
        return new Response(null, { status: 401 });
      }
      try {
        const { csrfToken } = await sessions.refreshCsrfSecret(cookieValue);
        return Response.json({ csrfToken });
      } catch {
        return new Response(null, { status: 401 });
      }
    }
    return new Response("<!doctype html><html><body><h1>auth-web e2e</h1></body></html>", {
      headers: { "Content-Type": "text/html; charset=utf-8" },
      status: 200,
    });
  },
  hostname: HOST,
  port: PORT,
  tls: {
    cert: Bun.file(certPath),
    key: Bun.file(keyPath),
  },
});

console.log(`auth-web e2e harness listening on ${ORIGIN}`);
