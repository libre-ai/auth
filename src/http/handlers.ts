import { secureResponse } from "@libre-ai/web-platform";

import { verifyCsrf } from "../csrf/verify";
import { type OidcLoginFlow, RETURN_PATH_PATTERN } from "../oidc/transaction";
import { randomOpaqueValue } from "../session/digest";
import {
  CANONICAL_REVOCATION_REASON,
  type CreatedSession,
  type SessionService,
} from "../session/lifecycle";

export const OIDC_TRANSACTION_COOKIE = "__Host-libre_ai_oidc";
export const SESSION_COOKIE = "__Host-libre_ai_session";

const IDEMPOTENCY_KEY_PATTERN = /^idem_[a-z0-9]{16,64}$/;
const REVISION_PATTERN = /^"[0-9]+"$/;

export interface AuthHttpBoundaryOptions {
  allowedOrigin: string;
  flow: OidcLoginFlow;
  sessions: SessionService;
}

// HTTP boundary for the four browser endpoints of auth.v1. The
// /v1/internal/* Biscuit surface belongs to the authorization issuer and is
// intentionally absent. Refusals never disclose whether a user, tenant or
// session exists; messages repeat the stable code only.
export class AuthHttpBoundary {
  constructor(private readonly options: AuthHttpBoundaryOptions) {}

  handleLogin(request: Request): Promise<Response> {
    return guarded((requestId) => this.login(request, requestId));
  }

  handleCallback(request: Request): Promise<Response> {
    return guarded((requestId) => this.callback(request, requestId));
  }

  handleGetSession(request: Request): Promise<Response> {
    return guarded((requestId) => this.readSession(request, requestId));
  }

  handleDeleteSession(request: Request): Promise<Response> {
    return guarded((requestId) => this.deleteSession(request, requestId));
  }

  private async login(request: Request, requestId: string): Promise<Response> {
    if (!this.originAllowed(request)) {
      return problemResponse(403, "auth.csrf_invalid", requestId);
    }
    if (!mutationFormatsValid(request)) {
      return problemResponse(400, "auth.csrf_invalid", requestId);
    }
    const returnPath = await readReturnPath(request);
    if (returnPath === null) {
      return problemResponse(400, "auth.oidc_state_invalid", requestId);
    }
    const started = await this.options.flow.start(returnPath);
    const response = Response.json(
      { authorizationUrl: started.authorizationUrl },
      {
        headers: {
          "Set-Cookie": `${OIDC_TRANSACTION_COOKIE}=${started.transactionCookieValue}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
        },
        status: 200,
      },
    );
    return secureResponse(response);
  }

  private async callback(request: Request, requestId: string): Promise<Response> {
    const url = new URL(request.url);
    const code = url.searchParams.get("code") ?? "";
    const state = url.searchParams.get("state") ?? "";
    const transactionCookie = readCookie(request, OIDC_TRANSACTION_COOKIE);
    if (
      code.length < 16 ||
      code.length > 4096 ||
      state.length < 32 ||
      state.length > 512 ||
      transactionCookie === null
    ) {
      return problemResponse(400, "auth.oidc_state_invalid", requestId);
    }

    const completed = await this.options.flow.complete({ code, state }, transactionCookie);
    if (!completed.ok) {
      return problemResponse(400, completed.code, requestId);
    }

    // `createSession` fails closed — an unstorable record must not yield a
    // cookie that authenticates nothing — and this is the only endpoint that
    // calls it. That refusal is answered by the fence around every handler
    // below, as `500 web.internal_error`: the browser is owed a response
    // either way, and the failure is a server fault rather than an auth
    // refusal, so it maps onto the platform's generic code instead of
    // extending the auth refusal table.
    const created: CreatedSession = await this.options.sessions.createSession(completed.facts);
    const response = new Response(null, {
      headers: { Location: completed.returnPath },
      status: 303,
    });
    response.headers.append(
      "Set-Cookie",
      `${SESSION_COOKIE}=${created.cookieValue}; Secure; HttpOnly; SameSite=Strict; Path=/`,
    );
    response.headers.append(
      "Set-Cookie",
      `${OIDC_TRANSACTION_COOKIE}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
    );
    return secureResponse(response);
  }

  private async readSession(request: Request, requestId: string): Promise<Response> {
    const cookieValue = readCookie(request, SESSION_COOKIE);
    if (cookieValue === null) {
      return problemResponse(401, "auth.session_missing", requestId);
    }
    const resolved = await this.options.sessions.resolveSession(cookieValue);
    if (!resolved.ok) {
      return problemResponse(401, resolved.code, requestId);
    }
    return secureResponse(
      Response.json(
        {
          absoluteExpiresAt: resolved.record.absoluteExpiresAt,
          idleExpiresAt: resolved.record.idleExpiresAt,
          revision: resolved.record.revision,
          roles: resolved.record.roles,
          tenantId: resolved.record.tenantId,
          userId: resolved.record.userId,
        },
        { status: 200 },
      ),
    );
  }

  private async deleteSession(request: Request, requestId: string): Promise<Response> {
    const cookieValue = readCookie(request, SESSION_COOKIE);
    if (cookieValue === null) {
      return problemResponse(401, "auth.session_missing", requestId);
    }
    const resolved = await this.options.sessions.resolveSession(cookieValue);
    if (!resolved.ok) {
      return problemResponse(401, resolved.code, requestId);
    }
    if (!mutationFormatsValid(request)) {
      return problemResponse(400, "auth.csrf_invalid", requestId);
    }
    const csrf = await verifyCsrf({
      allowedOrigin: this.options.allowedOrigin,
      csrfSecretDigest: resolved.record.csrfSecretDigest,
      csrfToken: request.headers.get("X-CSRF-Token"),
      origin: request.headers.get("Origin"),
      secFetchSite: request.headers.get("Sec-Fetch-Site"),
    });
    if (!csrf.ok) {
      return problemResponse(403, "auth.csrf_invalid", requestId);
    }
    const expectedRevision = request.headers.get("If-Match");
    if (expectedRevision !== `"${resolved.record.revision}"`) {
      return problemResponse(412, "auth.session_revision_mismatch", requestId);
    }

    // The 412 above is the client's precondition, and the only one on this
    // path. The revocation itself carries no revision precondition — it is
    // monotone and terminal, so it lands whatever concurrent writers did, and
    // 204 here never means "cleared your cookie for a logout that did not
    // happen". If the adapter under it fails, the fence answers a problem and
    // the two lines below never run: the cookie survives a logout that did
    // not land, which is the direction a failure must fall.
    await this.options.sessions.revokeSession(cookieValue, CANONICAL_REVOCATION_REASON);
    const response = new Response(null, { status: 204 });
    response.headers.append(
      "Set-Cookie",
      `${SESSION_COOKIE}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
    );
    return secureResponse(response);
  }

  private originAllowed(request: Request): boolean {
    const secFetchSite = request.headers.get("Sec-Fetch-Site");
    return (
      request.headers.get("Origin") === this.options.allowedOrigin &&
      (secFetchSite === null || secFetchSite === "same-origin")
    );
  }
}

// Every handler is the outermost frame of a browser request, and every one of
// them calls an adapter that can fail for reasons the handler does not
// control — a store round trip, a token endpoint. The browser is owed a
// Response; an escaped throw is a request that answers nothing, on a path
// that may already have mutated server state. The request id is minted here
// so a refusal and the fence that replaces it are indistinguishable from
// outside, and the error itself is never echoed: a refusal discloses the
// stable code only.
async function guarded(run: (requestId: string) => Promise<Response>): Promise<Response> {
  const requestId = newRequestId();
  try {
    return await run(requestId);
  } catch {
    return problemResponse(500, "web.internal_error", requestId);
  }
}

function mutationFormatsValid(request: Request): boolean {
  const idempotencyKey = request.headers.get("Idempotency-Key");
  const revision = request.headers.get("If-Match");
  return (
    idempotencyKey !== null &&
    IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey) &&
    revision !== null &&
    REVISION_PATTERN.test(revision)
  );
}

function newRequestId(): string {
  return `req_${randomOpaqueValue()
    .toLowerCase()
    .replaceAll(/[^a-z0-9]/g, "")
    .slice(0, 24)}`;
}

function problemResponse(status: number, code: string, requestId: string): Response {
  return secureResponse(
    Response.json(
      { error: { code, message: code, requestId } },
      { headers: { "Content-Type": "application/problem+json" }, status },
    ),
  );
}

async function readReturnPath(request: Request): Promise<string | null> {
  try {
    const body: unknown = await request.json();
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return null;
    }
    const returnPath = (body as Record<string, unknown>).returnPath;
    if (
      typeof returnPath !== "string" ||
      returnPath.length > 512 ||
      !RETURN_PATH_PATTERN.test(returnPath)
    ) {
      return null;
    }
    return returnPath;
  } catch {
    return null;
  }
}

function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (header === null) {
    return null;
  }
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      const value = rest.join("=");
      return value.length === 0 ? null : value;
    }
  }
  return null;
}
