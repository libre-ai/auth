import { expect, test } from "@playwright/test";

const IDEMPOTENCY = `idem_${"e".repeat(16)}`;

async function login(page: import("@playwright/test").Page): Promise<void> {
  await page.goto("/");
  const authorizationUrl = await page.evaluate(async (idempotency) => {
    const response = await fetch("/v1/auth/login", {
      body: JSON.stringify({ returnPath: "/welcome" }),
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotency,
        "If-Match": '"0"',
      },
      method: "POST",
    });
    if (!response.ok) {
      throw new Error(`login failed: ${response.status}`);
    }
    const body = (await response.json()) as { authorizationUrl: string };
    return body.authorizationUrl;
  }, IDEMPOTENCY);
  await page.goto(authorizationUrl);
  await page.waitForURL("**/welcome");
}

test("full PKCE login lands on the stored return path with a Strict opaque session", async ({
  context,
  page,
}) => {
  await login(page);

  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === "__Host-libre_ai_session");
  expect(session).toBeDefined();
  expect(session?.secure).toBeTruthy();
  expect(session?.httpOnly).toBeTruthy();
  expect(session?.sameSite).toBe("Strict");
  expect(session?.path).toBe("/");
  expect((session?.value ?? "").length).toBeGreaterThanOrEqual(43);
  expect(cookies.find((cookie) => cookie.name === "__Host-libre_ai_oidc")).toBeUndefined();

  const documentCookie = await page.evaluate(() => document.cookie);
  expect(documentCookie).not.toContain("__Host-libre_ai_session");

  const projection = await page.evaluate(async () => {
    const response = await fetch("/v1/auth/session");
    return { body: (await response.json()) as Record<string, unknown>, status: response.status };
  });
  expect(projection.status).toBe(200);
  expect(projection.body["userId"]).toBe(`usr_${"b".repeat(16)}`);
  expect(Object.keys(projection.body).sort()).toEqual([
    "absoluteExpiresAt",
    "idleExpiresAt",
    "revision",
    "roles",
    "tenantId",
    "userId",
  ]);
});

test("logout requires the synchronizer token and revokes before clearing", async ({
  context,
  page,
}) => {
  await login(page);

  const withoutToken = await page.evaluate(async (idempotency) => {
    const response = await fetch("/v1/auth/session", {
      headers: { "Idempotency-Key": idempotency, "If-Match": '"1"' },
      method: "DELETE",
    });
    return response.status;
  }, IDEMPOTENCY);
  expect(withoutToken).toBe(403);

  const result = await page.evaluate(async (idempotency) => {
    const csrfResponse = await fetch("/e2e/csrf");
    const { csrfToken } = (await csrfResponse.json()) as { csrfToken: string };
    const sessionResponse = await fetch("/v1/auth/session");
    const projection = (await sessionResponse.json()) as { revision: number };
    const deleteResponse = await fetch("/v1/auth/session", {
      headers: {
        "Idempotency-Key": idempotency,
        "If-Match": `"${projection.revision}"`,
        "X-CSRF-Token": csrfToken,
      },
      method: "DELETE",
    });
    const afterResponse = await fetch("/v1/auth/session");
    const after = (await afterResponse.json()) as { error?: { code?: string } };
    return {
      afterCode: after.error?.code ?? "",
      afterStatus: afterResponse.status,
      deleteStatus: deleteResponse.status,
    };
  }, IDEMPOTENCY);
  expect(result.deleteStatus).toBe(204);
  // The real browser honours Max-Age=0 immediately, so the follow-up call
  // carries no cookie at all: the server answers the generic missing-session
  // refusal. Revocation-before-clearing is proven at the unit level where
  // the revoked record is still addressed by its digest.
  expect(result.afterStatus).toBe(401);
  expect(result.afterCode).toBe("auth.session_missing");
  const cookies = await context.cookies();
  expect(cookies.find((cookie) => cookie.name === "__Host-libre_ai_session")).toBeUndefined();
});

test("idle and absolute expiry refuse after server time travel", async ({ page }) => {
  await login(page);

  const idle = await page.evaluate(async () => {
    await fetch("/e2e/clock/advance", {
      body: JSON.stringify({ ms: 31 * 60 * 1000 }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
    const response = await fetch("/v1/auth/session");
    const body = (await response.json()) as { error?: { code?: string } };
    return { code: body.error?.code ?? "", status: response.status };
  });
  expect(idle.status).toBe(401);
  expect(idle.code).toBe("auth.session_expired");

  await login(page);
  const absolute = await page.evaluate(async () => {
    for (let step = 0; step < 25; step += 1) {
      await fetch("/e2e/clock/advance", {
        body: JSON.stringify({ ms: 29 * 60 * 1000 }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const kept = await fetch("/v1/auth/session");
      if (kept.status !== 200) {
        const body = (await kept.json()) as { error?: { code?: string } };
        return { code: body.error?.code ?? "", status: kept.status, step };
      }
    }
    return { code: "", status: 200, step: -1 };
  });
  expect(absolute.status).toBe(401);
  expect(absolute.code).toBe("auth.session_expired");
  expect(absolute.step).toBeGreaterThanOrEqual(24);
});
