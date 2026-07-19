import { describe, expect, test } from "bun:test";

import { sha256Hex } from "../session/digest";
import { verifyCsrf } from "./verify";

const ALLOWED_ORIGIN = "https://app.test.libre-ai.fr";
const TOKEN = "k".repeat(43);
const tokenDigest = await sha256Hex(TOKEN);

function baseInput() {
  return {
    allowedOrigin: ALLOWED_ORIGIN,
    csrfSecretDigest: tokenDigest,
    csrfToken: TOKEN,
    origin: ALLOWED_ORIGIN,
    secFetchSite: "same-origin" as string | null,
  };
}

describe("CSRF verification", () => {
  test("accepts exact origin, same-origin fetch metadata and matching token", async () => {
    expect(await verifyCsrf(baseInput())).toEqual({ ok: true });
  });

  test("accepts when fetch metadata is unavailable", async () => {
    expect(await verifyCsrf({ ...baseInput(), secFetchSite: null })).toEqual({ ok: true });
  });

  test.each([
    ["missing origin", { origin: null }],
    ["cross origin", { origin: "https://evil.example.org" }],
    ["subdomain origin", { origin: "https://sub.app.test.libre-ai.fr" }],
    ["http scheme origin", { origin: "http://app.test.libre-ai.fr" }],
    ["origin with trailing slash", { origin: `${ALLOWED_ORIGIN}/` }],
    ["cross-site fetch metadata", { secFetchSite: "cross-site" }],
    ["same-site fetch metadata", { secFetchSite: "same-site" }],
    ["missing token", { csrfToken: null }],
    ["empty token", { csrfToken: "" }],
    ["wrong token", { csrfToken: "w".repeat(43) }],
    ["token differing in last char", { csrfToken: `${"k".repeat(42)}x` }],
  ])("refuses with auth.csrf_invalid on %s", async (_label, override) => {
    expect(await verifyCsrf({ ...baseInput(), ...override })).toEqual({
      code: "auth.csrf_invalid",
      ok: false,
    });
  });

  test("refuses a token whose digest length differs without throwing", async () => {
    expect(await verifyCsrf({ ...baseInput(), csrfToken: "short" })).toEqual({
      code: "auth.csrf_invalid",
      ok: false,
    });
  });
});
