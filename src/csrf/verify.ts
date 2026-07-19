import { sha256Hex } from "../session/digest";

export interface CsrfCheckInput {
  allowedOrigin: string;
  csrfSecretDigest: string;
  csrfToken: string | null;
  origin: string | null;
  secFetchSite: string | null;
}

export type CsrfCheckResult = { ok: true } | { ok: false; code: "auth.csrf_invalid" };

const REFUSED: CsrfCheckResult = { code: "auth.csrf_invalid", ok: false };

export async function verifyCsrf(input: CsrfCheckInput): Promise<CsrfCheckResult> {
  if (input.origin === null || input.origin !== input.allowedOrigin) {
    return REFUSED;
  }
  // Fetch Metadata is enforced only where the browser sends it; a
  // cookie-authenticated mutation must then come from the same origin.
  if (input.secFetchSite !== null && input.secFetchSite !== "same-origin") {
    return REFUSED;
  }
  if (input.csrfToken === null || input.csrfToken.length === 0) {
    return REFUSED;
  }
  const presented = await sha256Hex(input.csrfToken);
  if (!constantTimeEqual(presented, input.csrfSecretDigest)) {
    return REFUSED;
  }
  return { ok: true };
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}
