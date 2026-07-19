const encoder = new TextEncoder();

export function randomOpaqueValue(byteLength = 32): string {
  if (byteLength < 32) {
    throw new Error("auth.opaque_value_too_short");
  }
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toHex(new Uint8Array(digest));
}

export async function importHmacKey(rawKey: Uint8Array): Promise<CryptoKey> {
  if (rawKey.byteLength < 32) {
    throw new Error("auth.digest_key_too_short");
  }
  return crypto.subtle.importKey(
    "raw",
    rawKey as unknown as BufferSource,
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"],
  );
}

export async function hmacSha256Hex(key: CryptoKey, value: string): Promise<string> {
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return toHex(new Uint8Array(signature));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}
