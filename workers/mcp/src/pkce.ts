/**
 * PKCE + flow-binding crypto for the interactive login.
 *
 * Vendored rather than imported: the MCP worker is dependency-isolated from
 * packages/backend (workspace "vendor, don't depend" rule), so the S256
 * transformation lives in two places on purpose. It must stay byte-identical
 * to packages/backend/src/lib/deliver-session.ts — the challenge this file
 * computes is verified against the verifier that one hashes.
 */

/** A PKCE code verifier: 43-128 unreserved characters (RFC 7636 §4.1). */
export function generateVerifier(): string {
  return randomToken(32);
}

/** base64url(SHA-256(verifier)) — the PKCE S256 transformation. */
export async function s256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}

/** Hex SHA-256, used to store a browser secret without storing the secret. */
export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** base64url of `bytes` random bytes — 32 bytes yields 43 chars. */
export function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return b64url(buf);
}

/** Length-independent comparison for secrets that arrive from the network. */
export function timingSafeEqual(a: string, b: string): boolean {
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
