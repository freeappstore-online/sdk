/**
 * Session delivery for the OAuth / magic-link callbacks.
 *
 * Every provider callback ends the same way: it has a freshly signed session
 * and a validated `return_to`, and has to hand the session back to whoever
 * started the flow. There are three ways to do that, chosen by `response_mode`
 * on the /start call:
 *
 *  - `code`     — a one-time code in the query string; the caller exchanges it
 *                 for the session at POST /v1/auth/session/exchange. The
 *                 session itself never appears in a URL. This is the mode
 *                 server-side callers (MCP workers) must use, since a redirect
 *                 they receive is recorded in their request logs.
 *  - `query`    — session in `?fas_session=`. Legacy; kept for existing
 *                 callers, but it puts a reusable bearer token in a URL.
 *  - (default)  — session in the URL fragment, which browsers never send to a
 *                 server. Correct for SPAs using the SDK, useless for a
 *                 server-side callback.
 *
 * `code` mode requires PKCE (RFC 7636, S256): the initiator registers a
 * `code_challenge` at /start and presents the matching `code_verifier` at the
 * exchange. A code scraped from a log or a Referer header is not redeemable
 * without the verifier, which never leaves the initiator.
 */

import type { Env } from '../types.js';
import { timingSafeEqual } from './session.js';

/** Codes are redeemed immediately by a server-side caller; keep the window tight. */
export const AUTH_CODE_TTL_SECONDS = 60;

/** The parts of a validated OAuth/magic-link state that delivery depends on. */
export interface SessionDelivery {
  appId: string;
  returnTo: string;
  responseMode?: string;
  codeChallenge?: string;
}

export type DeliveryResult = { ok: true; url: string } | { ok: false; error: string };

/**
 * Build the redirect URL that hands `session` back to the caller, minting and
 * storing a one-time code first when `response_mode=code`.
 */
export async function deliverSession(
  env: Pick<Env, 'DB'>,
  delivery: SessionDelivery,
  session: string,
): Promise<DeliveryResult> {
  const redirect = new URL(delivery.returnTo);

  if (delivery.responseMode === 'code') {
    // Enforced at /start too; re-checked here because the state is signed and
    // long-lived enough that a code-mode flow must never silently downgrade to
    // putting the session in the URL.
    if (!delivery.codeChallenge) {
      return { ok: false, error: 'response_mode=code requires code_challenge' };
    }
    const code = randomCode();
    await env.DB.prepare(
      'INSERT INTO auth_codes (code_hash, session, app_id, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?)',
    )
      .bind(
        await sha256Hex(code),
        session,
        delivery.appId,
        delivery.codeChallenge,
        Math.floor(Date.now() / 1000) + AUTH_CODE_TTL_SECONDS,
      )
      .run();
    redirect.searchParams.set('code', code);
  } else if (delivery.responseMode === 'query') {
    redirect.searchParams.set('fas_session', session);
  } else {
    redirect.hash = `fas_session=${encodeURIComponent(session)}`;
  }

  return { ok: true, url: redirect.toString() };
}

/**
 * Redeem a one-time code for its session. Returns null for anything that
 * isn't a live, unredeemed code with a matching PKCE verifier — callers
 * should not distinguish the reasons to the client.
 */
export async function exchangeAuthCode(
  env: Pick<Env, 'DB'>,
  code: string,
  codeVerifier: string,
): Promise<string | null> {
  const codeHash = await sha256Hex(code);
  const row = await env.DB.prepare(
    'SELECT session, code_challenge, expires_at FROM auth_codes WHERE code_hash = ?',
  )
    .bind(codeHash)
    .first<{ session: string; code_challenge: string; expires_at: number }>();
  if (!row) return null;

  // Claim the code before validating anything else. The DELETE's change count
  // is what makes redemption single-use under concurrency — two racing
  // exchanges both read the row, but only one deletes it. It also means a
  // wrong verifier burns the code instead of leaving it redeemable.
  const deleted = await env.DB.prepare('DELETE FROM auth_codes WHERE code_hash = ?')
    .bind(codeHash)
    .run();
  if (!deleted.meta?.changes) return null;

  if (row.expires_at < Math.floor(Date.now() / 1000)) return null;
  if (!timingSafeEqual(await s256Challenge(codeVerifier), row.code_challenge)) return null;
  return row.session;
}

/** base64url(SHA-256(verifier)) — the PKCE S256 transformation. */
export async function s256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}

function randomCode(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return b64url(bytes);
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function b64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
