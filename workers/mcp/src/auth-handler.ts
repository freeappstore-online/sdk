/**
 * OAuth default handler — the interactive login flow that @cloudflare/workers-
 * oauth-provider delegates to. The provider itself handles /register, /token,
 * the discovery docs, and the 401 challenge; this only owns the human step:
 * bounce the user to FreeAppStore's GitHub login, redeem what comes back, and
 * hand the provider the user + props via completeAuthorization.
 *
 * The session never travels in a URL. FAS is called with `response_mode=code`,
 * so the browser is redirected back with a one-time code that is worthless on
 * its own; this worker trades it for the session over a server-to-server POST,
 * authenticating itself with a PKCE verifier that never left the worker. The
 * previous contract put a reusable `?fas_session=` bearer token in the callback
 * URL, where it landed in request logs and browser history.
 *
 * Three independent things must line up for a callback to be accepted:
 *
 *   nonce   — keys the pending flow in KV; single-use, 10 minute TTL.
 *   state   — echoed through the provider round-trip and compared to the
 *             value recorded when the flow started.
 *   cookie  — an HttpOnly secret set at /authorize, stored only as a hash.
 *             This is what makes the flow browser-bound: nonce and state are
 *             both visible to the FAS backend and to anything that observes
 *             the redirect chain, but the cookie is not, so a captured
 *             callback URL cannot be replayed from another browser.
 */

import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { generateVerifier, randomToken, s256Challenge, sha256Hex, timingSafeEqual } from "./pkce.js";
import { parseScopes } from "./safety.js";
import { verifySession } from "./session.js";

type Bindings = {
  OAUTH_KV: KVNamespace;
  API_BASE: string;
  SESSION_SIGNING_KEY?: string;
  OAUTH_PROVIDER: OAuthHelpers;
};

/** How long the user has to finish the GitHub round-trip. */
const FLOW_TTL_SECONDS = 600;

const COOKIE_BASE = "fas_mcp_flow";

/** The pending flow, held in KV under `authreq:<nonce>` for one round-trip. */
interface PendingAuth {
  req: AuthRequest;
  /** Echoed via return_to and compared on the way back. */
  state: string;
  /** PKCE verifier — presented to the backend to redeem the code. */
  codeVerifier: string;
  /** SHA-256 of the browser cookie secret; the secret itself is never stored. */
  browserHash: string;
}

const app = new Hono<{ Bindings: Bindings }>();

/** GET /authorize — record the MCP client's OAuth request plus fresh state,
 *  PKCE verifier and browser secret, then send the user to FreeAppStore's
 *  GitHub login in code mode. */
app.get("/authorize", async (c) => {
  const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
  if (!oauthReqInfo.clientId) return c.text("Invalid request", 400);

  const nonce = crypto.randomUUID();
  const state = randomToken();
  const codeVerifier = generateVerifier();
  const browserSecret = randomToken();

  const pending: PendingAuth = {
    req: oauthReqInfo,
    state,
    codeVerifier,
    browserHash: await sha256Hex(browserSecret),
  };
  await c.env.OAUTH_KV.put(`authreq:${nonce}`, JSON.stringify(pending), {
    expirationTtl: FLOW_TTL_SECONDS,
  });

  const callback = new URL("/callback", c.req.url);
  callback.searchParams.set("nonce", nonce);
  callback.searchParams.set("state", state);

  const login = new URL(`${c.env.API_BASE}/v1/auth/github/start`);
  login.searchParams.set("response_mode", "code");
  login.searchParams.set("code_challenge", await s256Challenge(codeVerifier));
  login.searchParams.set("code_challenge_method", "S256");
  login.searchParams.set("app_id", "mcp");
  login.searchParams.set("return_to", callback.toString());

  // Built by hand rather than c.redirect so the Set-Cookie rides along.
  return new Response(null, {
    status: 302,
    headers: {
      Location: login.toString(),
      "Set-Cookie": flowCookie(c.req.url, browserSecret),
    },
  });
});

/** GET /callback — FAS returns here with `?code=…`. Validate the flow is the
 *  one this browser started, redeem the code for the session, and issue the
 *  MCP access token carrying the session + granted scopes as props (available
 *  as `this.props` inside the MCP agent). */
app.get("/callback", async (c) => {
  // Refuse the old contract outright. If FAS ever regresses to query delivery,
  // this fails loudly instead of silently accepting a token from the URL.
  if (c.req.query("fas_session")) {
    return c.text("fas_session in the callback URL is no longer accepted", 400);
  }

  const nonce = c.req.query("nonce");
  const state = c.req.query("state");
  const code = c.req.query("code");
  if (!nonce || !state || !code) return c.text("missing nonce, state or code", 400);

  const raw = await c.env.OAUTH_KV.get(`authreq:${nonce}`);
  if (!raw) return c.text("invalid or expired nonce", 400);
  // Single-use: burn the pending flow before doing anything with it, so a
  // replayed callback finds nothing regardless of how the rest goes.
  await c.env.OAUTH_KV.delete(`authreq:${nonce}`);

  let pending: PendingAuth;
  try {
    pending = JSON.parse(raw) as PendingAuth;
  } catch {
    return c.text("invalid OAuth request", 400);
  }
  if (!pending.req?.clientId) return c.text("invalid OAuth request", 400);

  if (!timingSafeEqual(state, pending.state)) return c.text("state mismatch", 400);

  const browserSecret = readFlowCookie(c.req.raw, c.req.url);
  if (!browserSecret || !timingSafeEqual(await sha256Hex(browserSecret), pending.browserHash)) {
    return c.text("this sign-in was started in a different browser — start again", 400);
  }

  const fasSession = await exchangeCode(c.env.API_BASE, code, pending.codeVerifier);
  if (!fasSession) return c.text("could not redeem the sign-in code — start again", 400);

  const payload = c.env.SESSION_SIGNING_KEY
    ? await verifySession(fasSession, c.env.SESSION_SIGNING_KEY)
    : null;
  if (!payload) return c.text("invalid session", 400);

  const scopes = parseScopes(pending.req.scope);
  // The provider's tokens/codes are `userId:grantId:secret`, so the userId must
  // not contain a colon. FAS uids are `gh:123` / `google:<sub>` — pass a
  // colon-free id to the library and keep the real uid in props (used for
  // scoping + audit).
  const libUserId = payload.uid.replace(/:/g, "_");
  const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
    request: pending.req,
    userId: libUserId,
    scope: scopes,
    metadata: { label: payload.uid },
    props: { userId: payload.uid, token: fasSession, scopes },
  });
  return new Response(null, {
    status: 302,
    headers: { Location: redirectTo, "Set-Cookie": clearFlowCookie(c.req.url) },
  });
});

/** Trade the one-time code for the session, server to server. The verifier is
 *  the credential here — the code alone is not redeemable. */
async function exchangeCode(
  apiBase: string,
  code: string,
  codeVerifier: string,
): Promise<string | null> {
  const res = await fetch(`${apiBase}/v1/auth/session/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "freeappstore-mcp" },
    body: JSON.stringify({ code, code_verifier: codeVerifier }),
  });
  if (!res.ok) return null;
  const data = (await res.json().catch(() => null)) as { fas_session?: string } | null;
  return data?.fas_session ?? null;
}

// ── flow cookie ─────────────────────────────────────────────────
// `__Host-` (which requires Secure) in production; the bare name over http so
// `wrangler dev` on localhost still works.

function isSecure(url: string): boolean {
  return new URL(url).protocol === "https:";
}

function cookieName(url: string): string {
  return isSecure(url) ? `__Host-${COOKIE_BASE}` : COOKIE_BASE;
}

function flowCookie(url: string, value: string): string {
  // SameSite=Lax still sends the cookie on the top-level GET navigation that
  // FAS redirects the browser through; Strict would drop it and break login.
  return [
    `${cookieName(url)}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    ...(isSecure(url) ? ["Secure"] : []),
    `Max-Age=${FLOW_TTL_SECONDS}`,
  ].join("; ");
}

function clearFlowCookie(url: string): string {
  return [
    `${cookieName(url)}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    ...(isSecure(url) ? ["Secure"] : []),
    "Max-Age=0",
  ].join("; ");
}

function readFlowCookie(req: Request, url: string): string | null {
  const header = req.headers.get("Cookie");
  if (!header) return null;
  const name = cookieName(url);
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    return part.slice(eq + 1).trim() || null;
  }
  return null;
}

export { app as AuthHandler };
