import { Apple, decodeIdToken, Google, generateCodeVerifier, generateState } from 'arctic';
import { Hono } from 'hono';
import { HttpError, isAdminLogin, requireUser } from '../lib/auth.js';
import { deliverSession, exchangeAuthCode } from '../lib/deliver-session.js';
import { isLikelyEmail, normalizeEmail, sendEmail } from '../lib/email.js';
import { isAllowedReturnTo } from '../lib/origins.js';
import { signPayload, signSession, verifyPayload } from '../lib/session.js';
import type { Env } from '../types.js';

interface OAuthState {
  appId: string;
  returnTo: string;
  responseMode?: string;
  codeChallenge?: string;
  exp: number;
}

interface GoogleOAuthState {
  appId: string;
  returnTo: string;
  codeVerifier: string;
  responseMode?: string;
  codeChallenge?: string;
  exp: number;
}

interface AppleOAuthState {
  appId: string;
  returnTo: string;
  responseMode?: string;
  codeChallenge?: string;
  exp: number;
}

interface EmailMagicState {
  email: string;
  appId: string;
  returnTo: string;
  responseMode?: string;
  codeChallenge?: string;
  exp: number;
}

/**
 * Validate the PKCE parameters on a /start request. Only `response_mode=code`
 * uses them, and for that mode they are mandatory — a code-mode flow started
 * without a challenge would have nothing binding the eventual code to its
 * initiator, so it is rejected here rather than at the callback (by which
 * point the user has already been through the provider).
 */
function readCodeChallenge(
  responseMode: string | undefined,
  codeChallenge: string | undefined,
  method: string | undefined,
): { ok: true; codeChallenge?: string } | { ok: false; error: string } {
  if (responseMode !== 'code') return { ok: true };
  if (!codeChallenge) return { ok: false, error: 'response_mode=code requires code_challenge' };
  if (method && method !== 'S256') {
    return { ok: false, error: 'code_challenge_method must be S256' };
  }
  return { ok: true, codeChallenge };
}

const STATE_TTL_SECONDS = 10 * 60;
const MAGIC_LINK_TTL_SECONDS = 15 * 60;

// Best-effort per-recipient throttle for magic-link sends (per-isolate, same
// pattern as friends.ts rate limits). Stops an unauthenticated caller from
// email-bombing a victim address / burning the Resend quota.
const EMAIL_SEND_COOLDOWN_MS = 60_000;
const emailSendMap = new Map<string, number>();

export const authRoutes = new Hono<{ Bindings: Env }>();

authRoutes.get('/auth/github/start', async (c) => {
  const appId = c.req.query('app_id') ?? '';
  const returnTo = c.req.query('return_to') ?? '';
  const responseMode = c.req.query('response_mode');
  if (!appId || !returnTo) return c.text('missing app_id or return_to', 400);
  if (!isAllowedReturnTo(returnTo, appId)) return c.text('return_to not allowed', 400);
  const pkce = readCodeChallenge(
    responseMode,
    c.req.query('code_challenge'),
    c.req.query('code_challenge_method'),
  );
  if (!pkce.ok) return c.text(pkce.error, 400);

  const state = await signPayload<OAuthState>(
    {
      appId,
      returnTo,
      ...(responseMode ? { responseMode } : {}),
      ...(pkce.codeChallenge ? { codeChallenge: pkce.codeChallenge } : {}),
      exp: Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS,
    },
    c.env.SESSION_SIGNING_KEY,
  );
  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', c.env.GITHUB_CLIENT_ID);
  url.searchParams.set('scope', 'read:user');
  url.searchParams.set('state', state);
  url.searchParams.set('redirect_uri', new URL('/v1/auth/github/callback', c.req.url).toString());
  return c.redirect(url.toString());
});

authRoutes.get('/auth/github/callback', async (c) => {
  const code = c.req.query('code');
  const stateRaw = c.req.query('state');
  if (!code || !stateRaw) return c.text('missing code or state', 400);

  const state = await verifyPayload<OAuthState>(stateRaw, c.env.SESSION_SIGNING_KEY);
  if (!state) return c.text('invalid state', 400);
  if (state.exp < Math.floor(Date.now() / 1000)) return c.text('state expired', 400);
  if (!isAllowedReturnTo(state.returnTo, state.appId)) return c.text('return_to not allowed', 400);

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: c.env.GITHUB_CLIENT_ID,
      client_secret: c.env.GITHUB_CLIENT_SECRET,
      code,
    }),
  });
  const tok = (await tokenRes.json()) as { access_token?: string; error?: string };
  if (!tok.access_token) return c.text(`github oauth: ${tok.error ?? 'unknown'}`, 400);

  const userRes = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${tok.access_token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'freeappstore-api',
    },
  });
  if (!userRes.ok) return c.text('failed to fetch github user', 502);
  const ghUser = (await userRes.json()) as {
    id: number;
    login: string;
    avatar_url: string | null;
  };

  const userId = `gh:${ghUser.id}`;
  await c.env.DB.prepare(
    `INSERT INTO users (id, github_id, github_login, avatar_url, created_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       github_login = excluded.github_login,
       avatar_url = excluded.avatar_url`,
  )
    .bind(userId, ghUser.id, ghUser.login, ghUser.avatar_url, Date.now())
    .run();

  const { roles, appRoles } = await computeRoles(userId, ghUser.login, c.env);
  const session = await signSession(userId, c.env.SESSION_SIGNING_KEY, { roles, appRoles });
  const delivery = await deliverSession(c.env, state, session);
  if (!delivery.ok) return c.text(delivery.error, 400);
  return c.redirect(delivery.url);
});

authRoutes.get('/auth/google/start', async (c) => {
  const appId = c.req.query('app_id') ?? '';
  const returnTo = c.req.query('return_to') ?? '';
  const responseMode = c.req.query('response_mode');
  if (!appId || !returnTo) return c.text('missing app_id or return_to', 400);
  if (!isAllowedReturnTo(returnTo, appId)) return c.text('return_to not allowed', 400);
  const pkce = readCodeChallenge(
    responseMode,
    c.req.query('code_challenge'),
    c.req.query('code_challenge_method'),
  );
  if (!pkce.ok) return c.text(pkce.error, 400);

  if (!c.env.GOOGLE_CLIENT_ID || !c.env.GOOGLE_CLIENT_SECRET) {
    return c.text('Google OAuth not configured', 503);
  }

  const redirectUri = new URL('/v1/auth/google/callback', c.req.url).toString();
  const google = new Google(c.env.GOOGLE_CLIENT_ID, c.env.GOOGLE_CLIENT_SECRET, redirectUri);

  const _state = generateState();
  const codeVerifier = generateCodeVerifier();

  const signedState = await signPayload<GoogleOAuthState>(
    {
      appId,
      returnTo,
      codeVerifier,
      ...(responseMode ? { responseMode } : {}),
      ...(pkce.codeChallenge ? { codeChallenge: pkce.codeChallenge } : {}),
      exp: Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS,
    },
    c.env.SESSION_SIGNING_KEY,
  );

  const url = google.createAuthorizationURL(signedState, codeVerifier, [
    'openid',
    'profile',
    'email',
  ]);
  return c.redirect(url.toString());
});

authRoutes.get('/auth/google/callback', async (c) => {
  const code = c.req.query('code');
  const stateRaw = c.req.query('state');
  if (!code || !stateRaw) return c.text('missing code or state', 400);

  const state = await verifyPayload<GoogleOAuthState>(stateRaw, c.env.SESSION_SIGNING_KEY);
  if (!state) return c.text('invalid state', 400);
  if (state.exp < Math.floor(Date.now() / 1000)) return c.text('state expired', 400);
  if (!isAllowedReturnTo(state.returnTo, state.appId)) return c.text('return_to not allowed', 400);

  if (!c.env.GOOGLE_CLIENT_ID || !c.env.GOOGLE_CLIENT_SECRET) {
    return c.text('Google OAuth not configured', 503);
  }

  const redirectUri = new URL('/v1/auth/google/callback', c.req.url).toString();
  const google = new Google(c.env.GOOGLE_CLIENT_ID, c.env.GOOGLE_CLIENT_SECRET, redirectUri);

  try {
    const tokens = await google.validateAuthorizationCode(code, state.codeVerifier);
    const claims = decodeIdToken(tokens.idToken()) as {
      sub: string;
      name?: string;
      email?: string;
      picture?: string;
    };

    const userId = `google:${claims.sub}`;
    const login = claims.email ? (claims.email.split('@')[0] ?? claims.sub) : claims.sub;
    const displayName = claims.name ?? login;

    await c.env.DB.prepare(
      `INSERT INTO users (id, github_id, github_login, avatar_url, created_at, provider, provider_id, email, display_name)
       VALUES (?, 0, ?, ?, ?, 'google', ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         avatar_url = excluded.avatar_url,
         email = excluded.email,
         display_name = excluded.display_name`,
    )
      .bind(
        userId,
        login,
        claims.picture ?? null,
        Date.now(),
        claims.sub,
        claims.email ?? null,
        displayName,
      )
      .run();

    const { roles, appRoles } = await computeRoles(userId, login, c.env, 'google');
    const session = await signSession(userId, c.env.SESSION_SIGNING_KEY, { roles, appRoles });
    const delivery = await deliverSession(c.env, state, session);
    if (!delivery.ok) return c.text(delivery.error, 400);
    return c.redirect(delivery.url);
  } catch (err) {
    console.error('Google OAuth callback error:', err);
    return c.text(
      `Google sign-in failed: ${err instanceof Error ? err.message : 'unknown error'}`,
      500,
    );
  }
});

// ---------------------------------------------------------------------------
// Apple Sign In
// ---------------------------------------------------------------------------

authRoutes.get('/auth/apple/start', async (c) => {
  const appId = c.req.query('app_id') ?? '';
  const returnTo = c.req.query('return_to') ?? '';
  const responseMode = c.req.query('response_mode');
  if (!appId || !returnTo) return c.text('missing app_id or return_to', 400);
  if (!isAllowedReturnTo(returnTo, appId)) return c.text('return_to not allowed', 400);
  const pkce = readCodeChallenge(
    responseMode,
    c.req.query('code_challenge'),
    c.req.query('code_challenge_method'),
  );
  if (!pkce.ok) return c.text(pkce.error, 400);

  if (
    !c.env.APPLE_CLIENT_ID ||
    !c.env.APPLE_TEAM_ID ||
    !c.env.APPLE_KEY_ID ||
    !c.env.APPLE_PRIVATE_KEY
  ) {
    return c.text('Apple Sign In not configured', 503);
  }

  const redirectUri = new URL('/v1/auth/apple/callback', c.req.url).toString();
  const privateKeyBytes = Uint8Array.from(atob(c.env.APPLE_PRIVATE_KEY), (ch) => ch.charCodeAt(0));
  const apple = new Apple(
    c.env.APPLE_CLIENT_ID,
    c.env.APPLE_TEAM_ID,
    c.env.APPLE_KEY_ID,
    privateKeyBytes,
    redirectUri,
  );

  const signedState = await signPayload<AppleOAuthState>(
    {
      appId,
      returnTo,
      ...(responseMode ? { responseMode } : {}),
      ...(pkce.codeChallenge ? { codeChallenge: pkce.codeChallenge } : {}),
      exp: Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS,
    },
    c.env.SESSION_SIGNING_KEY,
  );

  const url = apple.createAuthorizationURL(signedState, ['name', 'email']);
  return c.redirect(url.toString());
});

/**
 * Apple callback is a POST (form_post response_mode).
 * Apple sends user info (name, email) in the request body only on first sign-in.
 */
authRoutes.post('/auth/apple/callback', async (c) => {
  const body = await c.req.parseBody();
  const code = body.code as string | undefined;
  const stateRaw = body.state as string | undefined;
  const userJson = body.user as string | undefined; // only on first sign-in

  if (!code || !stateRaw) return c.text('missing code or state', 400);

  const state = await verifyPayload<AppleOAuthState>(stateRaw, c.env.SESSION_SIGNING_KEY);
  if (!state) return c.text('invalid state', 400);
  if (state.exp < Math.floor(Date.now() / 1000)) return c.text('state expired', 400);
  if (!isAllowedReturnTo(state.returnTo, state.appId)) return c.text('return_to not allowed', 400);

  if (
    !c.env.APPLE_CLIENT_ID ||
    !c.env.APPLE_TEAM_ID ||
    !c.env.APPLE_KEY_ID ||
    !c.env.APPLE_PRIVATE_KEY
  ) {
    return c.text('Apple Sign In not configured', 503);
  }

  const redirectUri = new URL('/v1/auth/apple/callback', c.req.url).toString();
  const privateKeyBytes = Uint8Array.from(atob(c.env.APPLE_PRIVATE_KEY), (ch) => ch.charCodeAt(0));
  const apple = new Apple(
    c.env.APPLE_CLIENT_ID,
    c.env.APPLE_TEAM_ID,
    c.env.APPLE_KEY_ID,
    privateKeyBytes,
    redirectUri,
  );

  try {
    const tokens = await apple.validateAuthorizationCode(code);
    const claims = decodeIdToken(tokens.idToken()) as {
      sub: string;
      email?: string;
    };

    // Apple sends user name only on first sign-in, in the POST body
    let displayName: string | null = null;
    if (userJson) {
      try {
        const appleUser = JSON.parse(userJson) as {
          name?: { firstName?: string; lastName?: string };
        };
        const first = appleUser.name?.firstName ?? '';
        const last = appleUser.name?.lastName ?? '';
        displayName = [first, last].filter(Boolean).join(' ') || null;
      } catch {
        // malformed user JSON — ignore, use email/sub
      }
    }

    const userId = `apple:${claims.sub}`;
    const login = claims.email ? (claims.email.split('@')[0] ?? claims.sub) : claims.sub;

    await c.env.DB.prepare(
      `INSERT INTO users (id, github_id, github_login, avatar_url, created_at, provider, provider_id, email, display_name)
       VALUES (?, 0, ?, NULL, ?, 'apple', ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         email = COALESCE(excluded.email, users.email),
         display_name = COALESCE(excluded.display_name, users.display_name)`,
    )
      .bind(userId, login, Date.now(), claims.sub, claims.email ?? null, displayName ?? login)
      .run();

    const { roles, appRoles } = await computeRoles(userId, login, c.env, 'apple');
    const session = await signSession(userId, c.env.SESSION_SIGNING_KEY, { roles, appRoles });
    const delivery = await deliverSession(c.env, state, session);
    if (!delivery.ok) return c.text(delivery.error, 400);
    return c.redirect(delivery.url);
  } catch (err) {
    console.error('Apple OAuth callback error:', err);
    return c.text(
      `Apple sign-in failed: ${err instanceof Error ? err.message : 'unknown error'}`,
      500,
    );
  }
});

authRoutes.post('/auth/email/start', async (c) => {
  if (!c.env.RESEND_API_KEY || !c.env.EMAIL_FROM) {
    return c.text('Email auth not configured', 503);
  }

  const {
    email: rawEmail,
    appId,
    returnTo,
    responseMode,
    codeChallenge: rawCodeChallenge,
    codeChallengeMethod,
  } = await c.req.json<{
    email?: string;
    appId?: string;
    returnTo?: string;
    responseMode?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  }>();

  if (!rawEmail || !appId || !returnTo) {
    return c.text('missing email, appId, or returnTo', 400);
  }
  const pkce = readCodeChallenge(responseMode, rawCodeChallenge, codeChallengeMethod);
  if (!pkce.ok) return c.text(pkce.error, 400);
  // Normalize first (trim + lowercase) so UI-side whitespace doesn't reject
  // valid addresses; then validate the canonical form.
  const email = normalizeEmail(rawEmail);
  if (!isLikelyEmail(email)) return c.text('invalid email', 400);
  if (!isAllowedReturnTo(returnTo, appId)) return c.text('returnTo not allowed', 400);

  // Per-recipient send throttle. Silently succeed (don't leak account presence
  // or give an abuse oracle) but skip the actual send if within the cooldown.
  const nowMs = Date.now();
  if (emailSendMap.size > 5000) {
    for (const [k, t] of emailSendMap) {
      if (nowMs - t > EMAIL_SEND_COOLDOWN_MS) emailSendMap.delete(k);
    }
  }
  const lastSend = emailSendMap.get(email) ?? 0;
  if (nowMs - lastSend < EMAIL_SEND_COOLDOWN_MS) {
    return c.json({ ok: true });
  }
  emailSendMap.set(email, nowMs);

  const token = await signPayload<EmailMagicState>(
    {
      email,
      appId,
      returnTo,
      ...(responseMode ? { responseMode } : {}),
      ...(pkce.codeChallenge ? { codeChallenge: pkce.codeChallenge } : {}),
      exp: Math.floor(Date.now() / 1000) + MAGIC_LINK_TTL_SECONDS,
    },
    c.env.SESSION_SIGNING_KEY,
  );

  const callbackUrl = new URL('/v1/auth/email/callback', c.req.url);
  callbackUrl.searchParams.set('token', token);

  // The sign-in destination, displayed in the email body so the recipient
  // can sanity-check where this is taking them before they click.
  const dest = new URL(returnTo).origin;

  await sendEmail(
    { apiKey: c.env.RESEND_API_KEY, from: c.env.EMAIL_FROM },
    {
      to: email,
      subject: `Sign in to ${dest}`,
      text: `Click the link below to sign in to ${dest}.

${callbackUrl.toString()}

This link expires in 15 minutes. If you didn't request it, ignore this email.`,
      html: `<p>Click the link below to sign in to <strong>${dest}</strong>.</p>
<p><a href="${callbackUrl.toString()}">Sign in</a></p>
<p style="color:#888;font-size:12px">This link expires in 15 minutes. If you didn't request it, ignore this email.</p>`,
    },
  );

  // 200 regardless of whether the email exists — don't leak account presence.
  return c.json({ ok: true });
});

authRoutes.get('/auth/email/callback', async (c) => {
  const tokenRaw = c.req.query('token');
  if (!tokenRaw) return c.text('missing token', 400);

  const state = await verifyPayload<EmailMagicState>(tokenRaw, c.env.SESSION_SIGNING_KEY);
  if (!state) return c.text('invalid token', 400);
  if (state.exp < Math.floor(Date.now() / 1000)) return c.text('link expired', 400);
  if (!isAllowedReturnTo(state.returnTo, state.appId)) return c.text('returnTo not allowed', 400);

  // One-time-use: hash the token and reject if already consumed. Prevents
  // replay from server logs, Referer headers, or shared browser history.
  const tokenHash = await hashForReplay(tokenRaw);
  try {
    await c.env.DB.prepare('INSERT INTO consumed_tokens (hash, expires_at) VALUES (?, ?)')
      .bind(tokenHash, state.exp)
      .run();
  } catch {
    // UNIQUE constraint violation = token already used
    return c.text('link already used — request a new sign-in email', 400);
  }

  const userId = `email:${state.email}`;
  const login = state.email.split('@')[0] ?? state.email;

  await c.env.DB.prepare(
    `INSERT INTO users (id, github_id, github_login, avatar_url, created_at, provider, provider_id, email, display_name)
     VALUES (?, 0, ?, NULL, ?, 'email', ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       email = excluded.email,
       display_name = excluded.display_name`,
  )
    .bind(userId, login, Date.now(), state.email, state.email, login)
    .run();

  const { roles, appRoles } = await computeRoles(userId, login, c.env, 'email');
  const session = await signSession(userId, c.env.SESSION_SIGNING_KEY, { roles, appRoles });
  const delivery = await deliverSession(c.env, state, session);
  if (!delivery.ok) return c.text(delivery.error, 400);
  return c.redirect(delivery.url);
});

/**
 * Trade a one-time code from `response_mode=code` for the session token.
 *
 * Deliberately unauthenticated: the caller has no session yet — that is the
 * whole point of the exchange. The PKCE verifier is the credential, and the
 * code is single-use, so possession of the code alone (from a redirect log,
 * say) gets you nothing.
 */
authRoutes.post('/auth/session/exchange', async (c) => {
  const body = await c.req
    .json<{ code?: string; code_verifier?: string }>()
    .catch(() => ({}) as { code?: string; code_verifier?: string });
  if (!body.code || !body.code_verifier) {
    return c.json({ error: 'missing code or code_verifier' }, 400);
  }
  const session = await exchangeAuthCode(c.env, body.code, body.code_verifier);
  // One message for every failure mode — expired, already-redeemed and
  // wrong-verifier are not distinguished, so the endpoint isn't an oracle.
  if (!session) return c.json({ error: 'invalid, expired, or already-used code' }, 400);
  return c.json({ fas_session: session });
});

authRoutes.get('/auth/me', async (c) => {
  try {
    const user = await requireUser(c);
    return c.json(user);
  } catch (err) {
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status as 401);
    throw err;
  }
});

/**
 * Set the user's date of birth — once, irrevocably. Apps prompt for this when
 * they need an age check; once set, every other app on the platform reads it
 * from `GET /v1/auth/me`. 13+ is the platform floor (apps with stricter age
 * requirements check the returned DOB themselves).
 */
authRoutes.patch('/auth/me/date-of-birth', async (c) => {
  try {
    const user = await requireUser(c);
    if (user.dateOfBirth) {
      return c.json({ error: 'date of birth already set' }, 409);
    }
    const body = (await c.req.json().catch(() => null)) as { dateOfBirth?: unknown } | null;
    const dob = typeof body?.dateOfBirth === 'string' ? body.dateOfBirth : '';
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dob)) {
      return c.json({ error: 'dateOfBirth must be YYYY-MM-DD' }, 400);
    }
    const age = ageFromDob(dob);
    if (age == null) {
      return c.json({ error: 'invalid date' }, 400);
    }
    if (age < 13) {
      return c.json({ error: 'must be at least 13' }, 400);
    }
    if (age > 120) {
      return c.json({ error: 'invalid date' }, 400);
    }
    await c.env.DB.prepare('UPDATE users SET date_of_birth = ? WHERE id = ?')
      .bind(dob, user.id)
      .run();
    return c.json({ ...user, dateOfBirth: dob });
  } catch (err) {
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status as 401);
    throw err;
  }
});

/**
 * Delete the signed-in account and its personal data across the platform:
 * API keys, KV, friendships, app roles, owned documents, and logs, then the
 * user row itself. Runs as one D1 batch (transactional).
 *
 * Deliberately NOT deleted: apps the user owns (provisioned resources with their
 * own deprovision flow) and app-shared counters. NOTE: sessions are stateless
 * HMAC tokens, so the caller's current token remains valid until it expires
 * (≤30d) — there is no server-side revocation list yet. Full revocation needs a
 * stateful-session change; tracked separately.
 */
authRoutes.delete('/auth/me', async (c) => {
  try {
    const user = await requireUser(c);
    const db = c.env.DB;
    await db.batch([
      db.prepare('DELETE FROM user_api_keys WHERE user_id = ?').bind(user.id),
      db.prepare('DELETE FROM kv WHERE user_id = ?').bind(user.id),
      db.prepare('DELETE FROM friendships WHERE user_a = ? OR user_b = ?').bind(user.id, user.id),
      db.prepare('DELETE FROM app_roles WHERE user_id = ?').bind(user.id),
      db.prepare('DELETE FROM documents WHERE owner_id = ?').bind(user.id),
      db.prepare('DELETE FROM app_logs WHERE user_id = ?').bind(user.id),
      db.prepare('DELETE FROM users WHERE id = ?').bind(user.id),
    ]);
    return c.json({ ok: true });
  } catch (err) {
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status as 401);
    throw err;
  }
});

/**
 * Compute platform roles for a user at sign-in time. Roles are baked
 * into the session token so per-request checks are zero-I/O.
 *
 * - 'user' — always (signed in)
 * - 'creator' — has at least one published app
 * - 'admin' — login is in ADMIN_GITHUB_LOGINS env var
 */
export async function computeRoles(
  userId: string,
  login: string,
  env: Env,
  provider = 'github',
): Promise<{ roles: string[]; appRoles: Record<string, string[]> }> {
  const roles = ['user'];
  const appRoles: Record<string, string[]> = {};

  // SECURITY: app ownership (apps.owner_login) and admin (ADMIN_GITHUB_LOGINS)
  // are keyed by GitHub username. For non-GitHub providers `login` is the email
  // local-part (attacker-chosen on any domain they control), so matching it
  // against GitHub usernames would let someone who can receive mail at
  // <adminGithubLogin>@anydomain or <appOwner>@anydomain claim admin / app
  // ownership. Only honor login-based matches for actual GitHub auth; per-app
  // grants below are keyed by user_id and remain valid for every provider.
  const isGithub = provider === 'github';

  try {
    if (isGithub) {
      // Check if the user has published any apps (creator role).
      const appRow = await env.DB.prepare('SELECT 1 FROM apps WHERE owner_login = ? LIMIT 1')
        .bind(login)
        .first();
      if (appRow) roles.push('creator');
    }

    // Load per-app role assignments (keyed by user_id — safe for all providers).
    const { results } = await env.DB.prepare(
      'SELECT app_id, role_name FROM app_roles WHERE user_id = ?',
    )
      .bind(userId)
      .all<{ app_id: string; role_name: string }>();
    for (const r of results ?? []) {
      (appRoles[r.app_id] ??= []).push(r.role_name);
    }

    if (isGithub) {
      // Auto-assign 'owner' for apps this user created (not stored in DB).
      const { results: ownedApps } = await env.DB.prepare(
        'SELECT id FROM apps WHERE owner_login = ?',
      )
        .bind(login)
        .all<{ id: string }>();
      for (const a of ownedApps ?? []) {
        (appRoles[a.id] ??= []).push('owner');
      }
    }
  } catch {
    // Tables don't exist yet (fresh DB or test env) — skip
  }

  // Check admin list (GitHub identities only — see security note above).
  if (isGithub && isAdminLogin(login, env)) roles.push('admin');

  return { roles, appRoles };
}

async function hashForReplay(token: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function ageFromDob(dob: string): number | null {
  const d = new Date(`${dob}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return null;
  const now = new Date();
  let age = now.getUTCFullYear() - d.getUTCFullYear();
  const m = now.getUTCMonth() - d.getUTCMonth();
  if (m < 0 || (m === 0 && now.getUTCDate() < d.getUTCDate())) age--;
  return age;
}
