import { describe, expect, it, vi } from 'vitest';
import type { Env } from '../types.js';
import {
  AUTH_CODE_TTL_SECONDS,
  deliverSession,
  exchangeAuthCode,
  s256Challenge,
} from './deliver-session.js';

// A return_to that already carries a query param, so the tests also prove
// delivery doesn't clobber the caller's own state (the MCP worker puts its
// nonce here).
const RETURN_TO = 'https://demo.freeappstore.online/callback?nonce=n1';
const SESSION = 'eyJ1aWQiOiJnaDoxIn0.c2lnbmF0dXJl';
// PKCE verifiers are 43-128 unreserved chars (RFC 7636 §4.1).
const VERIFIER = 'v'.repeat(43);
const OTHER_VERIFIER = 'w'.repeat(43);

interface CodeRow {
  session: string;
  app_id: string;
  code_challenge: string;
  expires_at: number;
}

/**
 * In-memory stand-in for the auth_codes table. Unlike the `fakeDB` in the
 * route tests this one is stateful: single-use redemption is the behaviour
 * under test, so INSERT/SELECT/DELETE have to actually agree with each other.
 * DELETE reports changes=0 for a row that is already gone, which is what
 * exchangeAuthCode relies on to make redemption single-use.
 */
function fakeCodeDB() {
  const rows = new Map<string, CodeRow>();
  const prepare = (sql: string): D1PreparedStatement => {
    const trimmed = sql.replace(/\s+/g, ' ').trim();
    let bound: unknown[] = [];
    const stmt: Partial<D1PreparedStatement> = {
      bind: (...args: unknown[]) => {
        bound = args;
        return stmt as D1PreparedStatement;
      },
      first: async <T = Record<string, unknown>>() => {
        if (trimmed.startsWith('SELECT session, code_challenge, expires_at FROM auth_codes')) {
          return (rows.get(String(bound[0])) ?? null) as T | null;
        }
        return null as T | null;
      },
      run: async <T = Record<string, unknown>>() => {
        if (trimmed.startsWith('INSERT INTO auth_codes')) {
          const [codeHash, session, appId, codeChallenge, expiresAt] = bound as [
            string,
            string,
            string,
            string,
            number,
          ];
          rows.set(codeHash, {
            session,
            app_id: appId,
            code_challenge: codeChallenge,
            expires_at: expiresAt,
          });
          return { meta: { changes: 1 } } as unknown as D1Result<T>;
        }
        if (trimmed.startsWith('DELETE FROM auth_codes')) {
          const changes = rows.delete(String(bound[0])) ? 1 : 0;
          return { meta: { changes } } as unknown as D1Result<T>;
        }
        return { meta: { changes: 0 } } as unknown as D1Result<T>;
      },
    };
    return stmt as D1PreparedStatement;
  };
  return { env: { DB: { prepare } as unknown as D1Database } as Pick<Env, 'DB'>, rows };
}

/** Run a code-mode delivery and return the code from the redirect URL. */
async function mintCode(env: Pick<Env, 'DB'>, challenge: string): Promise<string> {
  const result = await deliverSession(
    env,
    { appId: 'demo', returnTo: RETURN_TO, responseMode: 'code', codeChallenge: challenge },
    SESSION,
  );
  if (!result.ok) throw new Error(`expected delivery to succeed: ${result.error}`);
  const code = new URL(result.url).searchParams.get('code');
  if (!code) throw new Error('expected a code in the redirect URL');
  return code;
}

describe('deliverSession', () => {
  it('puts the session in the fragment by default', async () => {
    const { env } = fakeCodeDB();
    const result = await deliverSession(env, { appId: 'demo', returnTo: RETURN_TO }, SESSION);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const url = new URL(result.url);
    expect(url.hash).toBe(`#fas_session=${encodeURIComponent(SESSION)}`);
    // The fragment is never sent to a server — that's the point of this mode.
    expect(url.searchParams.get('fas_session')).toBeNull();
    // The caller's own query param survives.
    expect(url.searchParams.get('nonce')).toBe('n1');
  });

  it('puts the session in the query string for response_mode=query', async () => {
    const { env } = fakeCodeDB();
    const result = await deliverSession(
      env,
      { appId: 'demo', returnTo: RETURN_TO, responseMode: 'query' },
      SESSION,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const url = new URL(result.url);
    expect(url.searchParams.get('fas_session')).toBe(SESSION);
    expect(url.hash).toBe('');
    expect(url.searchParams.get('nonce')).toBe('n1');
  });

  it('returns only a one-time code for response_mode=code, never the session', async () => {
    const { env, rows } = fakeCodeDB();
    const challenge = await s256Challenge(VERIFIER);
    const result = await deliverSession(
      env,
      { appId: 'demo', returnTo: RETURN_TO, responseMode: 'code', codeChallenge: challenge },
      SESSION,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const url = new URL(result.url);
    const code = url.searchParams.get('code');
    expect(code).toBeTruthy();
    expect(url.searchParams.get('fas_session')).toBeNull();
    expect(url.hash).toBe('');
    // The whole point of #44: the session must not appear anywhere in the URL.
    expect(result.url).not.toContain(SESSION);
    expect(url.searchParams.get('nonce')).toBe('n1');

    // The table keys on a hash of the code, not the code itself, so a DB read
    // doesn't hand an attacker something redeemable.
    expect(rows.size).toBe(1);
    const [storedKey, storedRow] = [...rows.entries()][0]!;
    expect(storedKey).not.toBe(code);
    expect(storedRow.session).toBe(SESSION);
    expect(storedRow.app_id).toBe('demo');
    expect(storedRow.code_challenge).toBe(challenge);
  });

  it('refuses response_mode=code without a code_challenge, storing nothing', async () => {
    const { env, rows } = fakeCodeDB();
    const result = await deliverSession(
      env,
      { appId: 'demo', returnTo: RETURN_TO, responseMode: 'code' },
      SESSION,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('code_challenge');
    // It must fail closed — not silently fall back to a session-in-URL mode.
    expect(rows.size).toBe(0);
  });

  it('issues a distinct code per delivery', async () => {
    const { env } = fakeCodeDB();
    const challenge = await s256Challenge(VERIFIER);
    const first = await mintCode(env, challenge);
    const second = await mintCode(env, challenge);
    expect(first).not.toBe(second);
  });
});

describe('exchangeAuthCode', () => {
  it('returns the session for a valid code with the correct verifier', async () => {
    const { env, rows } = fakeCodeDB();
    const code = await mintCode(env, await s256Challenge(VERIFIER));

    expect(await exchangeAuthCode(env, code, VERIFIER)).toBe(SESSION);
    // Redemption consumes the row.
    expect(rows.size).toBe(0);
  });

  it('rejects a wrong verifier and burns the code', async () => {
    const { env } = fakeCodeDB();
    const code = await mintCode(env, await s256Challenge(VERIFIER));

    expect(await exchangeAuthCode(env, code, OTHER_VERIFIER)).toBeNull();
    // A failed attempt must not leave the code redeemable — otherwise a
    // captured code stays live while its holder guesses.
    expect(await exchangeAuthCode(env, code, VERIFIER)).toBeNull();
  });

  it('rejects an expired code', async () => {
    const { env } = fakeCodeDB();
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-08-16T00:00:00Z'));
      const code = await mintCode(env, await s256Challenge(VERIFIER));
      vi.setSystemTime(new Date(Date.now() + (AUTH_CODE_TTL_SECONDS + 1) * 1000));
      expect(await exchangeAuthCode(env, code, VERIFIER)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('accepts a code just inside its TTL', async () => {
    const { env } = fakeCodeDB();
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-08-16T00:00:00Z'));
      const code = await mintCode(env, await s256Challenge(VERIFIER));
      vi.setSystemTime(new Date(Date.now() + (AUTH_CODE_TTL_SECONDS - 1) * 1000));
      expect(await exchangeAuthCode(env, code, VERIFIER)).toBe(SESSION);
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects an already-redeemed code', async () => {
    const { env } = fakeCodeDB();
    const code = await mintCode(env, await s256Challenge(VERIFIER));

    expect(await exchangeAuthCode(env, code, VERIFIER)).toBe(SESSION);
    expect(await exchangeAuthCode(env, code, VERIFIER)).toBeNull();
  });

  it('rejects a code that was never issued', async () => {
    const { env } = fakeCodeDB();
    expect(await exchangeAuthCode(env, 'never-issued', VERIFIER)).toBeNull();
  });
});
