/**
 * Route-level coverage for session delivery across response modes.
 *
 * The unit tests in lib/deliver-session.test.ts cover the helper itself; these
 * pin the wiring — that the callbacks actually pass the signed state through to
 * it, and that a code-mode flow is rejected at /start rather than partway
 * through a provider round-trip.
 */

import { describe, expect, it } from 'vitest';
import { app } from '../index.js';
import { s256Challenge } from '../lib/deliver-session.js';
import { signPayload } from '../lib/session.js';
import type { Env } from '../types.js';

const SIGNING_KEY = 'a'.repeat(64);
const VALID_RETURN_TO = 'https://demo.freeappstore.online/';
const VERIFIER = 'v'.repeat(43);

/** Permissive D1 stand-in — every write succeeds. Delivery behaviour is what
 *  these tests assert on; the storage layer has its own tests. */
function fakeDB(): D1Database {
  const prepare = (): D1PreparedStatement => {
    const stmt: Partial<D1PreparedStatement> = {
      bind: () => stmt as D1PreparedStatement,
      run: async <T = Record<string, unknown>>() =>
        ({ meta: { changes: 1 } }) as unknown as D1Result<T>,
      first: async <T = Record<string, unknown>>() => null as T | null,
    };
    return stmt as D1PreparedStatement;
  };
  return { prepare } as unknown as D1Database;
}

function makeEnv(): Env {
  return {
    DB: fakeDB(),
    ROOM: {} as DurableObjectNamespace,
    GITHUB_CLIENT_ID: 'cid',
    GITHUB_CLIENT_SECRET: 'csec',
    SESSION_SIGNING_KEY: SIGNING_KEY,
    RESEND_API_KEY: 'resend-test-key',
    EMAIL_FROM: 'FreeAppStore <auth@freeappstore.online>',
  } as unknown as Env;
}

/** A magic-link token, which is the cheapest way to reach a real callback. */
function makeToken(overrides: Record<string, unknown> = {}): Promise<string> {
  return signPayload(
    {
      email: 'alice@example.com',
      appId: 'demo',
      returnTo: VALID_RETURN_TO,
      exp: Math.floor(Date.now() / 1000) + 60,
      ...overrides,
    },
    SIGNING_KEY,
  );
}

async function callback(token: string) {
  return app.request(
    `/v1/auth/email/callback?token=${encodeURIComponent(token)}`,
    { redirect: 'manual' },
    makeEnv(),
  );
}

describe('session delivery from the email callback', () => {
  it('delivers in the query string for responseMode=query', async () => {
    const res = await callback(await makeToken({ responseMode: 'query' }));

    expect(res.status).toBe(302);
    const location = res.headers.get('location') ?? '';
    expect(location).toContain('?fas_session=');
    expect(location).not.toContain('#fas_session=');
  });

  it('delivers in the fragment when no responseMode is set', async () => {
    const res = await callback(await makeToken());

    expect(res.status).toBe(302);
    const location = res.headers.get('location') ?? '';
    expect(location).toContain('#fas_session=');
    expect(location).not.toContain('?fas_session=');
  });

  it('delivers only a code for responseMode=code', async () => {
    const codeChallenge = await s256Challenge(VERIFIER);
    const res = await callback(await makeToken({ responseMode: 'code', codeChallenge }));

    expect(res.status).toBe(302);
    const location = new URL(res.headers.get('location') ?? '');
    expect(location.searchParams.get('code')).toBeTruthy();
    expect(location.searchParams.get('fas_session')).toBeNull();
    expect(location.hash).toBe('');
  });

  it('refuses to complete a code-mode flow whose state carries no challenge', async () => {
    // A state signed before the challenge requirement, or tampered to drop it,
    // must fail rather than downgrade to putting the session in the URL.
    const res = await callback(await makeToken({ responseMode: 'code' }));

    expect(res.status).toBe(400);
    expect(await res.text()).toContain('code_challenge');
  });
});

describe('PKCE enforcement at /start', () => {
  const startUrl = (params: Record<string, string>) =>
    `/v1/auth/github/start?${new URLSearchParams({
      app_id: 'demo',
      return_to: VALID_RETURN_TO,
      ...params,
    })}`;

  it('rejects response_mode=code without a code_challenge', async () => {
    const res = await app.request(
      startUrl({ response_mode: 'code' }),
      { redirect: 'manual' },
      makeEnv(),
    );

    expect(res.status).toBe(400);
    expect(await res.text()).toContain('code_challenge');
  });

  it('rejects a non-S256 challenge method', async () => {
    const res = await app.request(
      startUrl({
        response_mode: 'code',
        code_challenge: 'whatever',
        code_challenge_method: 'plain',
      }),
      { redirect: 'manual' },
      makeEnv(),
    );

    expect(res.status).toBe(400);
    expect(await res.text()).toContain('S256');
  });

  it('redirects to the provider when a code-mode start is well formed', async () => {
    const res = await app.request(
      startUrl({
        response_mode: 'code',
        code_challenge: await s256Challenge(VERIFIER),
        code_challenge_method: 'S256',
      }),
      { redirect: 'manual' },
      makeEnv(),
    );

    expect(res.status).toBe(302);
    expect(res.headers.get('location') ?? '').toContain('github.com/login/oauth/authorize');
  });

  it('leaves the other response modes unaffected', async () => {
    for (const params of [{}, { response_mode: 'query' }]) {
      const res = await app.request(startUrl(params), { redirect: 'manual' }, makeEnv());
      expect(res.status).toBe(302);
    }
  });

  it('rejects a code-mode magic-link start without a challenge', async () => {
    const res = await app.request(
      '/v1/auth/email/start',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'pkce-check@example.com',
          appId: 'demo',
          returnTo: VALID_RETURN_TO,
          responseMode: 'code',
        }),
      },
      makeEnv(),
    );

    expect(res.status).toBe(400);
    expect(await res.text()).toContain('code_challenge');
  });
});
