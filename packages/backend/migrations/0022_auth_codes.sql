-- One-time auth codes for `response_mode=code` session delivery.
--
-- The callback stores the freshly-minted session here under SHA-256 of a
-- random code and redirects with only the code in the query; the caller
-- trades it for the session at POST /v1/auth/session/exchange. This keeps
-- the reusable session token out of redirect URLs (and therefore out of
-- server logs, Referer headers and browser history) for server-side
-- callers like the MCP worker.
--
-- code_challenge is the PKCE (RFC 7636, S256) challenge registered at
-- /start; the exchange must present a verifier that hashes to it, so a code
-- captured in transit is not redeemable on its own.
--
-- Rows are single-use and short-lived (60s). Deliberately NOT included in
-- the R2 backup table list — the session column is a live bearer token and
-- has no business sitting in a daily backup.

CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash       TEXT PRIMARY KEY,
  session         TEXT NOT NULL,
  app_id          TEXT NOT NULL,
  code_challenge  TEXT NOT NULL,
  expires_at      INTEGER NOT NULL
);

-- Pruned by the 0 3 * * * cron alongside consumed_tokens.
CREATE INDEX IF NOT EXISTS idx_auth_codes_exp ON auth_codes (expires_at);
