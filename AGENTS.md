# Project Guidelines

## Overview

Remote MCP server for XWiki. Exposes MCP over Streamable HTTP (`POST /mcp`, JSON responses, no SSE) with OAuth 2.1 authentication. The server is its own authorization server; users log in via Authentik in the browser, and all XWiki API calls run under that user's own XWiki consent token (bearer).

## Architecture

- **Entry**: `server.js` (`validateConfig`, `openStore`, `startBackground`) → `src/app.js` (`createApp()`)
- **Auth**: the MCP server is the OAuth AS for MCP clients (DCR, PKCE S256, `src/oauth.js`) and an OIDC client of Authentik (`src/authentik.js`: code exchange with RS256 ID token check, refresh, userinfo group check against `ALLOWED_GROUPS`)
- **Store** (`src/store.js`): one JSON file at `STORE_FILE` with `clients`, `grants`, `sessions`, `families`, `cleanups`, `uploadNonces`. Every change goes through `store.mutate()` and is written before the client gets an answer; secrets (XWiki token, Authentik refresh token) are sealed with `TOKEN_ENC_KEY` (AES-256-GCM). An unreadable store or a wrong key stops the start (no fresh start). Per-session work is serialized with `store.withLock("session:<sid>")`.
- **XWiki auth**: per session one XWiki consent token (`src/xwiki-tokens.js`), created at login on the profile page "Applications" with the browser's XWiki cookie of that one request; the cookie is never stored. Afterwards every XWiki call uses `Authorization: Bearer <token>`, so XWiki restarts do not end sessions. Token lifetime 90 days, renewed on refresh when < 14 days are left.
- **Sessions** (`src/sessions.js`): access token = HS256 JWT (1 h, `iss`/`aud` = `MCP_BASE_URL`, `sid`, `client_id`, `ver`); refresh tokens rotate on every use (stored as SHA-256, 30 s replay window, reuse of a spent token ends the session), 30 days sliding idle limit. Ending a session records a cleanup entry that deletes its XWiki token (background, hourly retry).
- **Background jobs**: daily reconcile with Authentik (refresh + group check per session, idle/orphan sessions end, unused clients removed), hourly cleanups. No keep-alive.
- **Transport**: HTTP (not stdio). Runs behind HAProxy under `xwiki.wus-technik.com`; `/mcp`, `/mcp/*` and the root OAuth/discovery aliases go to this server unchanged.

### OAuth Flow

```
MCP Client → POST /mcp/oauth/register (DCR, redirect URI allowlist)
MCP Client → /mcp/oauth/authorize (PKCE S256) → flow cookie xmcp_flow
  → Redirect to Authentik (state, nonce)
User authenticates in browser (SSO transparent if already logged in)
Authentik → /mcp/oauth/callback?code=...
  → Code exchange, ID token check, group check (userinfo)
  → Redirect to XWiki login /bin/login/XWiki/XWikiLogin?xredirect=/mcp/oauth/complete?t=...
XWiki (same origin) → /mcp/oauth/complete with the XWiki session cookie
  → whoami(cookie) must be the expected user (preferred_username without dots, lower-case)
  → first time for user + client: consent page → POST /mcp/oauth/consent
  → XWiki consent token created with the cookie, session written, cookie dropped
  → Redirect to MCP client with a one-time code
MCP Client → POST /mcp/oauth/token (code + PKCE verifier) → access token + refresh token
MCP Client → POST /mcp with Authorization: Bearer <jwt>
  → Auth middleware validates the JWT and loads the session
  → Tool calls use the session's XWiki token as bearer
MCP Client → POST /mcp/oauth/token (refresh_token) → rotated pair (Authentik refresh + group check)
MCP Client → POST /mcp/oauth/revoke → session ends, XWiki token deleted
```

### Discovery endpoints

- `GET /.well-known/oauth-protected-resource` — points MCP clients to this server as AS
- `GET /.well-known/oauth-authorization-server` — AS metadata (register, authorize, token, revoke)
- Same documents under `/mcp/.well-known/…` and with the `/mcp` suffix

## Build & Run

```bash
npm install
npm test
node server.js

docker-compose up -d --build
```

Env vars (full table in README.md, see docker-compose.yml):
- `XWIKI_URL` — XWiki base URL for REST calls and the consent token page (internal hostname in production)
- `XWIKI_PUBLIC_URL` — public XWiki URL for page links returned to clients (defaults to `XWIKI_URL`)
- `AUTHENTIK_ISSUER` — Authentik base URL (e.g. `https://auth.example.com`); `AUTHENTIK_APP_SLUG` (default `xwiki-mcp`)
- `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` — Authentik OIDC application credentials
- `OAUTH_REDIRECT_URI` — this server's callback URL (e.g. `https://xwiki.example.com/mcp/oauth/callback`)
- `MCP_BASE_URL` — public base URL of this server (e.g. `https://xwiki.example.com/mcp`)
- `SESSION_SECRET` — signs the access tokens, at least 32 bytes (required, start refused otherwise)
- `TOKEN_ENC_KEY` — 32 bytes, base64; encrypts the store's secrets (required; the store file is useless without it)
- `STORE_FILE` — path of the persistent store, e.g. `/data/store.json` on a volume (required)
- `ALLOWED_GROUPS` — Authentik groups allowed in (default `AdminsIT,xwiki_redaktion`)
- `EXTRA_REDIRECT_URIS` / `EXTRA_ORIGINS` — additional client redirect URIs / allowed Origins (comma-separated)
- `AUTH_DEBUG=1` — logs auth events without secrets

## Conventions

- ES modules (`"type": "module"`) — `import`, not `require`
- No bundler — plain Node.js 20+
- XWiki REST: `/rest/wikis/{wiki}/spaces/{spacePath}/pages/{pageName}`
- Tool definitions follow MCP tool schema
- Auth/session code is explicit and traceable — no hidden global state
- Tests: `node --test`; `test/e2e.test.js` runs the whole flow against in-process fakes of Authentik and XWiki (`test/helpers/`)

## Key Pitfalls

- `NODE_TLS_REJECT_UNAUTHORIZED=0` is dev-only — refused with `NODE_ENV=production`
- `SESSION_SECRET`, `TOKEN_ENC_KEY` and `STORE_FILE` must be set; otherwise the server exits with code 1
- XWiki consent token page behaviour (HTML, form fields, `XWiki-User` header) is pinned to XWiki 18.7.0, see `test/fixtures/xwiki-18.7.0/README.md`; an invalid bearer gets 200 without `XWiki-User` on `/rest/`, not 401
- XWiki form token (`XWiki-Form-Token` header) is required for write operations — fetched via GET before PUT
- Same-origin deployment is required for the login: the XWiki cookie must reach `/mcp/oauth/complete`, so MCP server and XWiki share the hostname
- Do not log `req.headers.cookie`, bearer tokens, refresh tokens or any session secrets
