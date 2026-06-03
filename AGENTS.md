# Project Guidelines

## Overview

Remote MCP server for XWiki. Exposes JSON-RPC (`/mcp`) and SSE (`/sse` + `/messages`) transports with OAuth 2.1 authentication. Each user authenticates via browser (Authentik/SSO) and all XWiki API calls run under that user's real session.

## Architecture

- **Entry**: `server.js` → `src/app.js` (`createApp()`)
- **Auth**: OAuth 2.1 BFF — MCP server is both AS (for MCP clients) and OIDC client (to Authentik)
- **Session store**: in-memory map `sessionId → { userId, xwikiCookie, expiresAt }`
- **XWiki auth**: per-user session cookie (captured at OAuth callback, same-origin)
- **Transport**: HTTP (not stdio). Runs behind HAProxy at `/mcp/` under `xwiki.wus-technik.com`

### OAuth Flow

```
MCP Client → /oauth/authorize (PKCE)
  → Server stores pending state
  → Redirect to Authentik
User authenticates in browser (SSO transparent if already logged in)
Authentik → /oauth/callback?code=...
  → Server exchanges code with Authentik
  → Server captures XWiki session cookie from request (same-origin)
  → Server creates MCP session, issues one-time auth code
  → Redirect to MCP client
MCP Client → /oauth/token (code + PKCE verifier)
  → Server issues signed JWT (payload: userId, sessionId)
MCP Client → /mcp with Authorization: Bearer <jwt>
  → Auth middleware validates JWT, loads session
  → Tool calls use session.xwikiCookie for XWiki REST
```

### Discovery endpoints

- `GET /.well-known/oauth-protected-resource` — points MCP clients to this server as AS
- `GET /.well-known/oauth-authorization-server` — AS metadata (authorize + token endpoints)

## Build & Run

```bash
npm install
node server.js

docker-compose up -d --build
```

Required env vars (see docker-compose.yml for full list):
- `XWIKI_URL` — XWiki base URL
- `AUTHENTIK_ISSUER` — Authentik base URL (e.g. `https://auth.example.com`)
- `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` — Authentik OIDC application credentials
- `OAUTH_REDIRECT_URI` — this server's callback URL (e.g. `https://xwiki.example.com/mcp/oauth/callback`)
- `MCP_BASE_URL` — public base URL of this server (e.g. `https://xwiki.example.com/mcp`)
- `SESSION_SECRET` — secret for signing JWT access tokens (min 32 chars, required in production)

## Conventions

- ES modules (`"type": "module"`) — `import`, not `require`
- No bundler — plain Node.js 20+
- XWiki REST: `/rest/wikis/{wiki}/spaces/{spacePath}/pages/{pageName}`
- Tool definitions follow MCP tool schema
- Auth/session code is explicit and traceable — no hidden global state

## Key Pitfalls

- `NODE_TLS_REJECT_UNAUTHORIZED=0` is dev-only — never in production
- `SESSION_SECRET` must be set in production; a missing value triggers a console warning but still works in dev
- XWiki form token (`XWiki-Form-Token` header) is required for write operations — fetched via GET before PUT
- Same-origin deployment is required for session cookie capture to work: MCP server must be behind the same hostname as XWiki
- Do not log `req.headers.cookie`, bearer tokens, or any session secrets
