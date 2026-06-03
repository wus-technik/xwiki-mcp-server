# Project Guidelines

## Overview

MCP (Model Context Protocol) server that proxies XWiki REST API access. Express-based HTTP server exposing JSON-RPC (`/mcp`) and SSE (`/sse` + `/messages`) transports.

## Architecture

- **Single-file server** (`server.js`) — all logic lives here: tool definitions, XWiki API calls, MCP protocol handling, SSE session management.
- **Transport**: HTTP (not stdio). Designed to run as a hosted service (Docker or bare Node).
- **Target auth model**: Proper remote MCP with OAuth. Users authenticate via browser/SSO and the server executes XWiki requests under the real user session, not a shared global account.

### Target: Remote MCP + XWiki SSO

This repo should move toward per-user authentication based on MCP OAuth and existing XWiki SSO instead of Basic Auth passthrough.

Key design considerations:
- The MCP server itself is the authenticated remote endpoint. Do not assume MCP clients send raw XWiki credentials.
- XWiki uses SSO/OIDC via Authentik. Browser-based login is the expected UX.
- Per-user XWiki permissions are required. Shared backend credentials are not an acceptable long-term auth model.
- `callTool` should execute with per-user session context, not global process auth.
- SSE sessions (`sessions` map) must stay bound to the authenticated user session.
- Prefer server-side session state over storing plaintext passwords.
- Design for same-origin deployment behind HAProxy, ideally under `https://xwiki.wus-technik.com/mcp/`.
- Keep the implementation friendly to standard remote MCP clients and possible later OpenWebUI usage.

## Build & Run

```bash
npm install          # install deps
node server.js       # start server (PORT defaults to 3000)
docker-compose up -d --build  # or via Docker
```

On Windows, prefer using `plink` if SSH auth with the default Git/OpenSSH setup is unreliable in your environment.

## Conventions

- ES modules (`"type": "module"` in package.json) — use `import`, not `require`.
- No transpilation or bundler — plain Node.js 20+.
- XWiki REST API paths follow: `/rest/wikis/{wiki}/spaces/{spacePath}/pages/{pageName}`.
- Tool definitions follow MCP tool schema (`name`, `description`, `inputSchema`).
- Keep auth/session code explicit and easy to trace. Hidden global auth state will become a maintenance problem fast.

## Key Pitfalls

- `NODE_TLS_REJECT_UNAUTHORIZED=0` is set in docker-compose for dev — do NOT carry this to production.
- XWiki page paths use dot-notation (`Main.WebHome`) but the REST API uses `/spaces/X/pages/Y` — conversion logic is in `callTool`.
- Do not reintroduce Basic Auth passthrough as the main plan unless requirements change explicitly.
- Same-origin deployment matters. If the MCP server is not exposed behind the same public XWiki host/path setup, the SSO/session design changes.
