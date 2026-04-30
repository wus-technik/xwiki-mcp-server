# Project Guidelines

## Overview

MCP (Model Context Protocol) server that proxies XWiki REST API access. Express-based HTTP server exposing JSON-RPC (`/mcp`) and SSE (`/sse` + `/messages`) transports.

## Architecture

- **Single-file server** (`server.js`) — all logic lives here: tool definitions, XWiki API calls, MCP protocol handling, SSE session management.
- **Transport**: HTTP (not stdio). Designed to run as a hosted service (Docker or bare Node).
- **Auth model (current)**: Global credentials via `XWIKI_URL`, `XWIKI_USERNAME`, `XWIKI_PASSWORD` env vars — shared across all sessions.

### Target: User-Based Access

The `hosted` branch introduces per-user authentication so each MCP client authenticates with its own XWiki credentials rather than sharing a single global account.

Key design considerations:
- Credentials should come from the MCP client (e.g., via `initialize` params, HTTP headers, or a token exchange) — NOT from server env vars.
- Each `callTool` invocation must use the requesting user's credentials.
- SSE sessions (`sessions` Map) must track per-session auth context.
- The `/mcp` JSON-RPC endpoint must extract user credentials from the request (e.g., `Authorization` header or session token).
- Avoid storing plaintext passwords in memory longer than the request lifecycle.
- Consider supporting both Basic Auth passthrough and token-based auth (XWiki supports both).

## Build & Run

```bash
npm install          # install deps
node server.js       # start server (PORT defaults to 3000)
docker-compose up -d --build  # or via Docker
```

## Conventions

- ES modules (`"type": "module"` in package.json) — use `import`, not `require`.
- No transpilation or bundler — plain Node.js 20+.
- XWiki REST API paths follow: `/rest/wikis/{wiki}/spaces/{spacePath}/pages/{pageName}`.
- Tool definitions follow MCP tool schema (`name`, `description`, `inputSchema`).

## Key Pitfalls

- `NODE_TLS_REJECT_UNAUTHORIZED=0` is set in docker-compose for dev — do NOT carry this to production.
- XWiki page paths use dot-notation (`Main.WebHome`) but the REST API uses `/spaces/X/pages/Y` — conversion logic is in `callTool`.
