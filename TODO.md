# TODO — Per-User Authentication

Before the per-user auth work, add a GitHub Actions workflow that builds the Docker image on pushes and tags, then publishes it to GitHub Container Registry (`ghcr.io`). The workflow should handle image naming, registry login with GitHub-provided credentials, and tagging for branch, tag, and latest-style releases so deployment can consume images directly from GHCR.

Goal: Each MCP client authenticates with its own XWiki credentials so users operate under their own permissions instead of a shared global account.

## 1. Accept credentials from the client

- [ ] Read `Authorization` header (Basic Auth) from incoming HTTP requests on `/mcp` and `/messages`.
- [ ] For the SSE transport, capture the `Authorization` header on the initial `GET /sse` request and store it with the session.
- [ ] Fall back to the existing env-var credentials (`XWIKI_USERNAME` / `XWIKI_PASSWORD`) only when no header is provided (backwards-compatible).
- [ ] Keep `XWIKI_URL` and `XWIKI_WIKI` as server-level config — these are not per-user.

## 2. Thread credentials through to `callTool`

- [ ] Change `callTool(name, args)` signature to `callTool(name, args, credentials)` where `credentials` is `{ baseUrl, wiki, authorization }`.
- [ ] Replace the global `DEFAULT_XWIKI_URL` / `DEFAULT_USERNAME` / `DEFAULT_PASSWORD` usage inside `callTool` with the passed-in credentials.
- [ ] In the `/mcp` handler, extract credentials from `req.headers.authorization` and pass them to `callTool`.
- [ ] In the `/messages` handler, retrieve the stored session credentials and pass them to `callTool`.

## 3. Update SSE session management

- [ ] Change the `sessions` Map value from just the SSE `res` object to a session object: `{ res, authorization }`.
- [ ] On `GET /sse`, store the `Authorization` header in the session object.
- [ ] Update all `sessions.get(sessionId)` call sites to destructure the new shape.
- [ ] On session close, delete the session (already done) — ensure no credential data lingers.

## 4. Return proper HTTP errors for auth failures

- [ ] Return `401 Unauthorized` with a `WWW-Authenticate: Basic realm="XWiki"` header when no credentials are provided and no env-var fallback is configured.
- [ ] Return `403 Forbidden` when XWiki responds with `401` or `403` to a proxied request (distinguish from other API errors).
- [ ] Map these to MCP-level JSON-RPC errors so the client gets a clear message.

## 5. Security hardening

- [ ] Do NOT log or persist credentials — only hold them for the lifetime of the request (or SSE session).
- [ ] Validate the `Authorization` header format before forwarding (must be `Basic <base64>`).
- [ ] Consider supporting XWiki token-based auth as an alternative to Basic Auth (XWiki REST API accepts both).
- [ ] Remove `NODE_TLS_REJECT_UNAUTHORIZED=0` from docker-compose or gate it behind a `DEV_MODE` flag for production use.
- [ ] Sanitize error messages returned to the client — do not leak internal URLs or stack traces.

## 6. Update docker-compose / Dockerfile

- [ ] Remove `XWIKI_USERNAME` and `XWIKI_PASSWORD` from docker-compose environment (no longer needed as defaults).
- [ ] Keep `XWIKI_URL` and `XWIKI_WIKI` — these remain server config.
- [ ] Document how to pass credentials from the MCP client.

## 7. Update health endpoint

- [ ] Adjust `/health` to reflect that auth is now per-user (e.g., report whether fallback credentials are configured vs. per-user mode).

## 8. Client documentation

- [ ] Update README with instructions for passing credentials via `Authorization` header.
- [ ] Provide example MCP client config showing how to set auth headers.
- [ ] Document the fallback behavior (env vars used when no header present).

## 9. Testing

- [ ] Test `/mcp` with Basic Auth header → requests hit XWiki as that user.
- [ ] Test `/sse` + `/messages` with Basic Auth header → session uses that user's credentials.
- [ ] Test without credentials and without env-var fallback → returns `401`.
- [ ] Test without credentials but with env-var fallback → uses global credentials (backwards-compatible).
- [ ] Test with invalid credentials → returns `403` / clear error.
- [ ] Test that two concurrent SSE sessions with different credentials are isolated.
