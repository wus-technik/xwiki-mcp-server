# TODO — Remote MCP with OAuth and XWiki SSO

## Done first

- [x] Add a GitHub Actions workflow that builds the Docker image on pushes and tags and publishes it to GitHub Container Registry (`ghcr.io`).
- [x] Publish branch, tag, SHA, and release-style tags from GitHub Actions so deployment can consume images directly from GHCR.

Goal: Turn `xwiki-mcp-server` into a proper remote MCP server with OAuth so each user authenticates via browser/SSO and all XWiki actions run under that user's real permissions instead of a shared backend account.

## Assumptions / constraints

- [ ] XWiki uses SSO/OIDC via Authentik. Users should not have to provide separate XWiki Basic Auth credentials in the MCP client.
- [ ] `xwiki-mcp-server` should be exposed behind the same public origin as XWiki, ideally `https://xwiki.wus-technik.com/mcp/`, via HAProxy or equivalent path routing.
- [ ] The implementation should work first for direct remote MCP clients and keep the door open for later OpenWebUI support.
- [ ] XWiki authorization must stay the source of truth. Users may only access pages they could access in the normal XWiki UI.

## 1. Replace the auth model

- [ ] Drop the Basic-Auth-passthrough plan from the implementation.
- [ ] Remove the idea that MCP clients send XWiki usernames/passwords directly to the server.
- [ ] Treat `XWIKI_URL` and `XWIKI_WIKI` as server config only. Do not rely on global `XWIKI_USERNAME` / `XWIKI_PASSWORD` for normal operation.
- [ ] Make the MCP server itself the authenticated remote endpoint. XWiki auth should happen behind it.

## 2. Implement remote MCP OAuth

- [ ] Add OAuth 2.1 support for the remote MCP server login flow.
- [ ] Expose login / callback / logout endpoints needed for browser-based auth.
- [ ] Bind the authenticated MCP identity to a server-side session or token owned by this service.
- [ ] Return proper MCP auth challenges / errors when a client is not logged in.
- [ ] Keep the implementation compatible with standard remote MCP clients instead of a custom one-off login protocol.

## 3. Map the MCP user to a real XWiki session

- [ ] Reuse the user's real XWiki browser session instead of asking for XWiki credentials manually.
- [ ] On same-origin browser requests, detect whether the user already has a valid XWiki session cookie.
- [ ] Bind the authenticated MCP user to a server-side XWiki session context.
- [ ] Store only the minimum session state needed to call XWiki REST as that user.
- [ ] Confirm that the XWiki cookie path / domain setup allows the `/mcp/*` endpoints to participate in the same login context.

## 4. Thread user session context through tool execution

- [ ] Change `callTool(name, args)` to accept a user session context instead of relying on globals.
- [ ] Replace the global default-auth usage inside `callTool` with per-user session state.
- [ ] Ensure `/mcp` requests resolve the authenticated MCP user and load the matching XWiki session context.
- [ ] Ensure SSE `/sse` + `/messages` requests are bound to the authenticated user session, not a shared process-global auth state.

## 5. Update SSE session management

- [ ] Change the `sessions` map to hold structured session data instead of only the SSE response object.
- [ ] Keep the SSE transport bound to the already authenticated MCP user.
- [ ] Ensure one user's SSE session cannot be reused by another user.
- [ ] Remove session state on close / expiry so no stale XWiki session linkage remains.

## 6. XWiki REST integration details

- [ ] Confirm which XWiki REST calls work with the user session cookie as-is for read operations.
- [ ] Fetch and reuse `XWiki-Form-Token` where required for write operations.
- [ ] Handle XWiki session expiry by forcing a fresh browser login rather than silently falling back to shared credentials.
- [ ] Keep tool behavior unchanged from the user's perspective: search, read, create/update should continue to work, but now under per-user auth.

## 7. Security hardening

- [ ] Do not log cookies, bearer tokens, or other session secrets.
- [ ] Do not keep plaintext credentials in memory longer than strictly necessary. Prefer session-based auth over password storage.
- [ ] Sanitize error messages returned to clients. Do not leak internal URLs, cookies, stack traces, or proxy details.
- [ ] Remove `NODE_TLS_REJECT_UNAUTHORIZED=0` from default production setup or gate it behind a clearly named dev-only flag.
- [ ] Ensure direct access to the MCP container is not treated as trusted. Trust should come from OAuth/session validation, not network location alone.

## 8. Infra / deployment work

- [ ] Run `xwiki-mcp-server` behind HAProxy under the same public hostname as XWiki, ideally `/mcp/*`.
- [ ] Preserve the original host header so browser login / callback URLs stay correct.
- [ ] Document the required proxy headers and path routing behavior.
- [ ] Verify that XWiki SSO still behaves correctly when the MCP server is mounted under the same origin.

## 9. Update local deployment config

- [ ] Remove `XWIKI_USERNAME` and `XWIKI_PASSWORD` from `docker-compose.yml` as standard runtime requirements.
- [ ] Keep only server-level config in compose and env files.
- [ ] Add any new OAuth/session config required by the MCP server.
- [ ] Make it clear which settings are local-dev-only and which are required in production behind HAProxy.

## 10. Documentation

- [ ] Rewrite `AGENTS.md` to match the new OAuth / remote MCP direction before implementing the rest.
- [ ] Update `README.md` to describe the new remote MCP login flow.
- [ ] Document the same-origin routing requirement and why it matters.
- [ ] Document expected client behavior: browser login, session expiry, logout, and re-authentication.
- [ ] Add a short architecture section explaining why Basic Auth passthrough was rejected for this repo.

## 11. Testing

- [ ] Test `/mcp` after OAuth login: requests hit XWiki as the real user.
- [ ] Test `/sse` + `/messages` after OAuth login: session stays bound to that same user.
- [ ] Test two concurrent users with different permissions and confirm search/read/write results differ correctly.
- [ ] Test a user who can read but not edit and confirm write calls fail with the expected XWiki authorization error.
- [ ] Test expired XWiki session behavior and confirm the user is asked to log in again.
- [ ] Test direct access without login and confirm the MCP client receives a clear auth-required response.
- [ ] Test the same flow behind the final reverse proxy path (`/mcp/*`), not only on localhost.
