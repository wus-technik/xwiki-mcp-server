# Security Audit

Date: 2026-04-30

Scope:
- Source review of the current repository state
- Manual inspection of runtime code, container config, and docs
- No dynamic penetration test against a live deployment

Files reviewed:
- `server.js`
- `docker-compose.yml`
- `Dockerfile`
- `README.md`
- `.gitignore`
- `setup.sh`

Limitations:
- A dependency vulnerability scan could not be completed because the repository does not include a `package-lock.json`, and `npm audit` failed with `ENOLOCK`.
- Findings below are therefore a code and configuration audit, not a verified SBOM/CVE inventory.

## Executive Summary

The current implementation is not safe to expose beyond a tightly controlled local development environment.

The most serious issue is that the MCP server itself has no authentication or authorization boundary, while it holds shared XWiki credentials in environment variables and can perform both read and write operations on behalf of any caller. In practice, any network client that can reach the service can search XWiki, read pages, and create or overwrite pages using the server's backend privileges.

The second major issue is transport/session security. The SSE compatibility mode uses an unbound `sessionId` in the query string as the only session handle, logs that session identifier, and does not tie it to a caller identity. That makes session hijacking and cross-client message injection materially easier.

The default Docker Compose configuration also disables TLS certificate verification for outbound XWiki requests, which creates a credential theft and content tampering risk if used outside a throwaway dev setup.

## Findings

### 1. Critical: No authentication or authorization on MCP endpoints

Severity: Critical

Affected locations:
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:68)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:94)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:116)
- [README.md](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/README.md:166)

Evidence:
- `POST /mcp` accepts JSON-RPC requests with no authentication checks.
- `GET /sse` creates a session for any caller.
- `POST /messages` processes tool calls for any caller that presents a valid `sessionId`.
- The documented client configuration exposes the service over plain HTTP with no credential exchange.

Impact:
- Any reachable client can invoke `search_xwiki`, `get_xwiki_page`, and `create_xwiki_page`.
- Unauthorized users can read wiki content and modify or overwrite pages.
- Access control is entirely delegated to network reachability, which is not sufficient for a hosted MCP service.

Why this matters especially here:
- The server is not read-only. It exposes a write primitive (`create_xwiki_page`) using backend credentials.
- This effectively turns the service into an unauthenticated proxy to privileged XWiki operations.

Recommended remediation:
- Require authentication on every externally reachable endpoint.
- For the hosted design, bind each request to user-supplied XWiki credentials or a short-lived server-issued token derived from them.
- Reject tool calls when no authenticated user context is present.
- Treat `/mcp`, `/sse`, and `/messages` consistently; do not secure one transport and leave the other open.

### 2. High: Shared global XWiki credentials collapse user isolation and auditing

Severity: High

Affected locations:
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:4)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:18)
- [docker-compose.yml](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/docker-compose.yml:12)
- [README.md](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/README.md:184)

Evidence:
- The service reads `XWIKI_URL`, `XWIKI_USERNAME`, `XWIKI_PASSWORD`, and `XWIKI_WIKI` once at process start.
- Every request uses the same Basic Authorization header when credentials exist.

Impact:
- All callers inherit the same XWiki permissions.
- XWiki audit trails cannot distinguish which MCP client initiated a change.
- Compromising the MCP service or one client session exposes the effective privileges of the shared service account.
- Least privilege is hard to enforce because all operations run as one principal.

Recommended remediation:
- Replace process-wide credentials with per-request or per-session user credentials.
- Prefer short-lived auth material over long-lived plaintext passwords in memory.
- If a service account must remain for compatibility, restrict it to the smallest possible scope and disable write operations by default.

### 3. High: SSE session hijacking and cross-session message injection risk

Severity: High

Affected locations:
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:92)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:95)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:103)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:105)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:117)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:125)
- [README.md](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/README.md:92)

Evidence:
- Sessions are stored as `Map<sessionId, res>`.
- `sessionId` is transmitted in the response stream and then used as a query parameter to authorize `/messages`.
- No caller identity, IP, token, or auth context is bound to the session.
- The server logs session IDs.

Impact:
- Anyone who learns a valid `sessionId` can send tool calls into that session.
- Query-string tokens are more likely to leak through logs, proxies, browser history, and operational tooling.
- Because the session is not identity-bound, the service cannot distinguish a legitimate client from a hijacker.

Recommended remediation:
- Do not use the raw `sessionId` as the only authorization factor.
- Bind sessions to an authenticated principal and verify that identity on every `/messages` request.
- Avoid putting bearer-like secrets in query strings.
- Remove session identifiers from logs or redact them.

### 4. High: Outbound TLS verification is disabled by default in Compose

Severity: High

Affected locations:
- [docker-compose.yml](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/docker-compose.yml:16)
- [README.md](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/README.md:189)

Evidence:
- Docker Compose sets `NODE_TLS_REJECT_UNAUTHORIZED=${NODE_TLS_REJECT_UNAUTHORIZED:-0}`.
- The documented default shown in the environment table is `0`.

Impact:
- HTTPS connections to XWiki will accept invalid or attacker-supplied certificates unless the operator overrides the value.
- A machine-in-the-middle attacker could intercept Basic credentials and tamper with wiki responses or write requests.

Recommended remediation:
- Remove the insecure default from `docker-compose.yml`.
- Make secure TLS verification the default behavior.
- If local development needs self-signed certificates, use an explicit opt-in profile or a dedicated dev override file.

### 5. Medium: Unbounded unauthenticated SSE sessions enable resource exhaustion

Severity: Medium

Affected locations:
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:92)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:94)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:107)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:148)

Evidence:
- Every `GET /sse` request allocates a session entry and a keepalive timer.
- There is no authentication, rate limiting, session cap, idle timeout policy, or per-client quota.
- `/health` discloses live session count, which helps an attacker measure DoS effectiveness.

Impact:
- An attacker can open many SSE connections and keep them alive to consume memory, file descriptors, and timer resources.
- Because the endpoint is unauthenticated, exploitation cost is low.

Recommended remediation:
- Authenticate before creating an SSE session.
- Add connection quotas, idle timeouts, and reverse-proxy rate limiting.
- Consider whether SSE is needed at all if JSON-RPC over HTTP is sufficient for your clients.

### 6. Medium: XML request body is built by string interpolation without proper escaping

Severity: Medium

Affected locations:
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:51)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:52)

Evidence:
- `title` is inserted directly into XML element content.
- `content` is wrapped in `CDATA`, but the code does not handle embedded `]]>` sequences.

Impact:
- Special characters in `title` can break the XML structure or alter request semantics.
- A malicious caller may be able to trigger malformed backend requests or inject unintended XML payload structure.
- This is partly a data integrity issue, but in a service that proxies authenticated write access it becomes a security concern too.

Recommended remediation:
- Escape XML special characters in element text.
- Safely encode content instead of interpolating raw strings into XML.
- Consider sending the format XWiki expects through a supported library or a safer serializer.

### 7. Medium: No request validation, rate limiting, or outbound timeout controls

Severity: Medium

Affected locations:
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:15)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:24)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:68)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:116)

Evidence:
- `limit`, `page_path`, `title`, and `content` are accepted without bounds checking.
- No application-level rate limiting is present.
- `fetch()` calls do not use an abort signal or timeout.

Impact:
- Attackers can send oversized or pathological requests that increase CPU, memory, or backend load.
- A slow or malicious upstream XWiki endpoint can tie up Node.js request handlers indefinitely.
- Large `content` payloads can be used to amplify write abuse against XWiki.

Recommended remediation:
- Enforce schema validation with explicit bounds and allowed character sets where appropriate.
- Add per-route rate limits and concurrency controls.
- Apply outbound request timeouts and fail fast on hung XWiki calls.

### 8. Medium: Container runs as root

Severity: Medium

Affected locations:
- [Dockerfile](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/Dockerfile:1)
- [Dockerfile](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/Dockerfile:15)

Evidence:
- The image uses `node:20-alpine` and never switches to a non-root user.

Impact:
- If the Node.js process is compromised, the attacker gains root inside the container.
- Container root is not equivalent to host root, but it still increases blast radius and weakens defense in depth.

Recommended remediation:
- Use a non-root runtime user.
- Copy only needed files and set ownership explicitly.

### 9. Low: Operational logging exposes session identifiers

Severity: Low

Affected locations:
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:70)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:96)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:110)
- [server.js](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/server.js:125)

Evidence:
- The code logs request methods and full session IDs to stdout.

Impact:
- Log readers, aggregators, and support tooling may gain enough data to hijack sessions while they are active.
- This compounds Finding 3.

Recommended remediation:
- Remove session IDs from logs, or hash/truncate them.
- Move to structured logging with explicit redaction rules.

### 10. Low: No dependency lockfile or reproducible install baseline

Severity: Low

Affected locations:
- [package.json](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/package.json:1)
- [Dockerfile](/C:/Users/ChristianFoellmann/projects/wus-technik/xwiki-mcp-server/Dockerfile:6)

Evidence:
- The repo contains `package.json` but no `package-lock.json`.
- The image build uses `npm install`, which resolves transitive dependencies at build time.

Impact:
- Builds are less reproducible.
- Security patch state is harder to verify and review.
- Dependency auditing and provenance controls are weaker than they should be for a network-facing service.

Recommended remediation:
- Commit a lockfile.
- Prefer `npm ci` in container builds once a lockfile exists.
- Add dependency scanning in CI.

## Attack Paths

### Likely attack path today

1. An attacker finds the exposed port `3000`.
2. They call `POST /mcp` directly with `tools/list`.
3. They invoke `get_xwiki_page` to enumerate sensitive content.
4. They invoke `create_xwiki_page` to overwrite or plant content using the server's shared XWiki account.

### Likely SSE abuse path

1. An attacker opens many `GET /sse` connections to consume resources.
2. They reuse or steal a `sessionId` from logs, a proxy, or another client context.
3. They post arbitrary tool calls to `/messages?sessionId=...`.

### Likely transport attack path in a misconfigured environment

1. The service connects to XWiki over HTTPS with certificate verification disabled.
2. A machine-in-the-middle presents a forged certificate.
3. The attacker captures Basic credentials and tampers with wiki reads or writes.

## Recommended Remediation Order

### Immediate

1. Add authentication and authorization to `/mcp`, `/sse`, and `/messages`.
2. Remove the insecure `NODE_TLS_REJECT_UNAUTHORIZED=0` default.
3. Disable or gate `create_xwiki_page` until request identity is enforced.
4. Stop logging session IDs.

### Near term

1. Implement per-user XWiki auth context for every tool call.
2. Replace query-string session authorization with authenticated session binding.
3. Add request validation, rate limiting, quotas, and upstream timeouts.
4. Escape or safely serialize XML for page writes.

### Defense in depth

1. Run the container as a non-root user.
2. Add a lockfile and dependency scanning.
3. Reduce public metadata leakage from `/health`.
4. Place the service behind a reverse proxy that enforces TLS, auth, and request limits.

## Suggested Security Acceptance Criteria For The Hosted Branch

- Every tool call is attributable to one authenticated end user.
- No plaintext user password is stored beyond the minimum request or session lifetime required.
- Write operations are impossible without a verified user identity and explicit authorization.
- SSE or any alternate transport uses the same auth guarantees as `/mcp`.
- TLS certificate verification is enabled by default in every non-test deployment.
- Rate limiting and timeouts are enforced at both the application and proxy layers.

## Overall Rating

Current risk posture: High

Reason:
- The service is network-facing, unauthenticated, capable of authenticated writes to XWiki, and ships with an insecure outbound TLS default in Compose.
