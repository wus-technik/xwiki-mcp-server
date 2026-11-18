# XWiki MCP Server

MCP (Model Context Protocol) server for interacting with XWiki instances. This server allows you to search, read, and create pages in XWiki through the REST API.

## 🚀 Features

- **Article Search**: Search pages in XWiki using the search API
- **Page Reading**: Get the full content of any XWiki page
- **Page Creation/Update**: Create or update pages in XWiki using CommonMark Markdown (this wiki's default document syntax)

## 🔐 Authentication

The server is its own OAuth 2.1 authorization server (dynamic client registration, PKCE S256, rotating refresh tokens) and signs users in through Authentik:

1. The MCP client registers itself and opens the browser at `/mcp/oauth/authorize`.
2. The user signs in at Authentik (transparent if an SSO session exists). Only members of `ALLOWED_GROUPS` get through.
3. The browser passes through the XWiki login on the same hostname; the resulting XWiki session cookie is used for exactly one request.
4. On the first login with a client the user confirms access on a consent page.
5. With that one-time cookie the server creates a personal XWiki consent token (`xwiki-mcp – <client> – <date>`, 90 days) and discards the cookie. The token appears in the XWiki profile under "Applications" and can be revoked there.
6. The client receives an access token (1 h) and a refresh token (rotated on every use, valid for 30 days after its last use).

All XWiki calls then run with `Authorization: Bearer <consent token>` under the user's own permissions, so an XWiki restart does not end the session. The XWiki token is renewed automatically once less than 14 days are left. A session ends when the client revokes it, when the client has not refreshed for 30 days, when Authentik rejects the user (deactivated or no longer in an allowed group), or when the token is deleted in the XWiki profile. The server then deletes the session's XWiki token as well.

## 🔌 Connecting a client

The URL is all a client needs. It discovers the OAuth endpoints from `/.well-known/oauth-protected-resource` and opens the browser for the login:

```
https://xwiki.wus-technik.com/mcp
```

- **claude.ai / Claude app:** add a custom connector with this URL and connect.
- **ChatGPT (chatgpt.com / app):** add a connector (developer mode) with this URL and connect.
- **Claude Code:** `claude mcp add --transport http xwiki https://xwiki.wus-technik.com/mcp`, then log in via `/mcp`.
- **Codex CLI:** `codex mcp add xwiki --url https://xwiki.wus-technik.com/mcp`, then `codex mcp login xwiki`.

No client secret, header or token has to be configured by hand.

## 📋 Prerequisites

- Docker and Docker Compose installed
- Node.js 20+ (if running without Docker)
- Access to an XWiki instance with REST API enabled and consent tokens in the user profile ("Applications"; tested with XWiki 18.7.0)
- An Authentik OAuth2/OIDC application (scopes `openid profile email offline_access`)

## 🔧 Installation

### Option 1: Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/alfredfs85/xwiki-mcp-server.git
cd xwiki-mcp-server
```

2. Generate the two secrets (32 random bytes each) and store them in the password manager:
```bash
openssl rand -base64 32   # SESSION_SECRET
openssl rand -base64 32   # TOKEN_ENC_KEY
```

3. Provide the environment variables (see [Environment Variables](#-environment-variables)) in the shell or stack definition that runs Compose:
```bash
XWIKI_URL=http://your-xwiki-internal-host:8080
XWIKI_PUBLIC_URL=https://your-domain.com
AUTHENTIK_ISSUER=https://your-authentik-instance.com
AUTHENTIK_APP_SLUG=xwiki-mcp
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_REDIRECT_URI=https://your-domain.com/mcp/oauth/callback
MCP_BASE_URL=https://your-domain.com/mcp
SESSION_SECRET=<32 random bytes, base64>
TOKEN_ENC_KEY=<32 random bytes, base64>
```
`docker-compose.yml` sets `STORE_FILE=/data/store.json` on the `./data` volume.

> **Important:** the store file is unusable without its key. Back up `TOKEN_ENC_KEY` in the password manager. If the key is missing or wrong, the server refuses to start (no automatic fresh start).

4. Build and run the container:
```bash
docker-compose up -d --build
```

5. Verify the server is running:
```bash
curl https://your-domain.com/mcp/health
```

### Option 2: Local Execution

1. Install dependencies:
```bash
npm install
```

2. Set the same environment variables as above, plus a writable store path, e.g. `STORE_FILE=./data/store.json`.

3. Run the server:
```bash
node server.js
```

The server listens on `http://localhost:3000`. It exits with code 1 if `SESSION_SECRET`, `TOKEN_ENC_KEY` or `STORE_FILE` is missing or invalid, or if the store file cannot be opened with the key.

## 🚀 Deployment (HAProxy)

The MCP server must share the public hostname with XWiki: the login passes through the XWiki login on the same origin, so the XWiki session cookie reaches `/mcp/oauth/complete`. The proxy forwards these paths to the MCP backend **unchanged** (no path rewriting) and everything else to XWiki:

```
^/(mcp(/.*)?|register|authorize|token|revoke|\.well-known/(oauth-protected-resource|oauth-authorization-server)(/mcp)?|\.well-known/openid-configuration/mcp)$
```

The root paths (`/register`, `/authorize`, `/token`, `/revoke` and the discovery documents) serve clients that build OAuth URLs from the origin and ignore the `/mcp` base path. `/.well-known/openid-configuration` without suffix stays with XWiki.

**Required env vars for this setup:**
- `XWIKI_URL=http://xwiki-postgres-tomcat-web:8080` — use the internal Docker hostname (join the same network)
- `XWIKI_PUBLIC_URL=https://xwiki.wus-technik.com` — public URL used for page links returned to clients
- `MCP_BASE_URL=https://xwiki.wus-technik.com/mcp`
- `OAUTH_REDIRECT_URI=https://xwiki.wus-technik.com/mcp/oauth/callback`

## 📡 Endpoints

### MCP (Streamable HTTP, JSON responses)
```
POST /mcp
```
JSON-RPC 2.0 with `Authorization: Bearer <access token>`. `GET` and `DELETE` on `/mcp` answer 405 (no SSE stream). Without a valid token the answer is 401 with a `WWW-Authenticate` header that points to the resource metadata.

### OAuth
```
POST /mcp/oauth/register     dynamic client registration
GET  /mcp/oauth/authorize    login (browser)
GET  /mcp/oauth/callback     return from Authentik
GET  /mcp/oauth/complete     return from the XWiki login
POST /mcp/oauth/consent      consent page
POST /mcp/oauth/token        authorization_code and refresh_token grants
POST /mcp/oauth/revoke       revocation (RFC 7009): ends the session and deletes its XWiki token
```

### Discovery
```
GET /.well-known/oauth-protected-resource
GET /.well-known/oauth-authorization-server
```
Also served below `/mcp/.well-known/…` and with the `/mcp` suffix.

### Health Check
```
GET /mcp/health
```
Returns the server status and whether XWiki is configured.

## 🛠️ Available Tools

### `search_xwiki`
Searches for articles in XWiki.

**Parameters:**
- `query` (required): Search term
- `limit` (optional): Maximum number of results (default: 10)
- `include_headings` (optional): Include parsed XWiki headings for each result so clients can discover exact section names

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "search_xwiki",
    "arguments": {
      "query": "documentation",
      "limit": 5,
      "include_headings": true
    }
  }
}
```

### `get_xwiki_page`
Gets the content of an XWiki page.

**Parameters:**
- `page_path` (required): Page path (e.g., `Main.WebHome` or `Space.Page`)
- `include_content` (optional): Set to `false` to return only metadata plus content length info
- `heading` (optional): Return only the section that starts at the matching XWiki heading
- `heading_occurrence` (optional): 1-based occurrence for duplicate headings, default `1`
- `content_offset` (optional): Character offset applied after any heading extraction
- `content_length` (optional): Maximum number of characters to return after any heading extraction

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "get_xwiki_page",
    "arguments": {
      "page_path": "Main.WebHome",
      "heading": "Deployment",
      "heading_occurrence": 1,
      "content_length": 500
    }
  }
}
```

### `create_xwiki_page`
Creates or updates a page in XWiki.

**Parameters:**
- `page_path` (required): Page path
- `title` (required): Page title
- `content` (required): Content in CommonMark Markdown syntax (this wiki's default document syntax)

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "create_xwiki_page",
    "arguments": {
      "page_path": "Test.MyPage",
      "title": "My Test Page",
      "content": "= Title =\n\nPage content..."
    }
  }
}
```

## 🐳 Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PORT` | Server port | no | `3000` |
| `XWIKI_URL` | XWiki internal URL (REST calls and the consent token page) | yes | - |
| `XWIKI_PUBLIC_URL` | Public XWiki URL used for page links in tool results | no | `XWIKI_URL` |
| `XWIKI_WIKI` | Wiki name | no | `xwiki` |
| `AUTHENTIK_ISSUER` | Authentik base URL (e.g. `https://auth.example.com`) | yes | - |
| `AUTHENTIK_APP_SLUG` | Slug of the Authentik application; ID token issuer `<AUTHENTIK_ISSUER>/application/o/<slug>/` | no | `xwiki-mcp` |
| `OAUTH_CLIENT_ID` | Authentik OAuth2 client ID | yes | - |
| `OAUTH_CLIENT_SECRET` | Authentik OAuth2 client secret | yes | - |
| `OAUTH_REDIRECT_URI` | Callback URL registered in Authentik, `<MCP_BASE_URL>/oauth/callback` | yes | - |
| `MCP_BASE_URL` | Public base URL of the MCP server; issuer and resource in the OAuth metadata | yes | `http://localhost:<PORT>` |
| `SESSION_SECRET` | Signs the access tokens (HS256); at least 32 bytes. The server does not start without it | yes | - |
| `TOKEN_ENC_KEY` | Encrypts the secrets in the store file; exactly 32 bytes, standard base64. The server does not start without it | yes | - |
| `STORE_FILE` | Path of the persistent store (clients, consents, sessions, refresh token families, pending cleanups) | yes | - (Compose: `/data/store.json`) |
| `ALLOWED_GROUPS` | Authentik groups allowed to log in (comma-separated) | no | `AdminsIT,xwiki_redaktion` |
| `EXTRA_REDIRECT_URIS` | Additional client redirect URIs (comma-separated, exact match) besides loopback, claude.ai, claude.com and chatgpt.com | no | empty |
| `EXTRA_ORIGINS` | Additional allowed `Origin` values for `POST /mcp` besides claude.ai, claude.com, chatgpt.com and the origin of `MCP_BASE_URL` | no | empty |
| `AUTH_DEBUG` | `1` logs auth events (event name, shortened session id, user, client name; never tokens or cookies) | no | off |
| `NODE_ENV` | `production` refuses `NODE_TLS_REJECT_UNAUTHORIZED=0` | no | `development` |

> **The store file is unusable without its key.** Back up `TOKEN_ENC_KEY` (and `SESSION_SECRET`) in the password manager. With a wrong or missing key the server does not start.

## 📝 Security Notes

- ⚠️ **Never** commit credentials to the repository
- ⚠️ The store file holds the XWiki consent tokens and Authentik refresh tokens encrypted with `TOKEN_ENC_KEY` (AES-256-GCM); refresh tokens of the MCP clients are stored only as SHA-256 hashes. Browser cookies are never stored.
- ⚠️ No token, cookie or refresh token is written to the log
- ⚠️ `NODE_TLS_REJECT_UNAUTHORIZED=0` is for development only and refused with `NODE_ENV=production`
- ⚠️ The `.env` file is in `.gitignore` for security

## 🤝 Contributing

Contributions are welcome. Please:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## 🐛 Reporting Issues

If you encounter any issues, please open an issue on the GitHub repository.

## 👤 Author

**alfredfs85**

- GitHub: [@alfredfs85](https://github.com/alfredfs85)

## 🙏 Acknowledgments

- XWiki for their excellent platform and REST API
- The Model Context Protocol team for the MCP standard
