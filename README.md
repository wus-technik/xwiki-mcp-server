# XWiki MCP Server

MCP (Model Context Protocol) server for interacting with XWiki instances. This server allows you to search, read, and create pages in XWiki through the REST API.

## 🚀 Features

- **Article Search**: Search pages in XWiki using the search API
- **Page Reading**: Get the full content of any XWiki page
- **Page Creation/Update**: Create or update pages in XWiki using XWiki syntax

## 🔐 Authentication

Login is browser-based via Authentik SSO. MCP clients that support remote MCP OAuth (e.g. Claude Desktop) will open a browser window automatically.

1. Connect your MCP client to `https://xwiki.wus-technik.com/mcp`
2. The client discovers OAuth endpoints from `/.well-known/oauth-protected-resource`
3. Your browser opens → Authentik login (skip if already logged in via SSO)
4. MCP client receives a session token and connects
5. All XWiki actions run under your real user permissions

## 📋 Prerequisites

- Docker and Docker Compose installed
- Node.js 20+ (if running without Docker)
- Access to an XWiki instance with REST API enabled

## 🔧 Installation

### Option 1: Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/alfredfs85/xwiki-mcp-server.git
cd xwiki-mcp-server
```

2. Configure environment variables by creating a `.env` file:
```bash
XWIKI_URL=http://your-xwiki-internal-host:8080
XWIKI_WIKI=xwiki
AUTHENTIK_ISSUER=https://your-authentik-instance.com
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_REDIRECT_URI=https://your-domain.com/mcp/oauth/callback
MCP_BASE_URL=https://your-domain.com/mcp
SESSION_SECRET=your_random_secret
```

3. Build and run the container:
```bash
docker-compose up -d --build
```

4. Verify the server is running:
```bash
curl https://your-domain.com/mcp/health
```

### Option 2: Local Execution

1. Install dependencies:
```bash
npm install
```

2. Configure environment variables:
```bash
export XWIKI_URL=http://your-xwiki-internal-host:8080
export XWIKI_WIKI=xwiki
export AUTHENTIK_ISSUER=https://your-authentik-instance.com
export OAUTH_CLIENT_ID=your_client_id
export OAUTH_CLIENT_SECRET=your_client_secret
export OAUTH_REDIRECT_URI=https://your-domain.com/mcp/oauth/callback
export MCP_BASE_URL=https://your-domain.com/mcp
export SESSION_SECRET=your_random_secret
```

3. Run the server:
```bash
node server.js
```

The server will be available at `http://localhost:3000`

## 🚀 Deployment (HAProxy)

The MCP server must share the same public hostname as XWiki so the browser's XWiki session cookie is present on MCP requests.

```
frontend https-in
  bind *:443 ssl crt /etc/ssl/certs/xwiki.pem
  # Match both /mcp (exact — the JSON-RPC endpoint) and /mcp/* (SSE, OAuth, discovery)
  acl is_mcp     path     /mcp
  acl is_mcp_sub path_beg /mcp/
  use_backend mcp_backend if is_mcp OR is_mcp_sub
  default_backend xwiki_backend

backend mcp_backend
  option forwardfor
  http-request set-header X-Forwarded-Host %[req.hdr(Host)]
  http-request set-header X-Forwarded-Proto https
  # Strip the /mcp/ prefix so Express receives clean paths (/sse, /oauth/callback, etc.)
  # Paths without a trailing slash (i.e. /mcp itself) are passed through unchanged.
  http-request set-path %[path,regsub(^/mcp/,/)]
  server mcp 127.0.0.1:3000

backend xwiki_backend
  server xwiki 127.0.0.1:8080
```

Preserve `Host` header so OAuth redirect URIs and callback URLs resolve correctly.

**Required env vars for this setup:**
- `XWIKI_URL=http://xwiki-postgres-tomcat-web:8080` — use the internal Docker hostname (join the same network)
- `MCP_BASE_URL=https://xwiki.wus-technik.com/mcp`
- `OAUTH_REDIRECT_URI=https://xwiki.wus-technik.com/mcp/oauth/callback` — includes the `/mcp/` prefix (goes through HAProxy)

## 📡 Endpoints

### Health Check
```
GET /health
```
Returns the server status and XWiki configuration.

### MCP JSON-RPC
```
POST /mcp
```
Main endpoint for MCP communication using JSON-RPC 2.0.

### Server-Sent Events (SSE)
```
GET /sse
POST /messages?sessionId={sessionId}
```
Alternative endpoints for communication via Server-Sent Events.

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
- `content` (required): Content in XWiki syntax

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

## 🔌 Integration with Cursor/Claude Desktop

To use this MCP server with Cursor or Claude Desktop, add the following configuration to your MCP configuration file:

```json
{
  "mcpServers": {
    "xwiki": {
      "url": "http://localhost:3000/mcp",
      "transport": "http"
    }
  }
}
```

## 🐳 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `XWIKI_URL` | XWiki internal URL (used for REST API calls) | - |
| `XWIKI_WIKI` | Wiki name | `xwiki` |
| `AUTHENTIK_ISSUER` | Authentik base URL | - |
| `OAUTH_CLIENT_ID` | Authentik OAuth2 client ID | - |
| `OAUTH_CLIENT_SECRET` | Authentik OAuth2 client secret | - |
| `OAUTH_REDIRECT_URI` | OAuth callback URL (must include `/mcp/` prefix if behind HAProxy) | - |
| `MCP_BASE_URL` | Public base URL of the MCP server | - |
| `SESSION_SECRET` | Secret for signing JWTs (min 32 chars) | - |
| `NODE_ENV` | Set to `production` to enforce TLS | - |

## 📝 Security Notes

- ⚠️ **Never** commit credentials to the repository
- ⚠️ Self-signed SSL certificates are for development only
- ⚠️ In production, use valid certificates and set `NODE_TLS_REJECT_UNAUTHORIZED=1`
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
