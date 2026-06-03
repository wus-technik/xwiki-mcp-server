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
XWIKI_URL=https://your-xwiki-instance.com
XWIKI_USERNAME=your_username
XWIKI_PASSWORD=your_password
XWIKI_WIKI=xwiki
```

3. Build and run the container:
```bash
docker-compose up -d --build
```

4. Verify the server is running:
```bash
curl http://localhost:3000/health
```

### Option 2: Local Execution

1. Install dependencies:
```bash
npm install
```

2. Configure environment variables:
```bash
export XWIKI_URL=https://your-xwiki-instance.com
export XWIKI_USERNAME=your_username
export XWIKI_PASSWORD=your_password
export XWIKI_WIKI=xwiki
```

3. Run the server:
```bash
node server.js
```

The server will be available at `http://localhost:3000`

## 🔐 SSL Configuration (Optional)

If you need HTTPS, you can use the `setup.sh` script to generate self-signed SSL certificates:

```bash
chmod +x setup.sh
./setup.sh --ssl
```

**Note**: Generated certificates (`server.key` and `server.crt`) are in `.gitignore` and will not be uploaded to the repository.

## 🚀 Deployment (HAProxy)

The MCP server must share the same public hostname as XWiki so the browser's XWiki session cookie is present on MCP requests.

```
frontend https-in
  bind *:443 ssl crt /etc/ssl/certs/xwiki.pem
  acl is_mcp path_beg /mcp/
  use_backend mcp_backend if is_mcp
  default_backend xwiki_backend

backend mcp_backend
  option forwardfor
  http-request set-header X-Forwarded-Host %[req.hdr(Host)]
  http-request set-header X-Forwarded-Proto https
  server mcp 127.0.0.1:3000

backend xwiki_backend
  server xwiki 127.0.0.1:8080
```

Preserve `Host` header so OAuth redirect URIs and callback URLs resolve correctly.

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

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "search_xwiki",
    "arguments": {
      "query": "documentation",
      "limit": 5
    }
  }
}
```

### `get_xwiki_page`
Gets the content of an XWiki page.

**Parameters:**
- `page_path` (required): Page path (e.g., `Main.WebHome` or `Space.Page`)

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "get_xwiki_page",
    "arguments": {
      "page_path": "Main.WebHome"
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
| `XWIKI_URL` | Your XWiki instance URL | - |
| `XWIKI_USERNAME` | Username for authentication | - |
| `XWIKI_PASSWORD` | Password for authentication | - |
| `XWIKI_WIKI` | Wiki name | `xwiki` |
| `MCP_MODE` | MCP operation mode | `http` |
| `NODE_TLS_REJECT_UNAUTHORIZED` | Disable SSL validation (development only) | `0` |

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
