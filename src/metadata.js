// OAuth discovery metadata (RFC 9728 / RFC 8414 / OIDC alias) and the 401 challenge.
// Clients probe different paths, so every variant is served with identical content.
const RESOURCE_PATHS = [
  "/.well-known/oauth-protected-resource",
  "/.well-known/oauth-protected-resource/mcp",
  "/mcp/.well-known/oauth-protected-resource",
];

const AS_PATHS = [
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-authorization-server/mcp",
  "/mcp/.well-known/oauth-authorization-server",
  "/.well-known/openid-configuration/mcp",
  "/mcp/.well-known/openid-configuration",
];

export function resourceMetadata(cfg) {
  const base = cfg.mcpBaseUrl;
  return {
    resource: base,
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    scopes_supported: ["xwiki"],
  };
}

export function asMetadata(cfg) {
  const base = cfg.mcpBaseUrl;
  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    revocation_endpoint: `${base}/oauth/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["xwiki"],
  };
}

// Register on the app itself (full paths) before any router so no middleware shadows them.
export function mountMetadata(app, cfg) {
  for (const p of RESOURCE_PATHS) app.get(p, (_req, res) => res.json(resourceMetadata(cfg)));
  for (const p of AS_PATHS) app.get(p, (_req, res) => res.json(asMetadata(cfg)));
}

export function sendUnauthorized(res, cfg, { error, description } = {}) {
  const base = cfg.mcpBaseUrl;
  let header = `Bearer realm="${base}", resource_metadata="${base}/.well-known/oauth-protected-resource"`;
  if (error) header += `, error="${error}"`;
  if (description) {
    const safe = String(description).replace(/[\r\n]/g, "").replace(/[\\"]/g, (c) => "\\" + c);
    header += `, error_description="${safe}"`;
  }
  res.setHeader("WWW-Authenticate", header);
  const body = { error: error || "unauthorized" };
  if (description) body.error_description = String(description).replace(/[\r\n]/g, "");
  return res.status(401).json(body);
}
