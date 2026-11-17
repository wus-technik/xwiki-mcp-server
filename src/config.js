const list = (v) => (v || "").split(",").map((s) => s.trim()).filter(Boolean);
const stripSlash = (v) => (v || "").replace(/\/$/, "");

export function loadConfig(env = process.env) {
  const port = env.PORT || "3000";
  const xwikiUrl = stripSlash(env.XWIKI_URL);
  return {
    port,
    nodeEnv: env.NODE_ENV || "development",
    devTlsBypass: env.NODE_TLS_REJECT_UNAUTHORIZED === "0",
    xwikiUrl,
    // Public base URL for page links returned to MCP clients; xwikiUrl is usually an internal
    // Docker hostname that clients cannot open. Falls back to xwikiUrl.
    xwikiPublicUrl: stripSlash(env.XWIKI_PUBLIC_URL || xwikiUrl),
    xwikiWiki: env.XWIKI_WIKI || "xwiki",
    oauthClientId: env.OAUTH_CLIENT_ID || "",
    oauthClientSecret: env.OAUTH_CLIENT_SECRET || "",
    oauthRedirectUri: env.OAUTH_REDIRECT_URI || "",
    authentikIssuer: stripSlash(env.AUTHENTIK_ISSUER),
    mcpBaseUrl: stripSlash(env.MCP_BASE_URL || `http://localhost:${port}`),
    sessionSecret: env.SESSION_SECRET || "",
    tokenEncKey: Buffer.from(env.TOKEN_ENC_KEY || "", "base64"),
    // Where the persistent store lives (sessions, tokens); required.
    storeFile: env.STORE_FILE || "",
    allowedGroups: env.ALLOWED_GROUPS ? list(env.ALLOWED_GROUPS) : ["AdminsIT", "xwiki_redaktion"],
    extraRedirectUris: list(env.EXTRA_REDIRECT_URIS),
    extraOrigins: list(env.EXTRA_ORIGINS),
    authDebug: env.AUTH_DEBUG === "1",
  };
}

export function validateConfig(cfg) {
  if (!cfg.sessionSecret || Buffer.byteLength(cfg.sessionSecret) < 32) {
    throw new Error("SESSION_SECRET must be set and at least 32 bytes long.");
  }
  if (!cfg.tokenEncKey || cfg.tokenEncKey.length === 0) {
    throw new Error("TOKEN_ENC_KEY must be set (32 bytes, base64-encoded).");
  }
  if (cfg.tokenEncKey.length !== 32) {
    throw new Error(`TOKEN_ENC_KEY must decode to exactly 32 bytes (got ${cfg.tokenEncKey.length}).`);
  }
  if (!cfg.storeFile) {
    throw new Error("STORE_FILE must be set (path of the persistent store).");
  }
  if (cfg.devTlsBypass && cfg.nodeEnv === "production") {
    throw new Error("NODE_TLS_REJECT_UNAUTHORIZED=0 in production is not allowed.");
  }
}
