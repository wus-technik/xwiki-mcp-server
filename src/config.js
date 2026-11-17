const list = (v) => (v || "").split(",").map((s) => s.trim()).filter(Boolean);
const t = (v) => (v || "").trim();
const stripSlash = (v) => t(v).replace(/\/$/, "");

export function loadConfig(env = process.env) {
  const port = t(env.PORT) || "3000";
  const xwikiUrl = stripSlash(env.XWIKI_URL);
  return {
    port,
    nodeEnv: env.NODE_ENV || "development",
    devTlsBypass: env.NODE_TLS_REJECT_UNAUTHORIZED === "0",
    xwikiUrl,
    // Public base URL for page links returned to MCP clients; xwikiUrl is usually an internal
    // Docker hostname that clients cannot open. Falls back to xwikiUrl.
    xwikiPublicUrl: stripSlash(t(env.XWIKI_PUBLIC_URL) || xwikiUrl),
    xwikiWiki: t(env.XWIKI_WIKI) || "xwiki",
    oauthClientId: t(env.OAUTH_CLIENT_ID) || "",
    oauthClientSecret: env.OAUTH_CLIENT_SECRET || "",
    oauthRedirectUri: t(env.OAUTH_REDIRECT_URI) || "",
    authentikIssuer: stripSlash(env.AUTHENTIK_ISSUER),
    mcpBaseUrl: stripSlash(t(env.MCP_BASE_URL) || `http://localhost:${port}`),
    sessionSecret: env.SESSION_SECRET || "",
    tokenEncKeyRaw: t(env.TOKEN_ENC_KEY),
    tokenEncKey: Buffer.from(t(env.TOKEN_ENC_KEY), "base64"),
    // Where the persistent store lives (sessions, tokens); required.
    storeFile: t(env.STORE_FILE) || "",
    allowedGroups: env.ALLOWED_GROUPS ? list(env.ALLOWED_GROUPS) : ["AdminsIT", "xwiki_redaktion"],
    extraRedirectUris: list(env.EXTRA_REDIRECT_URIS),
    extraOrigins: list(env.EXTRA_ORIGINS),
    authDebug: env.AUTH_DEBUG === "1",
  };
}

export function validateConfig(cfg) {
  if (!cfg.sessionSecret || !cfg.sessionSecret.trim() || Buffer.byteLength(cfg.sessionSecret) < 32) {
    throw new Error("SESSION_SECRET must be set and at least 32 bytes long.");
  }
  if (!cfg.tokenEncKeyRaw) {
    throw new Error("TOKEN_ENC_KEY must be set (32 bytes, base64-encoded).");
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cfg.tokenEncKeyRaw) || cfg.tokenEncKey.toString("base64") !== cfg.tokenEncKeyRaw) {
    throw new Error("TOKEN_ENC_KEY is not valid standard base64.");
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
