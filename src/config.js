export const PORT = process.env.PORT || "3000";
export const XWIKI_URL = (process.env.XWIKI_URL || "").replace(/\/$/, "");
export const XWIKI_WIKI = process.env.XWIKI_WIKI || "xwiki";

export const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "";
export const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
export const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI || "";
export const AUTHENTIK_ISSUER = (process.env.AUTHENTIK_ISSUER || "").replace(/\/$/, "");
export const MCP_BASE_URL = (process.env.MCP_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
export const SESSION_SECRET = process.env.SESSION_SECRET || "";

if (!SESSION_SECRET) {
  console.warn("[config] SESSION_SECRET not set — using insecure default. Required in production.");
}

export const NODE_ENV = process.env.NODE_ENV || "development";
export const DEV_TLS_BYPASS = process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0";

if (DEV_TLS_BYPASS && NODE_ENV === "production") {
  console.error("[config] NODE_TLS_REJECT_UNAUTHORIZED=0 in production is not allowed. Exiting.");
  process.exit(1);
}
