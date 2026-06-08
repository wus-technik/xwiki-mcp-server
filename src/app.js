import express from "express";
import cookieParser from "cookie-parser";
import {
  XWIKI_URL, XWIKI_WIKI,
  OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI,
  AUTHENTIK_ISSUER, MCP_BASE_URL, SESSION_SECRET,
} from "./config.js";
import { createOAuthRouter, createOAuthHandlers } from "./oauth.js";
import { createAuthMiddleware } from "./auth-middleware.js";
import { createSseRouter } from "./sse-handler.js";
import { createXWikiClient, XWikiAuthError } from "./xwiki-client.js";
import { handleMcpRequest } from "./mcp-handler.js";
import { deleteSession } from "./session-store.js";

export function createApp(overrides = {}) {
  const cfg = {
    xwikiUrl: XWIKI_URL,
    xwikiWiki: XWIKI_WIKI,
    oauthClientId: OAUTH_CLIENT_ID,
    oauthClientSecret: OAUTH_CLIENT_SECRET,
    oauthRedirectUri: OAUTH_REDIRECT_URI,
    authentikIssuer: AUTHENTIK_ISSUER,
    mcpBaseUrl: MCP_BASE_URL,
    sessionSecret: SESSION_SECRET,
    ...overrides,
  };

  const xwikiClient = overrides.xwikiClient || createXWikiClient({
    baseUrl: cfg.xwikiUrl,
    wiki: cfg.xwikiWiki,
  });

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());

  // Claude Code constructs OAuth URLs as origin+/path, ignoring the /mcp base path.
  // Mount the real handlers at root so those requests reach the right logic.
  const oauthCfg = {
    mcpBaseUrl: cfg.mcpBaseUrl,
    authentikIssuer: cfg.authentikIssuer,
    oauthClientId: cfg.oauthClientId,
    oauthClientSecret: cfg.oauthClientSecret,
    oauthRedirectUri: cfg.oauthRedirectUri,
    sessionSecret: cfg.sessionSecret,
  };
  const h = createOAuthHandlers(oauthCfg);
  app.get("/.well-known/oauth-protected-resource", h.resourceMetadata);
  app.get("/.well-known/oauth-authorization-server", h.asMetadata);
  app.post("/register", h.register);
  app.get("/authorize", h.authorize);
  app.post("/token", h.token);

  const authMiddleware = createAuthMiddleware({
    sessionSecret: cfg.sessionSecret,
    mcpBaseUrl: cfg.mcpBaseUrl,
  });

  const mcpRouter = express.Router();

  mcpRouter.use(createOAuthRouter(oauthCfg));

  mcpRouter.post("/", authMiddleware, async (req, res) => {
    const { method, params, id } = req.body;
    const sessionCtx = req.mcpSession;

    let result;
    try {
      result = await handleMcpRequest(method, params, sessionCtx, xwikiClient);
    } catch (e) {
      if (e instanceof XWikiAuthError) {
        deleteSession(req.mcpSession.sessionId);
        res.setHeader(
          "WWW-Authenticate",
          `Bearer error="invalid_token", error_description="XWiki session expired. Please re-authenticate."`
        );
        return res.status(401).json({ error: "xwiki_session_expired" });
      }
      return res.json({ jsonrpc: "2.0", id, error: { code: e.code || -32600, message: "Internal error" } });
    }

    if (result === null) return res.json({ jsonrpc: "2.0", id });
    res.json({ jsonrpc: "2.0", id, result });
  });

  mcpRouter.use(createSseRouter({
    sessionSecret: cfg.sessionSecret,
    mcpBaseUrl: cfg.mcpBaseUrl,
    xwikiClient,
  }));

  mcpRouter.get("/health", (_req, res) => {
    res.json({ status: "ok", xwiki: cfg.xwikiUrl ? "configured" : "not configured" });
  });

  app.use("/mcp", mcpRouter);

  return app;
}
