import express from "express";
import cookieParser from "cookie-parser";
import { loadConfig } from "./config.js";
import { createOAuthRouter, createOAuthHandlers } from "./oauth.js";
import { mountMetadata } from "./metadata.js";
import { createAuthMiddleware } from "./auth-middleware.js";
import { createAuthDebugLogger } from "./auth-debug.js";
import { createSseRouter } from "./sse-handler.js";
import { createXWikiClient, XWikiAuthError } from "./xwiki-client.js";
import { createUploadRouter } from "./upload-route.js";
import { handleMcpRequest } from "./mcp-handler.js";
import { deleteSession } from "./session-store.js";

export function createApp(overrides = {}) {
  const cfg = { ...loadConfig(), ...overrides };

  const xwikiClient = overrides.xwikiClient || createXWikiClient({
    baseUrl: cfg.xwikiUrl,
    publicUrl: cfg.xwikiPublicUrl,
    wiki: cfg.xwikiWiki,
  });

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  const authDebugLogger = createAuthDebugLogger(cfg.authDebug);

  // Claude Code constructs OAuth URLs as origin+/path, ignoring the /mcp base path.
  // Mount the real handlers at root so those requests reach the right logic.
  const oauthCfg = {
    mcpBaseUrl: cfg.mcpBaseUrl,
    authentikIssuer: cfg.authentikIssuer,
    oauthClientId: cfg.oauthClientId,
    oauthClientSecret: cfg.oauthClientSecret,
    oauthRedirectUri: cfg.oauthRedirectUri,
    sessionSecret: cfg.sessionSecret,
    store: cfg.store,
    extraRedirectUris: cfg.extraRedirectUris || [],
  };
  const h = createOAuthHandlers(oauthCfg);
  mountMetadata(app, cfg);
  app.post("/register", h.register);
  app.get("/authorize", h.authorize);
  app.post("/token", h.token);

  const authMiddleware = createAuthMiddleware({
    sessionSecret: cfg.sessionSecret,
    mcpBaseUrl: cfg.mcpBaseUrl,
    authDebugLogger,
  });

  const mcpRouter = express.Router();

  mcpRouter.use(createOAuthRouter(oauthCfg));

  mcpRouter.post("/", authMiddleware, async (req, res) => {
    const { method, params, id } = req.body;
    const sessionCtx = req.mcpSession;

    let result;
    try {
      result = await handleMcpRequest(method, params, sessionCtx, xwikiClient, {
        sessionSecret: cfg.sessionSecret,
        mcpBaseUrl: cfg.mcpBaseUrl,
      });
    } catch (e) {
      if (e instanceof XWikiAuthError) {
        authDebugLogger.warn("xwiki_session_expired", req, {
          sessionId: req.mcpSession.sessionId,
          userId: req.mcpSession.userId,
        });
        deleteSession(req.mcpSession.sessionId);
        res.setHeader(
          "WWW-Authenticate",
          `Bearer error="invalid_token", error_description="XWiki session expired. Please re-authenticate."`
        );
        return res.status(401).json({ error: "xwiki_session_expired" });
      }
      return res.json({ jsonrpc: "2.0", id, error: { code: e.code || -32600, message: "Internal error" } });
    }

    if (result === null) {
      if (id === undefined) return res.status(202).end();
      return res.json({ jsonrpc: "2.0", id });
    }
    res.json({ jsonrpc: "2.0", id, result });
  });

  mcpRouter.use(createSseRouter({
    sessionSecret: cfg.sessionSecret,
    mcpBaseUrl: cfg.mcpBaseUrl,
    authDebugLogger,
    xwikiClient,
  }));

  // Not wrapped with authMiddleware: a bare `curl -T` can't send a Bearer token.
  // The signed, single-use token in the URL path is the auth.
  mcpRouter.use(createUploadRouter({ sessionSecret: cfg.sessionSecret, xwikiClient }));

  mcpRouter.get("/health", (_req, res) => {
    res.json({ status: "ok", xwiki: cfg.xwikiUrl ? "configured" : "not configured" });
  });

  app.use("/mcp", mcpRouter);
  app.locals.xwikiClient = xwikiClient;

  // Body-parser failures (malformed JSON etc.) answer JSON, not Express's HTML page.
  app.use((err, req, res, next) => {
    if (res.headersSent || !err || typeof err.status !== "number" || err.status < 400 || err.status >= 500 || !err.type) return next(err);
    const isRegister = req.path === "/register" || req.path === "/mcp/oauth/register";
    res.status(err.status).json({ error: isRegister ? "invalid_client_metadata" : "invalid_request" });
  });

  return app;
}
