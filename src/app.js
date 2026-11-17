import express from "express";
import cookieParser from "cookie-parser";
import { loadConfig } from "./config.js";
import { createOAuthRouter, createOAuthHandlers, sendError } from "./oauth.js";
import { mountMetadata } from "./metadata.js";
import { createAuthMiddleware } from "./auth-middleware.js";
import { createAuthDebugLogger } from "./auth-debug.js";
import { createAuthentik } from "./authentik.js";
import { createXWikiTokens } from "./xwiki-tokens.js";
import { createXWikiClient, XWikiAuthError } from "./xwiki-client.js";
import { createUploadRouter } from "./upload-route.js";
import { handleMcpRequest } from "./mcp-handler.js";
import { deleteSession } from "./session-store.js";

const FLOW_PAGE_PATHS = new Set([
  "/authorize",
  "/mcp/oauth/authorize",
  "/mcp/oauth/callback",
  "/mcp/oauth/complete",
  "/mcp/oauth/consent",
]);

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

  const authentik = overrides.authentik || createAuthentik({
    issuer: cfg.authentikIssuer || "",
    appSlug: cfg.authentikAppSlug,
    clientId: cfg.oauthClientId,
    clientSecret: cfg.oauthClientSecret,
    redirectUri: cfg.oauthRedirectUri,
    allowedGroups: cfg.allowedGroups || [],
  });
  const xwikiTokens = overrides.xwikiTokens || createXWikiTokens({ baseUrl: cfg.xwikiUrl || "" });

  // One handler set for both mounts: the login flow keeps its in-memory state there.
  // Claude Code constructs OAuth URLs as origin+/path, ignoring the /mcp base path.
  // Mount the real handlers at root so those requests reach the right logic.
  const h = createOAuthHandlers(
    { ...cfg, extraRedirectUris: cfg.extraRedirectUris || [] },
    { authentik, xwikiTokens, now: overrides.now || Date.now, logger: authDebugLogger },
  );
  app.locals.oauth = h;
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

  mcpRouter.use(createOAuthRouter(h));

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
    // Browser pages of the login flow get the flow's HTML error page.
    if (FLOW_PAGE_PATHS.has(req.path)) {
      return sendError(res, err.status, "Die Anfrage konnte nicht gelesen werden. Bitte im Programm erneut verbinden.", "invalid_request");
    }
    const isRegister = req.path === "/register" || req.path === "/mcp/oauth/register";
    res.status(err.status).json({ error: isRegister ? "invalid_client_metadata" : "invalid_request" });
  });

  // Anything else unhandled: plain error page, no stack trace, no request data in the log.
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    console.error(`[app] unhandled error: ${err?.name || "Error"}`);
    sendError(res, 500, "Interner Fehler. Bitte später erneut versuchen.", "server_error");
  });

  return app;
}
