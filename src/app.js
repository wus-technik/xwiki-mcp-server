import express from "express";
import cookieParser from "cookie-parser";
import { loadConfig } from "./config.js";
import { createOAuthRouter, createOAuthHandlers, sendError } from "./oauth.js";
import { mountMetadata } from "./metadata.js";
import { createAuthMiddleware, sessionCtxFrom, debugFields } from "./auth-middleware.js";
import { createAuthDebugLogger } from "./auth-debug.js";
import { createAuthentik } from "./authentik.js";
import { createXWikiTokens } from "./xwiki-tokens.js";
import { createXWikiClient, XWikiAuthError } from "./xwiki-client.js";
import { createUploadRouter } from "./upload-route.js";
import { handleMcpRequest, SUPPORTED_PROTOCOL_VERSIONS } from "./mcp-handler.js";
import { sendUnauthorized } from "./metadata.js";
import { isAllowedOrigin } from "./redirects.js";
import { endSession } from "./sessions.js";

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
  const authDebugLogger = createAuthDebugLogger(cfg.authDebug);
  // Origin check for every method on /mcp, mounted BEFORE the body parsers and the token check, so a
  // refused Origin wins over a malformed body or a missing token. Only browsers send Origin;
  // a present Origin outside the allowlist is refused (DNS-rebinding protection of the MCP spec).
  // The MCP-Protocol-Version check is NOT here: it runs behind the login (see versionGuard),
  // so clients without a token always get the 401 that leads them to the OAuth flow.
  const transportGuard = (req, res, next) => {
    const origin = req.headers.origin;
    if (origin !== undefined && !isAllowedOrigin(origin, cfg.mcpBaseUrl, cfg.extraOrigins || [])) {
      authDebugLogger.warn("origin_rejected", req);
      return res.status(403).json({ error: "forbidden_origin" });
    }
    next();
  };
  // After auth: a present but unsupported MCP-Protocol-Version header is refused with 400,
  // except for `initialize`, which negotiates the version in its body.
  const versionGuard = (req, res, next) => {
    const version = req.headers["mcp-protocol-version"];
    if (version !== undefined && !SUPPORTED_PROTOCOL_VERSIONS.includes(version) && req.body?.method !== "initialize") {
      authDebugLogger.warn("protocol_version_rejected", req, { protocolVersion: /^[\w.-]{1,32}$/.test(version) ? version : "<invalid>" });
      return res.status(400).json({ error: "unsupported_protocol_version", supported: SUPPORTED_PROTOCOL_VERSIONS });
    }
    next();
  };

  // Every method on /mcp and /mcp/ (also the 405 ones), before parsers and token check.
  app.all("/mcp", transportGuard);
  // Upload PUTs stream a raw body: the global parsers must not touch them.
  // POST /mcp parses its JSON body itself, behind the login (auth before parser).
  const notUpload = (mw) => (req, res, next) => (
    (req.method === "PUT" && req.path.startsWith("/mcp/uploads/")) || (req.method === "POST" && (req.path === "/mcp" || req.path === "/mcp/"))
      ? next() : mw(req, res, next));
  app.use(notUpload(express.json()));
  app.use(notUpload(express.urlencoded({ extended: false })));
  app.use(cookieParser());

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
  const now = overrides.now || Date.now;
  const h = createOAuthHandlers(
    { ...cfg, extraRedirectUris: cfg.extraRedirectUris || [] },
    { authentik, xwikiTokens, now, logger: authDebugLogger },
  );
  app.locals.oauth = h;
  // The session deps for background jobs (server.js → startBackground).
  app.locals.deps = { store: cfg.store, cfg, authentik, xwikiTokens, now };
  mountMetadata(app, cfg);
  app.post("/register", h.register);
  app.get("/authorize", h.authorize);
  app.post("/token", h.token);
  app.post("/revoke", h.revoke);
  app.post("/oauth/revoke", h.revoke);

  const deps = app.locals.deps;
  const authMiddleware = createAuthMiddleware({ ...deps, logger: authDebugLogger });

  // XWikiAuthError handling. XWiki rejected the session's token. Under `session:<sid>`:
  //  - session gone → 401 (someone else ended it);
  //  - session has a newer tokenVersion than the one used (a renewal replaced the token while
  //    the request was in flight) → retry ONCE, outside the lock, with the current token;
  //  - otherwise the token is really dead (e.g. deleted in the XWiki profile) → endSession
  //    ("xwiki-401", records the cleanup entry) and 401.
  // A second XWikiAuthError on the retry never retries again: if yet another renewal raced
  // it, the client just gets 401 and comes back with the session intact; otherwise the
  // session is ended as above.
  const runWithXWikiAuth = async (req, run) => {
    let ctx = req.mcpSession;
    for (let attempt = 0; ; attempt++) {
      try {
        return { result: await run(ctx) };
      } catch (e) {
        if (!(e instanceof XWikiAuthError)) throw e;
        const sid = ctx.sessionId;
        const usedVersion = ctx.tokenVersion;
        const outcome = await deps.store.withLock(`session:${sid}`, async () => {
          const state = deps.store.read();
          const session = state.sessions[sid];
          if (!session) return { kind: "gone" };
          const newer = session.tokenVersion > usedVersion;
          if (newer && attempt === 0) {
            const fresh = sessionCtxFrom(deps.store, sid, session);
            return fresh ? { kind: "retry", ctx: fresh } : { kind: "gone" };
          }
          if (newer) return { kind: "raced" };
          authDebugLogger.warn("xwiki_token_rejected", req, debugFields(state, sid, session));
          await endSession(deps, sid, "xwiki-401");
          return { kind: "ended" };
        });
        if (outcome.kind === "retry") {
          ctx = outcome.ctx;
          continue;
        }
        return { unauthorized: true };
      }
    }
  };

  const mcpRouter = express.Router();

  mcpRouter.use(createOAuthRouter(h));

  // Only POST carries MCP messages; no SSE stream (GET) and no session termination (DELETE).
  // Matches /mcp and /mcp/.
  mcpRouter.route("/")
    .get((_req, res) => res.set("Allow", "POST").status(405).json({ error: "method_not_allowed" }))
    .delete((_req, res) => res.set("Allow", "POST").status(405).json({ error: "method_not_allowed" }));

  mcpRouter.post("/", authMiddleware, express.json(), versionGuard, async (req, res) => {
    const body = req.body;
    // No batching: an array (or any non-object body) is an invalid request.
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return res.status(400).json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } });
    }
    // Without an id the message is a notification (notifications/initialized, cancelled,
    // progress, ...): acknowledged with 202 and no body, never dispatched, never an error.
    if (!Object.hasOwn(body, "id")) return res.status(202).end();
    const { method, params, id } = body;
    const toolConfig = { sessionSecret: cfg.sessionSecret, mcpBaseUrl: cfg.mcpBaseUrl };

    let outcome;
    try {
      outcome = await runWithXWikiAuth(req, (ctx) => handleMcpRequest(method, params, ctx, xwikiClient, toolConfig));
    } catch (e) {
      return res.json({ jsonrpc: "2.0", id, error: { code: e.code || -32600, message: "Internal error" } });
    }
    if (outcome.unauthorized) {
      return sendUnauthorized(res, cfg, {
        error: "invalid_token",
        description: "XWiki rejected the access token. Please re-authenticate.",
      });
    }

    const { result } = outcome;
    res.json({ jsonrpc: "2.0", id, result: result ?? {} });
  });

  // Not wrapped with authMiddleware: a bare `curl -T` can't send a Bearer token.
  // The signed, single-use token in the URL path is the auth.
  mcpRouter.use(createUploadRouter({ sessionSecret: cfg.sessionSecret, xwikiClient, store: cfg.store }));

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
    if (["/token", "/mcp/oauth/token", "/revoke", "/oauth/revoke", "/mcp/oauth/revoke"].includes(req.path)) {
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
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
