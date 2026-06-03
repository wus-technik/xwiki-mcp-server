import { Router } from "express";
import { randomUUID } from "node:crypto";
import { createAuthMiddleware } from "./auth-middleware.js";
import { handleMcpRequest } from "./mcp-handler.js";

export function createSseRouter({ sessionSecret, mcpBaseUrl = "", xwikiClient }) {
  const router = Router();
  const authMiddleware = createAuthMiddleware({ sessionSecret, mcpBaseUrl });

  // sessionId → { res, userId, xwikiCookie }
  const sseSessions = new Map();

  router.get("/sse", authMiddleware, (req, res) => {
    const sseId = randomUUID();

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");

    sseSessions.set(sseId, {
      res,
      userId: req.mcpSession.userId,
      xwikiCookie: req.mcpSession.xwikiCookie,
    });

    res.write(`event: endpoint\ndata: /messages?sessionId=${sseId}\n\n`);

    const keepAlive = setInterval(() => res.write(":keepalive\n\n"), 30000);

    req.on("close", () => {
      clearInterval(keepAlive);
      sseSessions.delete(sseId);
    });
  });

  router.post("/messages", async (req, res) => {
    const sseSession = sseSessions.get(req.query.sessionId);
    if (!sseSession) return res.status(400).json({ error: "Session not found" });

    const { method, params, id } = req.body;
    const sessionCtx = { userId: sseSession.userId, xwikiCookie: sseSession.xwikiCookie };

    let result;
    try {
      result = await handleMcpRequest(method, params, sessionCtx, xwikiClient);
    } catch (e) {
      if (e.name === "XWikiAuthError") {
        // Close the SSE stream so the client reconnects and hits auth middleware again
        sseSession.res.write(`event: error\ndata: ${JSON.stringify({ error: "xwiki_session_expired" })}\n\n`);
        sseSession.res.end();
        sseSessions.delete(req.query.sessionId);
        res.setHeader(
          "WWW-Authenticate",
          `Bearer error="invalid_token", error_description="XWiki session expired. Please re-authenticate."`
        );
        return res.status(401).json({ error: "xwiki_session_expired" });
      }
      const response = { jsonrpc: "2.0", id, error: { code: e.code || -32600, message: "Internal error" } };
      sseSession.res.write(`event: message\ndata: ${JSON.stringify(response)}\n\n`);
      return res.status(202).end();
    }

    if (result === null) return res.status(202).end();

    const response = { jsonrpc: "2.0", id, result };
    sseSession.res.write(`event: message\ndata: ${JSON.stringify(response)}\n\n`);
    res.status(202).end();
  });

  return router;
}
