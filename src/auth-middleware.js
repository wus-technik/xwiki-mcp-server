import { jwtVerify } from "jose";
import { getSession } from "./session-store.js";

export function createAuthMiddleware({ sessionSecret, mcpBaseUrl = "", authDebugLogger }) {
  const jwtSecret = new TextEncoder().encode(sessionSecret || "dev-insecure-secret-change-me");

  return async (req, res, next) => {
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) {
      authDebugLogger?.info("missing_bearer", req);
      res.setHeader(
        "WWW-Authenticate",
        `Bearer realm="${mcpBaseUrl}", resource_metadata="${mcpBaseUrl}/.well-known/oauth-protected-resource"`
      );
      return res.status(401).json({ error: "unauthorized", error_description: "Bearer token required" });
    }

    const token = auth.slice(7);
    let payload;
    try {
      ({ payload } = await jwtVerify(token, jwtSecret));
    } catch {
      authDebugLogger?.warn("invalid_jwt", req);
      res.setHeader("WWW-Authenticate", `Bearer error="invalid_token"`);
      return res.status(401).json({ error: "invalid_token" });
    }

    const session = getSession(payload.sid);
    if (!session) {
      authDebugLogger?.warn("session_not_found", req, { sessionId: payload.sid });
      res.setHeader("WWW-Authenticate", `Bearer error="invalid_token", error_description="Session expired"`);
      return res.status(401).json({ error: "invalid_token", error_description: "Session expired or not found" });
    }

    authDebugLogger?.info("session_authenticated", req, { sessionId: payload.sid, userId: session.userId });
    req.mcpSession = { ...session, sessionId: payload.sid };
    next();
  };
}
