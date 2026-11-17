import { jwtVerify } from "jose";
import { getSession } from "./session-store.js";
import { sendUnauthorized } from "./metadata.js";

export function createAuthMiddleware({ sessionSecret, mcpBaseUrl = "", authDebugLogger }) {
  const jwtSecret = new TextEncoder().encode(sessionSecret);

  return async (req, res, next) => {
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) {
      authDebugLogger?.info("missing_bearer", req);
      return sendUnauthorized(res, { mcpBaseUrl }, { description: "Bearer token required" });
    }

    const token = auth.slice(7);
    let payload;
    try {
      ({ payload } = await jwtVerify(token, jwtSecret));
    } catch {
      authDebugLogger?.warn("invalid_jwt", req);
      return sendUnauthorized(res, { mcpBaseUrl }, { error: "invalid_token" });
    }

    const session = getSession(payload.sid);
    if (!session) {
      authDebugLogger?.warn("session_not_found", req, { sessionId: payload.sid });
      return sendUnauthorized(res, { mcpBaseUrl }, { error: "invalid_token", description: "Session expired or not found" });
    }

    authDebugLogger?.info("session_authenticated", req, { sessionId: payload.sid, userId: session.userId });
    req.mcpSession = { ...session, sessionId: payload.sid };
    next();
  };
}
