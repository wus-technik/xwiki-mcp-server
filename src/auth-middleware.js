// Bearer check for /mcp. Access tokens are HS256 JWTs issued by /token (sessions.js):
// iss = aud = MCP_BASE_URL, exp, sid, client_id, ver. A token is valid only for a session
// that still exists in the store and belongs to the same client.
import { jwtVerify } from "jose";
import { sendUnauthorized } from "./metadata.js";
import { sealAad } from "./sessions.js";

// SessionCtx = { sessionId, userId, xwikiUser, xwikiToken, tokenVersion }, built from the
// session's CURRENT state (decrypted XWiki token). Returns null if the session is gone or
// its token cannot be opened.
export function sessionCtxFrom(store, sid, session) {
  if (!session) return null;
  try {
    return {
      sessionId: sid,
      userId: session.userId,
      xwikiUser: session.xwikiUser,
      xwikiToken: store.openField(session.xwikiTokenSealed, sealAad(sid, "xwikiToken")),
      tokenVersion: session.tokenVersion,
    };
  } catch {
    return null;
  }
}

// AUTH_DEBUG fields: never tokens, only a shortened session id, user and client name.
export function debugFields(state, sid, session) {
  return {
    sid: typeof sid === "string" ? sid.slice(0, 8) : undefined,
    user: session?.userId,
    client: session ? state.clients?.[session.clientId]?.clientName : undefined,
  };
}

export function createAuthMiddleware(deps) {
  const { store, cfg } = deps;
  const logger = deps.logger;
  const base = cfg.mcpBaseUrl;
  const secret = new TextEncoder().encode(cfg.sessionSecret || "");
  const reject = (res) => sendUnauthorized(res, cfg, { error: "invalid_token" });

  return async (req, res, next) => {
    const auth = typeof req.headers.authorization === "string" ? req.headers.authorization.trim() : "";
    if (!auth) {
      logger?.info("missing_bearer", req);
      // RFC 6750 §3.1: no error code when the request carries no credentials at all.
      return sendUnauthorized(res, cfg, { description: "Bearer token required" });
    }
    // Scheme is case-insensitive (RFC 7235); any other scheme or an empty token is invalid.
    const m = /^bearer +(\S+)$/i.exec(auth);
    if (!m) {
      logger?.warn("invalid_authorization", req);
      return reject(res);
    }

    let payload;
    try {
      ({ payload } = await jwtVerify(m[1], secret, {
        algorithms: ["HS256"],
        issuer: base,
        audience: base,
        requiredClaims: ["exp", "sid"],
      }));
    } catch {
      logger?.warn("invalid_jwt", req);
      return reject(res);
    }

    const sid = payload.sid;
    const state = store.read();
    const session = typeof sid === "string" ? state.sessions[sid] : undefined;
    if (!session) {
      logger?.warn("session_not_found", req, debugFields(state, sid, null));
      return reject(res);
    }
    if (payload.client_id !== session.clientId) {
      logger?.warn("client_mismatch", req, debugFields(state, sid, session));
      return reject(res);
    }
    // `ver` is informational: an access token (1 h) outlives an XWiki token renewal, which
    // increments the session's tokenVersion. Older ver values are accepted; the context
    // always carries the session's current token and version.
    const ctx = sessionCtxFrom(store, sid, session);
    if (!ctx) {
      logger?.warn("session_unreadable", req, debugFields(state, sid, session));
      return reject(res);
    }

    logger?.info("session_authenticated", req, debugFields(state, sid, session));
    req.mcpSession = ctx;
    next();
  };
}
