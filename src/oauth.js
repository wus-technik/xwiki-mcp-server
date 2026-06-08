import { Router } from "express";
import { randomUUID, createHash, randomBytes } from "node:crypto";
import { SignJWT, jwtVerify, decodeJwt } from "jose";
import { storeAuthState, consumeAuthState, storeAuthCode, consumeAuthCode, createSession, getSession, deleteSession } from "./session-store.js";

export function createOAuthHandlers(cfg) {
  const {
    mcpBaseUrl,
    authentikIssuer,
    oauthClientId,
    oauthClientSecret,
    oauthRedirectUri,
    sessionSecret,
  } = cfg;

  const jwtSecret = new TextEncoder().encode(sessionSecret || "dev-insecure-secret-change-me");

  const resourceMetadata = (_req, res) => {
    res.json({
      resource: mcpBaseUrl,
      authorization_servers: [mcpBaseUrl],
      bearer_methods_supported: ["header"],
      scopes_supported: ["openid", "profile", "email"],
    });
  };

  const asMetadata = (_req, res) => {
    res.json({
      issuer: mcpBaseUrl,
      authorization_endpoint: `${mcpBaseUrl}/oauth/authorize`,
      token_endpoint: `${mcpBaseUrl}/oauth/token`,
      registration_endpoint: `${mcpBaseUrl}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
    });
  };

  const register = (req, res) => {
    res.status(201).json({
      ...req.body,
      client_id: randomUUID(),
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_secret_expires_at: 0,
    });
  };

  const authorize = (req, res) => {
    const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;

    if (response_type !== "code") return res.status(400).json({ error: "unsupported_response_type" });
    if (code_challenge_method !== "S256") return res.status(400).json({ error: "invalid_request", error_description: "Only S256 PKCE supported" });
    if (!code_challenge || !state || !redirect_uri) return res.status(400).json({ error: "invalid_request" });

    const serverState = randomUUID();
    storeAuthState(serverState, { clientState: state, redirect_uri, code_challenge, client_id });

    const params = new URLSearchParams({
      response_type: "code",
      client_id: oauthClientId,
      redirect_uri: oauthRedirectUri,
      scope: "openid profile email",
      state: serverState,
      nonce: randomBytes(16).toString("hex"),
    });

    res.redirect(`${authentikIssuer}/application/o/authorize/?${params}`);
  };

  const callback = async (req, res) => {
    const { code, state, error } = req.query;
    if (error) return res.status(400).send("Auth error. Please try again.");

    const authData = consumeAuthState(state);
    if (!authData) return res.status(400).send("Invalid or expired state parameter.");

    let userId;
    try {
      const tokenRes = await fetch(`${authentikIssuer}/application/o/token/`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: oauthRedirectUri,
          client_id: oauthClientId,
          client_secret: oauthClientSecret,
        }),
      });
      if (!tokenRes.ok) throw new Error(`status ${tokenRes.status}`);
      const tokens = await tokenRes.json();
      const claims = decodeJwt(tokens.id_token);
      userId = String(claims.preferred_username || claims.email || claims.sub || randomUUID());
    } catch {
      return res.status(502).send("Failed to complete authentication. Please try again.");
    }

    // Capture XWiki session cookie. When deployed at the same origin as XWiki (e.g.
    // xwiki.example.com/mcp/), the browser's XWiki session cookie is present here.
    // Empty string if not same-origin or user has no active XWiki session yet —
    // in that case tool calls will fail with XWikiAuthError and trigger re-auth.
    const xwikiCookie = req.headers.cookie || "";
    const sessionId = createSession(userId, xwikiCookie);

    const mcpCode = randomUUID();
    storeAuthCode(mcpCode, sessionId, authData.code_challenge);

    const redirectParams = new URLSearchParams({ code: mcpCode, state: authData.clientState });
    res.redirect(`${authData.redirect_uri}?${redirectParams}`);
  };

  const token = async (req, res) => {
    const { grant_type, code, code_verifier } = req.body;
    if (grant_type !== "authorization_code") {
      return res.status(400).json({ error: "unsupported_grant_type" });
    }
    if (!code || !code_verifier) {
      return res.status(400).json({ error: "invalid_request" });
    }

    const codeData = consumeAuthCode(code);
    if (!codeData) return res.status(400).json({ error: "invalid_grant" });

    const computed = createHash("sha256").update(code_verifier).digest("base64url");
    if (computed !== codeData.codeChallenge) {
      return res.status(400).json({ error: "invalid_grant" });
    }

    const session = getSession(codeData.sessionId);
    if (!session) return res.status(400).json({ error: "invalid_grant" });

    const accessToken = await new SignJWT({ sub: session.userId, sid: codeData.sessionId })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("8h")
      .setIssuedAt()
      .sign(jwtSecret);

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 8 * 3600,
    });
  };

  const logout = async (req, res) => {
    const auth = req.headers.authorization || "";
    const tok = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (tok) {
      try {
        const { payload } = await jwtVerify(tok, jwtSecret);
        if (payload.sid) deleteSession(payload.sid);
      } catch { /* expired or invalid, nothing to clean up */ }
    }
    res.json({ message: "Logged out." });
  };

  return { resourceMetadata, asMetadata, register, authorize, callback, token, logout };
}

export function createOAuthRouter(cfg) {
  const h = createOAuthHandlers(cfg);
  const router = Router();

  router.get("/.well-known/oauth-protected-resource", h.resourceMetadata);
  router.get("/.well-known/oauth-authorization-server", h.asMetadata);
  router.post("/oauth/register", h.register);
  router.get("/oauth/authorize", h.authorize);
  router.get("/oauth/callback", h.callback);
  router.post("/oauth/token", h.token);
  router.get("/oauth/logout", h.logout);

  return router;
}
