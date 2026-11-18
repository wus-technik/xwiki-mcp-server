// In-process fake of Authentik's OAuth2/OIDC provider for the end-to-end test:
// authorize (browser, SSO session set by the test), token endpoint (authorization_code
// with an RS256-signed ID token; refresh_token with rotation), userinfo with groups, JWKS.
// deactivate(user): refresh and userinfo are rejected. removeFromGroups(user): userinfo
// returns no groups (refresh still works, as in Authentik).
import express from "express";
import { randomBytes } from "node:crypto";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

const rand = () => randomBytes(24).toString("base64url");

export async function fakeAuthentik({ slug = "xwiki-mcp", clientId, clientSecret, users = {} }) {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "fake-1", alg: "RS256", use: "sig" };
  const accounts = new Map(Object.entries(users).map(([name, u]) => [name, { active: true, ...u }]));
  const codes = new Map(); // code → { username, nonce, redirectUri }
  const accessTokens = new Map(); // access token → username
  const refreshTokens = new Map(); // refresh token → username
  let browserUser = null;
  let issuer = "";

  const app = express();
  app.use(express.urlencoded({ extended: false }));

  app.get("/application/o/authorize/", (req, res) => {
    const q = req.query;
    if (q.client_id !== clientId || !browserUser) return res.status(400).send("bad request");
    const code = rand();
    codes.set(code, { username: browserUser, nonce: q.nonce, redirectUri: q.redirect_uri });
    const u = new URL(String(q.redirect_uri));
    u.searchParams.set("code", code);
    u.searchParams.set("state", String(q.state));
    res.redirect(302, u.toString());
  });

  const issue = (username) => {
    const at = rand();
    const rt = rand();
    accessTokens.set(at, username);
    refreshTokens.set(rt, username);
    return { access_token: at, refresh_token: rt, token_type: "Bearer", expires_in: 300 };
  };

  app.post("/application/o/token/", async (req, res) => {
    const b = req.body || {};
    if (b.client_id !== clientId || b.client_secret !== clientSecret) return res.status(401).json({ error: "invalid_client" });
    if (b.grant_type === "authorization_code") {
      const c = codes.get(b.code);
      codes.delete(b.code);
      const acct = c && accounts.get(c.username);
      if (!c || c.redirectUri !== b.redirect_uri || !acct?.active) return res.status(400).json({ error: "invalid_grant" });
      const idToken = await new SignJWT({ nonce: c.nonce, preferred_username: c.username })
        .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
        .setIssuer(`${issuer}/application/o/${slug}/`)
        .setAudience(clientId)
        .setSubject(acct.sub)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);
      return res.json({ ...issue(c.username), id_token: idToken });
    }
    if (b.grant_type === "refresh_token") {
      const username = refreshTokens.get(b.refresh_token);
      if (!username || !accounts.get(username)?.active) return res.status(400).json({ error: "invalid_grant" });
      refreshTokens.delete(b.refresh_token); // rotation: the old token is spent
      return res.json(issue(username));
    }
    return res.status(400).json({ error: "unsupported_grant_type" });
  });

  app.get("/application/o/userinfo/", (req, res) => {
    const m = /^Bearer (\S+)$/.exec(req.headers.authorization || "");
    const username = m && accessTokens.get(m[1]);
    const acct = username && accounts.get(username);
    if (!acct?.active) return res.status(401).json({ error: "invalid_token" });
    res.json({ sub: acct.sub, preferred_username: username, groups: [...acct.groups] });
  });

  app.get(`/application/o/${slug}/jwks/`, (_req, res) => res.json({ keys: [jwk] }));

  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  issuer = `http://127.0.0.1:${server.address().port}`;

  return {
    issuer,
    // The browser has an Authentik SSO session for this user.
    login(username) {
      browserUser = username;
    },
    deactivate(username) {
      accounts.get(username).active = false;
    },
    removeFromGroups(username) {
      accounts.get(username).groups = [];
    },
    close() {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}
