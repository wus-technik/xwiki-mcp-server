import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import express from "express";
import { createOAuthRouter } from "../src/oauth.js";
import { createAuthMiddleware } from "../src/auth-middleware.js";
import { createSession } from "../src/session-store.js";
import { createApp } from "../src/app.js";
import { getSession } from "../src/session-store.js";
import { XWikiAuthError } from "../src/xwiki-client.js";

function makeTestApp(overrides = {}) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  const router = createOAuthRouter({
    mcpBaseUrl: "https://mcp.example.com",
    authentikIssuer: "https://auth.example.com",
    oauthClientId: "client_id",
    oauthClientSecret: "client_secret",
    oauthRedirectUri: "https://mcp.example.com/oauth/callback",
    sessionSecret: "test-secret-32-chars-minimum-pad",
    ...overrides,
  });
  app.use(router);
  return app;
}

test("GET /.well-known/oauth-protected-resource returns resource metadata", async () => {
  const app = makeTestApp();
  const res = await request(app).get("/.well-known/oauth-protected-resource");
  assert.equal(res.status, 200);
  assert.equal(res.body.resource, "https://mcp.example.com");
  assert.deepEqual(res.body.authorization_servers, ["https://mcp.example.com"]);
});

test("GET /.well-known/oauth-authorization-server returns AS metadata", async () => {
  const app = makeTestApp();
  const res = await request(app).get("/.well-known/oauth-authorization-server");
  assert.equal(res.status, 200);
  assert.equal(res.body.authorization_endpoint, "https://mcp.example.com/oauth/authorize");
  assert.equal(res.body.token_endpoint, "https://mcp.example.com/oauth/token");
  assert.deepEqual(res.body.code_challenge_methods_supported, ["S256"]);
});

test("GET /oauth/authorize with missing params returns 400", async () => {
  const app = makeTestApp();
  const res = await request(app).get("/oauth/authorize?response_type=code");
  assert.equal(res.status, 400);
});

test("GET /oauth/authorize with valid params redirects to Authentik", async () => {
  const app = makeTestApp();
  const res = await request(app).get("/oauth/authorize").query({
    response_type: "code",
    client_id: "mcp-client",
    redirect_uri: "http://localhost:9000/callback",
    state: "client-state-123",
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
  });
  assert.equal(res.status, 302);
  assert.ok(res.headers.location.startsWith("https://auth.example.com/application/o/authorize/"));
  const url = new URL(res.headers.location);
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("client_id"), "client_id");
});

test("auth middleware rejects missing Authorization header with 401", async () => {
  const app = express();
  app.use(createAuthMiddleware({ sessionSecret: "test-secret-32-chars-minimum-pad" }));
  app.get("/protected", (req, res) => res.json({ userId: req.mcpSession.userId }));
  const res = await request(app).get("/protected");
  assert.equal(res.status, 401);
  assert.ok(res.headers["www-authenticate"]);
});

test("auth middleware rejects malformed token with 401", async () => {
  const app = express();
  app.use(createAuthMiddleware({ sessionSecret: "test-secret-32-chars-minimum-pad" }));
  app.get("/protected", (req, res) => res.json({ ok: true }));
  const res = await request(app).get("/protected").set("Authorization", "Bearer not-a-jwt");
  assert.equal(res.status, 401);
});

test("auth middleware attaches mcpSession for valid token", async () => {
  const sessionId = createSession("alice", "XWIKI_SESSION=test");
  const { SignJWT } = await import("jose");
  const secret = new TextEncoder().encode("test-secret-32-chars-minimum-pad");
  const token = await new SignJWT({ sub: "alice", sid: sessionId })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("1h")
    .setIssuedAt()
    .sign(secret);

  const app = express();
  app.use(createAuthMiddleware({ sessionSecret: "test-secret-32-chars-minimum-pad" }));
  app.get("/protected", (req, res) => res.json({ userId: req.mcpSession.userId, sessionId: req.mcpSession.sessionId }));
  const res = await request(app).get("/protected").set("Authorization", `Bearer ${token}`);
  assert.equal(res.status, 200);
  assert.equal(res.body.userId, "alice");
  assert.equal(res.body.sessionId, sessionId);
});

test("POST /mcp without auth returns 401 with WWW-Authenticate", async () => {
  const app = createApp({ sessionSecret: "test-secret-32-chars-minimum-pad" });
  const res = await request(app)
    .post("/mcp")
    .send({ jsonrpc: "2.0", method: "initialize", id: 1 });
  assert.equal(res.status, 401);
  assert.ok(res.headers["www-authenticate"]);
});

test("POST /mcp tools/list with valid auth returns tool list", async () => {
  const sessionId = createSession("bob", "XWIKI_SESSION=xyz");
  const { SignJWT } = await import("jose");
  const secret = new TextEncoder().encode("test-secret-32-chars-minimum-pad");
  const token = await new SignJWT({ sub: "bob", sid: sessionId })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("1h")
    .setIssuedAt()
    .sign(secret);

  const mockClient = {
    search: async () => [],
    getPage: async () => ({ title: "", content: "", author: "", modified: "" }),
    createPage: async () => "",
  };
  const app = createApp({ sessionSecret: "test-secret-32-chars-minimum-pad", xwikiClient: mockClient });
  const res = await request(app)
    .post("/mcp")
    .set("Authorization", `Bearer ${token}`)
    .send({ jsonrpc: "2.0", method: "tools/list", id: 2 });
  assert.equal(res.status, 200);
  assert.equal(res.body.result.tools.length, 3);
});

test("POST /mcp tools/call search_xwiki passes session context to xwiki client", async () => {
  const sessionId = createSession("carol", "XWIKI_SESSION=abc");
  const { SignJWT } = await import("jose");
  const secret = new TextEncoder().encode("test-secret-32-chars-minimum-pad");
  const token = await new SignJWT({ sub: "carol", sid: sessionId })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("1h")
    .setIssuedAt()
    .sign(secret);

  let capturedCtx;
  const mockClient = {
    search: async (query, limit, ctx) => { capturedCtx = ctx; return []; },
    getPage: async () => ({}),
    createPage: async () => "",
  };
  const app = createApp({ sessionSecret: "test-secret-32-chars-minimum-pad", xwikiClient: mockClient });
  await request(app)
    .post("/mcp")
    .set("Authorization", `Bearer ${token}`)
    .send({ jsonrpc: "2.0", method: "tools/call", params: { name: "search_xwiki", arguments: { query: "test" } }, id: 3 });
  assert.equal(capturedCtx.userId, "carol");
  assert.equal(capturedCtx.xwikiCookie, "XWIKI_SESSION=abc");
});

test("POST /mcp returns 401 and deletes session when XWiki session expires", async () => {
  const sessionId = createSession("dan", "XWIKI_SESSION=expired");
  const { SignJWT } = await import("jose");
  const secret = new TextEncoder().encode("test-secret-32-chars-minimum-pad");
  const token = await new SignJWT({ sub: "dan", sid: sessionId })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("1h")
    .setIssuedAt()
    .sign(secret);

  const mockClient = {
    search: async () => { throw new XWikiAuthError("XWiki session expired"); },
    getPage: async () => { throw new XWikiAuthError("XWiki session expired"); },
    createPage: async () => { throw new XWikiAuthError("XWiki session expired"); },
  };

  const app = createApp({ sessionSecret: "test-secret-32-chars-minimum-pad", xwikiClient: mockClient });
  const res = await request(app)
    .post("/mcp")
    .set("Authorization", `Bearer ${token}`)
    .send({ jsonrpc: "2.0", method: "tools/call", params: { name: "search_xwiki", arguments: { query: "test" } }, id: 5 });

  assert.equal(res.status, 401);
  assert.ok(res.headers["www-authenticate"]);
  assert.equal(getSession(sessionId), null);
});
