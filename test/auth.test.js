// /mcp token check (Task 11): HS256 only, iss/aud = MCP_BASE_URL, exp required, known
// session from the encrypted store, client_id bound to the session.
import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import express from "express";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SignJWT, UnsecuredJWT } from "jose";
import { createAuthMiddleware } from "../src/auth-middleware.js";
import { createApp } from "../src/app.js";
import { openStore } from "../src/store.js";
import { createSession } from "../src/sessions.js";

const KEY = Buffer.alloc(32, 7);
const SECRET = "test-secret-32-chars-minimum-pad";
const BASE = "https://xwiki.example.com/mcp";
const CID = "client-1";

async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auth-"));
  const store = openStore({ file: path.join(dir, "s.json"), key: KEY });
  await store.mutate((s) => {
    s.clients[CID] = { clientId: CID, clientName: "Claude", redirectUris: [], createdAt: 1, lastUsedAt: 1 };
  });
  const cfg = { mcpBaseUrl: BASE, sessionSecret: SECRET, authDebug: false };
  const deps = { store, cfg, now: Date.now };
  const { sid } = await createSession(deps, {
    sub: "sub-1", userId: "alice", xwikiUser: "xwiki:XWiki.alice", clientId: CID,
    authentikRefresh: "AK-RT", xwikiToken: "XW-TOKEN-1", consentId: "c-1", tokenExpiresAt: Date.now() + 1e9,
  });
  return { store, cfg, deps, sid };
}

function sign(claims, { iss = BASE, aud = BASE, exp = "1h", secret = SECRET } = {}) {
  let jwt = new SignJWT(claims).setProtectedHeader({ alg: "HS256" }).setIssuedAt();
  if (iss) jwt = jwt.setIssuer(iss);
  if (aud) jwt = jwt.setAudience(aud);
  if (exp !== null) jwt = jwt.setExpirationTime(exp);
  return jwt.sign(new TextEncoder().encode(secret));
}

function protectedApp(deps) {
  const app = express();
  app.use(createAuthMiddleware(deps));
  app.get("/protected", (req, res) => res.json(req.mcpSession));
  return app;
}

function assertChallenge(res) {
  assert.equal(res.status, 401);
  const h = res.headers["www-authenticate"];
  assert.ok(h, "WWW-Authenticate present");
  assert.match(h, new RegExp(`resource_metadata="${BASE}/\\.well-known/oauth-protected-resource"`));
  return h;
}

test("missing Authorization header → 401 with resource_metadata", async () => {
  const { deps } = await setup();
  assertChallenge(await request(protectedApp(deps)).get("/protected"));
});

test("empty Authorization header → 401 without error code", async () => {
  const { deps } = await setup();
  const h = assertChallenge(await request(protectedApp(deps)).get("/protected").set("Authorization", ""));
  assert.doesNotMatch(h, /error=/);
});

test("missing Authorization header → challenge without error code", async () => {
  const { deps } = await setup();
  const h = assertChallenge(await request(protectedApp(deps)).get("/protected"));
  assert.doesNotMatch(h, /error=/);
});

test("scheme is case-insensitive: 'bearer <token>' is accepted", async () => {
  const { deps, sid } = await setup();
  const token = await sign({ sub: "sub-1", sid, client_id: CID, ver: 1 });
  for (const scheme of ["bearer", "BEARER", "Bearer"]) {
    const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `${scheme} ${token}`);
    assert.equal(res.status, 200, scheme);
  }
});

for (const value of ["Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Bearer    ", "Token abc", "garbage"]) {
  test(`present but unusable Authorization '${value}' → 401 invalid_token`, async () => {
    const { deps } = await setup();
    const res = await request(protectedApp(deps)).get("/protected").set("Authorization", value);
    assert.match(assertChallenge(res), /error="invalid_token"/);
  });
}

test("non-string sid claim → 401 invalid_token", async () => {
  const { deps } = await setup();
  for (const sid of [123, { a: 1 }, ["x"]]) {
    const token = await sign({ sub: "sub-1", sid, client_id: CID, ver: 1 });
    const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `Bearer ${token}`);
    assert.match(assertChallenge(res), /error="invalid_token"/);
  }
});

test("malformed token → 401 invalid_token", async () => {
  const { deps } = await setup();
  const res = await request(protectedApp(deps)).get("/protected").set("Authorization", "Bearer not-a-jwt");
  assert.match(assertChallenge(res), /error="invalid_token"/);
});

test("valid token → SessionCtx with decrypted XWiki token and tokenVersion", async () => {
  const { deps, sid } = await setup();
  const token = await sign({ sub: "sub-1", sid, client_id: CID, ver: 1 });
  const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `Bearer ${token}`);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, {
    sessionId: sid, userId: "alice", xwikiUser: "xwiki:XWiki.alice", xwikiToken: "XW-TOKEN-1", tokenVersion: 1,
  });
});

for (const [name, opts] of [
  ["wrong aud", { aud: "https://other.example.com/mcp" }],
  ["wrong iss", { iss: "https://other.example.com/mcp" }],
  ["missing aud", { aud: null }],
  ["missing iss", { iss: null }],
  ["expired", { exp: Math.floor(Date.now() / 1000) - 60 }],
  ["no exp", { exp: null }],
  ["wrong secret", { secret: "another-secret-32-chars-minimum-p" }],
]) {
  test(`token with ${name} → 401 with resource_metadata`, async () => {
    const { deps, sid } = await setup();
    const token = await sign({ sub: "sub-1", sid, client_id: CID, ver: 1 }, opts);
    const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `Bearer ${token}`);
    assert.match(assertChallenge(res), /error="invalid_token"/);
  });
}

test("alg none → 401 with resource_metadata", async () => {
  const { deps, sid } = await setup();
  const token = new UnsecuredJWT({ sub: "sub-1", sid, client_id: CID, ver: 1 })
    .setIssuer(BASE).setAudience(BASE).setIssuedAt().setExpirationTime("1h").encode();
  const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `Bearer ${token}`);
  assert.match(assertChallenge(res), /error="invalid_token"/);
});

test("HS512 token with the right secret → 401 (HS256 only)", async () => {
  const { deps, sid } = await setup();
  const token = await new SignJWT({ sub: "sub-1", sid, client_id: CID, ver: 1 })
    .setProtectedHeader({ alg: "HS512" }).setIssuer(BASE).setAudience(BASE).setIssuedAt().setExpirationTime("1h")
    .sign(new TextEncoder().encode(SECRET));
  const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `Bearer ${token}`);
  assertChallenge(res);
});

test("unknown session → 401", async () => {
  const { deps } = await setup();
  const token = await sign({ sub: "sub-1", sid: "no-such-session", client_id: CID, ver: 1 });
  const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `Bearer ${token}`);
  assertChallenge(res);
});

test("missing sid claim → 401", async () => {
  const { deps } = await setup();
  const token = await sign({ sub: "sub-1", client_id: CID, ver: 1 });
  const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `Bearer ${token}`);
  assertChallenge(res);
});

test("client_id not matching the session → 401", async () => {
  const { deps, sid } = await setup();
  const token = await sign({ sub: "sub-1", sid, client_id: "client-other", ver: 1 });
  const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `Bearer ${token}`);
  assertChallenge(res);
});

test("token with an older ver than the session is accepted (outlives a renewal)", async () => {
  const { deps, sid, store } = await setup();
  await store.mutate((s) => {
    s.sessions[sid].tokenVersion = 3;
    s.sessions[sid].xwikiTokenSealed = store.sealField("XW-TOKEN-3", `session:${sid}:xwikiToken`);
  });
  const token = await sign({ sub: "sub-1", sid, client_id: CID, ver: 1 });
  const res = await request(protectedApp(deps)).get("/protected").set("Authorization", `Bearer ${token}`);
  assert.equal(res.status, 200);
  assert.equal(res.body.tokenVersion, 3);
  assert.equal(res.body.xwikiToken, "XW-TOKEN-3");
});

test("POST /mcp without auth through createApp → 401 with resource_metadata", async () => {
  const { store } = await setup();
  const app = createApp({ sessionSecret: SECRET, mcpBaseUrl: BASE, store, authDebug: false, xwikiClient: {} });
  const res = await request(app).post("/mcp").send({ jsonrpc: "2.0", method: "initialize", id: 1 });
  assertChallenge(res);
});
