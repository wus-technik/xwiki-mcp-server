// /mcp transport (Task 11): protocol version negotiation, MCP-Protocol-Version header,
// Origin allowlist, 405 for GET/DELETE, XWikiAuthError handling (end session or one retry
// after a renewal), and the discovery/OAuth routes through the full app.
import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SignJWT } from "jose";
import { createApp } from "../src/app.js";
import { openStore } from "../src/store.js";
import { createSession, sealAad } from "../src/sessions.js";
import { XWikiAuthError } from "../src/xwiki-client.js";
import { handleMcpRequest } from "../src/mcp-handler.js";

const KEY = Buffer.alloc(32, 5);
const SECRET = "test-secret-32-chars-minimum-pad";
const BASE = "https://xwiki.example.com/mcp";
const CID = "client-1";

async function setup({ search, extraOrigins = [] } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-transport-"));
  const store = openStore({ file: path.join(dir, "s.json"), key: KEY });
  await store.mutate((s) => {
    s.clients[CID] = { clientId: CID, clientName: "Claude", redirectUris: [], createdAt: 1, lastUsedAt: 1 };
  });
  const cfg = { mcpBaseUrl: BASE, sessionSecret: SECRET };
  const { sid } = await createSession({ store, cfg, now: Date.now }, {
    sub: "sub-1", userId: "alice", xwikiUser: "xwiki:XWiki.alice", clientId: CID,
    authentikRefresh: "AK-RT", xwikiToken: "XW-TOKEN-1", consentId: "c-1", tokenExpiresAt: Date.now() + 1e9,
  });
  const calls = [];
  const xwikiClient = {
    search: async (query, limit, options, ctx) => {
      calls.push(ctx.xwikiToken);
      if (search) return search(ctx, calls.length);
      return [];
    },
  };
  const xwikiTokens = {
    // XWiki "unreachable": cleanup entries stay so the test can inspect them.
    deleteToken: async () => { throw Object.assign(new Error("unavailable"), { code: "unavailable" }); },
  };
  const app = createApp({
    sessionSecret: SECRET, mcpBaseUrl: BASE, store, xwikiClient, xwikiTokens,
    authentik: {}, authDebug: false, extraOrigins, extraRedirectUris: [],
  });
  const token = await new SignJWT({ sid, client_id: CID, ver: 1 })
    .setProtectedHeader({ alg: "HS256" }).setIssuer(BASE).setAudience(BASE).setSubject("sub-1")
    .setIssuedAt().setExpirationTime("1h").sign(new TextEncoder().encode(SECRET));
  return { app, store, sid, token, calls };
}

const searchCall = { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "search_xwiki", arguments: { query: "x" } } };

async function renew(store, sid, version, token) {
  await store.mutate((s) => {
    s.sessions[sid].tokenVersion = version;
    s.sessions[sid].xwikiTokenSealed = store.sealField(token, sealAad(sid, "xwikiToken"));
  });
}

// --- version negotiation ---------------------------------------------------------------

test("initialize answers a supported requested version", async () => {
  for (const v of ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]) {
    const r = await handleMcpRequest("initialize", { protocolVersion: v }, null, null);
    assert.equal(r.protocolVersion, v);
  }
});

test("initialize with an unknown or missing version answers 2025-06-18", async () => {
  assert.equal((await handleMcpRequest("initialize", { protocolVersion: "1999-01-01" }, null, null)).protocolVersion, "2025-06-18");
  assert.equal((await handleMcpRequest("initialize", undefined, null, null)).protocolVersion, "2025-06-18");
});

test("POST /mcp initialize with 2025-03-26 → 2025-03-26, with 1999-01-01 → 2025-06-18", async () => {
  const { app, token } = await setup();
  const a = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26" } });
  assert.equal(a.status, 200);
  assert.equal(a.body.result.protocolVersion, "2025-03-26");
  const b = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .send({ jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "1999-01-01" } });
  assert.equal(b.body.result.protocolVersion, "2025-06-18");
});

test("MCP-Protocol-Version header unsupported → 400; supported → 200", async () => {
  const { app, token } = await setup();
  const bad = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .set("MCP-Protocol-Version", "1999-01-01").send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(bad.status, 400);
  assert.equal(bad.type, "application/json");
  const ok = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .set("MCP-Protocol-Version", "2025-06-18").send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(ok.status, 200);
});

// --- Origin ------------------------------------------------------------------------------

test("Origin: evil → 403; none → 200; claude.ai → 200; MCP origin → 200; EXTRA_ORIGINS → 200", async () => {
  const { app, token } = await setup({ extraOrigins: ["https://extra.example"] });
  const send = (origin) => {
    const r = request(app).post("/mcp").set("Authorization", `Bearer ${token}`);
    if (origin) r.set("Origin", origin);
    return r.send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  };
  const evil = await send("https://evil.example");
  assert.equal(evil.status, 403);
  assert.equal(evil.type, "application/json");
  assert.equal((await send(null)).status, 200);
  assert.equal((await send("https://claude.ai")).status, 200);
  assert.equal((await send("https://xwiki.example.com")).status, 200);
  assert.equal((await send("https://extra.example")).status, 200);
});

for (const origin of ["https://CLAUDE.AI", "https://claude.ai/", "null", "https://claude.ai.evil.example", "http://claude.ai"]) {
  test(`Origin edge case '${origin}' → 403`, async () => {
    const { app, token } = await setup();
    const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
      .set("Origin", origin).send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(res.status, 403);
  });
}

test("bad Origin with a malformed body → 403 (checked before the body parser)", async () => {
  const { app, token } = await setup();
  for (const p of ["/mcp", "/mcp/"]) {
    const res = await request(app).post(p).set("Authorization", `Bearer ${token}`)
      .set("Origin", "https://evil.example").set("Content-Type", "application/json").send("{not json");
    assert.equal(res.status, 403, p);
    assert.equal(res.body.error, "forbidden_origin");
  }
});

// --- version check sits behind the login (claude.ai connector check) ----------------------

for (const v of ["2099-01-01", "2025-11-25"]) {
  test(`POST /mcp without token and MCP-Protocol-Version ${v} → 401 with resource_metadata`, async () => {
    const { app } = await setup();
    const res = await request(app).post("/mcp").set("MCP-Protocol-Version", v)
      .send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: v } });
    assert.equal(res.status, 401);
    assert.match(res.headers["www-authenticate"], /resource_metadata=/);
  });
}

test("authenticated initialize with unknown header and protocolVersion → 200, negotiated 2025-06-18", async () => {
  const { app, token } = await setup();
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .set("MCP-Protocol-Version", "2099-01-01")
    .send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2099-01-01" } });
  assert.equal(res.status, 200);
  assert.equal(res.body.result.protocolVersion, "2025-06-18");
});

test("authenticated initialize with protocolVersion 2025-11-25 → 200, 2025-11-25", async () => {
  const { app, token } = await setup();
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } });
  assert.equal(res.status, 200);
  assert.equal(res.body.result.protocolVersion, "2025-11-25");
});

test("authenticated tools/list with unsupported header → 400 unsupported_protocol_version", async () => {
  const { app, token } = await setup();
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .set("MCP-Protocol-Version", "2099-01-01").send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, "unsupported_protocol_version");
});

test("authenticated tools/list with 2025-11-25 header → 200", async () => {
  const { app, token } = await setup();
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .set("MCP-Protocol-Version", "2025-11-25").send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(res.status, 200);
});

// --- JSON-RPC envelope -------------------------------------------------------------------

for (const method of ["notifications/initialized", "notifications/cancelled", "notifications/progress", "tools/call", "unknown/thing"]) {
  test(`message without id (${method}) → 202 with empty body, nothing dispatched`, async () => {
    const { app, token, calls } = await setup();
    const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
      .send({ jsonrpc: "2.0", method, params: { name: "search_xwiki", arguments: { query: "x" } } });
    assert.equal(res.status, 202);
    assert.equal(res.text, "");
    assert.deepEqual(calls, []);
  });
}

test("batch (array body) → 400 JSON-RPC -32600 Invalid Request with id null", async () => {
  const { app, token, calls } = await setup();
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .send([{ jsonrpc: "2.0", id: 1, method: "tools/list" }, searchCall]);
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } });
  assert.deepEqual(calls, []);
});

test("bad Origin is rejected before the token check (no 401)", async () => {
  const { app } = await setup();
  const res = await request(app).post("/mcp").set("Origin", "https://evil.example").send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(res.status, 403);
});

// --- 405 ---------------------------------------------------------------------------------

for (const p of ["/mcp", "/mcp/"]) {
  for (const m of ["get", "delete"]) {
    test(`${m.toUpperCase()} ${p} → 405 with Allow: POST`, async () => {
      const { app } = await setup();
      const res = await request(app)[m](p);
      assert.equal(res.status, 405);
      assert.equal(res.headers.allow, "POST");
    });
  }
}

// --- XWikiAuthError (Review focus 5) -------------------------------------------------------

test("XWikiAuthError at the current version → 401, session ended, cleanup entry, tool called once", async () => {
  const { app, store, sid, token, calls } = await setup({
    search: () => { throw new XWikiAuthError("XWiki session expired"); },
  });
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`).send(searchCall);
  assert.equal(res.status, 401);
  assert.match(res.headers["www-authenticate"], /resource_metadata="[^"]+\/\.well-known\/oauth-protected-resource"/);
  assert.match(res.headers["www-authenticate"], /error="invalid_token"/);
  assert.deepEqual(calls, ["XW-TOKEN-1"]);
  const state = store.read();
  assert.equal(state.sessions[sid], undefined);
  const cleanups = Object.values(state.cleanups).filter((c) => c.reason === "xwiki-401");
  assert.equal(cleanups.length, 1);
  assert.equal(cleanups[0].xwikiUser, "xwiki:XWiki.alice");

  // Next call with the same token: 401 from the token check, the tool is not called again
  // and no further cleanup entry appears.
  const again = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`).send(searchCall);
  assert.equal(again.status, 401);
  assert.deepEqual(calls, ["XW-TOKEN-1"]);
  assert.equal(Object.values(store.read().cleanups).filter((c) => c.reason === "xwiki-401").length, 1);
});

test("XWikiAuthError at an outdated version → exactly one retry with the new token, 200", async () => {
  let storeRef, sidRef;
  const { app, store, sid, token, calls } = await setup({
    search: async (ctx, n) => {
      if (n === 1) {
        // A renewal happened while this request was in flight.
        await renew(storeRef, sidRef, 2, "XW-TOKEN-2");
        throw new XWikiAuthError("XWiki session expired");
      }
      return [];
    },
  });
  storeRef = store; sidRef = sid;
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`).send(searchCall);
  assert.equal(res.status, 200);
  assert.equal(res.body.id, 7);
  assert.ok(res.body.result);
  assert.deepEqual(calls, ["XW-TOKEN-1", "XW-TOKEN-2"]);
  assert.ok(store.read().sessions[sid], "session kept");
});

test("XWikiAuthError again on the retry → 401, session ended, no third call", async () => {
  let storeRef, sidRef;
  const { app, store, sid, token, calls } = await setup({
    search: async (ctx, n) => {
      if (n === 1) await renew(storeRef, sidRef, 2, "XW-TOKEN-2");
      throw new XWikiAuthError("XWiki session expired");
    },
  });
  storeRef = store; sidRef = sid;
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`).send(searchCall);
  assert.equal(res.status, 401);
  assert.deepEqual(calls, ["XW-TOKEN-1", "XW-TOKEN-2"]);
  assert.equal(store.read().sessions[sid], undefined);
  assert.equal(Object.values(store.read().cleanups).filter((c) => c.reason === "xwiki-401").length, 1);
});

test("retry raced by yet another renewal → 401 without ending the session, no third call", async () => {
  let storeRef, sidRef;
  const { app, store, sid, token, calls } = await setup({
    search: async (ctx, n) => {
      await renew(storeRef, sidRef, n + 1, `XW-TOKEN-${n + 1}`);
      throw new XWikiAuthError("XWiki session expired");
    },
  });
  storeRef = store; sidRef = sid;
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`).send(searchCall);
  assert.equal(res.status, 401);
  assert.deepEqual(calls, ["XW-TOKEN-1", "XW-TOKEN-2"]);
  assert.ok(store.read().sessions[sid], "session kept");
  assert.equal(Object.values(store.read().cleanups).filter((c) => c.reason === "xwiki-401").length, 0);
});

test("XWikiAuthError after the session was already ended elsewhere → 401, no crash", async () => {
  let storeRef, sidRef;
  const { app, store, sid, token, calls } = await setup({
    search: async () => {
      await storeRef.mutate((s) => { delete s.sessions[sidRef]; });
      throw new XWikiAuthError("XWiki session expired");
    },
  });
  storeRef = store; sidRef = sid;
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`).send(searchCall);
  assert.equal(res.status, 401);
  assert.match(res.headers["www-authenticate"], /resource_metadata=/);
  assert.equal(calls.length, 1);
  assert.equal(Object.values(store.read().cleanups).filter((c) => c.reason === "xwiki-401").length, 0);
});

// --- discovery and OAuth routes through the full app ---------------------------------------

for (const p of [
  "/.well-known/oauth-protected-resource",
  "/.well-known/oauth-protected-resource/mcp",
  "/mcp/.well-known/oauth-protected-resource",
]) {
  test(`createApp serves resource metadata at ${p}`, async () => {
    const { app } = await setup();
    const res = await request(app).get(p);
    assert.equal(res.status, 200);
    assert.equal(res.body.resource, BASE);
  });
}

for (const p of [
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-authorization-server/mcp",
  "/mcp/.well-known/oauth-authorization-server",
  "/.well-known/openid-configuration/mcp",
  "/mcp/.well-known/openid-configuration",
]) {
  test(`createApp serves AS metadata at ${p}`, async () => {
    const { app } = await setup();
    const res = await request(app).get(p);
    assert.equal(res.status, 200);
    assert.equal(res.body.issuer, BASE);
    assert.equal(res.body.token_endpoint, `${BASE}/oauth/token`);
  });
}

test("advertised /mcp/oauth/{authorize,token,register,revoke} routes exist", async () => {
  const { app } = await setup();
  const meta = (await request(app).get("/.well-known/oauth-authorization-server")).body;
  const routes = [
    ["get", meta.authorization_endpoint],
    ["post", meta.token_endpoint],
    ["post", meta.registration_endpoint],
    ["post", meta.revocation_endpoint],
  ];
  for (const [m, url] of routes) {
    const p = new URL(url).pathname;
    assert.ok(p.startsWith("/mcp/oauth/"), p);
    const res = m === "get" ? await request(app).get(p) : await request(app).post(p).type("form").send("");
    assert.notEqual(res.status, 404, `${m.toUpperCase()} ${p}`);
    assert.notEqual(res.status, 405, `${m.toUpperCase()} ${p}`);
  }
});

// --- auth before parser, Origin on every method ----------------------------------------------

test("no token + malformed JSON → 401 with resource_metadata (auth before the parser)", async () => {
  const { app } = await setup();
  for (const p of ["/mcp", "/mcp/"]) {
    const res = await request(app).post(p).set("Content-Type", "application/json").send("{not json");
    assert.equal(res.status, 401, p);
    assert.match(res.headers["www-authenticate"], /resource_metadata=/);
  }
});

test("valid token + malformed JSON → 400 invalid_request", async () => {
  const { app, token } = await setup();
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .set("Content-Type", "application/json").send("{not json");
  assert.equal(res.status, 400);
  assert.equal(res.body.error, "invalid_request");
});

for (const method of ["get", "delete"]) {
  for (const p of ["/mcp", "/mcp/"]) {
    test(`${method.toUpperCase()} ${p} with a bad Origin → 403, without Origin → 405 Allow: POST`, async () => {
      const { app } = await setup();
      const bad = await request(app)[method](p).set("Origin", "https://evil.example");
      assert.equal(bad.status, 403);
      assert.equal(bad.body.error, "forbidden_origin");
      const ok = await request(app)[method](p);
      assert.equal(ok.status, 405);
      assert.equal(ok.headers.allow, "POST");
    });
  }
}

// --- non-canonical /mcp paths are not served --------------------------------------------------

for (const p of ["/mcp//", "/MCP", "/Mcp/", "//mcp", "/mcp//oauth/token", "/MCP/oauth/authorize"]) {
  test(`non-canonical ${p} → 404 not_found, whatever Origin/token/body`, async () => {
    const { app, token } = await setup();
    const plain = await request(app).post(p).set("Content-Type", "application/json").send("{not json");
    assert.equal(plain.status, 404);
    assert.equal(plain.body.error, "not_found");
    const evil = await request(app).post(p).set("Origin", "https://evil.example").send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(evil.status, 404);
    const authed = await request(app).post(p).set("Authorization", `Bearer ${token}`).send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(authed.status, 404);
    assert.equal((await request(app).get(p)).status, 404);
  });
}

test("canonical /mcp paths still work", async () => {
  const { app, token } = await setup();
  for (const p of ["/mcp", "/mcp/"]) {
    const r = await request(app).post(p).set("Authorization", `Bearer ${token}`).send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(r.status, 200, p);
  }
  assert.equal((await request(app).get("/mcp/health")).status, 200);
  assert.equal((await request(app).get("/mcp/.well-known/oauth-protected-resource")).status, 200);
});

for (const method of ["head", "options"]) {
  test(`${method.toUpperCase()} /mcp with a foreign Origin → 403`, async () => {
    const { app } = await setup();
    const res = await request(app)[method]("/mcp").set("Origin", "https://evil.example");
    assert.equal(res.status, 403);
  });
}
