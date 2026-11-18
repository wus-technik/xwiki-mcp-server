import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import request from "supertest";
import express from "express";
import { createUploadRouter } from "../src/upload-route.js";
import { mintUploadToken } from "../src/upload-token.js";
import { openStore } from "../src/store.js";
import { createSession } from "../src/sessions.js";
import { createXWikiClient, XWikiAuthError } from "../src/xwiki-client.js";

const SECRET = "test-secret-32-chars-minimum-pad";
const KEY = Buffer.alloc(32, 7);
const BEARER = "zurmano/1/secret1";

function tmpFile() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "upload-")), "s.json");
}

function newStore(file = tmpFile()) {
  return { store: openStore({ file, key: KEY }), file };
}

async function newSession(store, user = "alice") {
  const { sid } = await createSession({ store, now: Date.now }, {
    sub: user, userId: user, xwikiUser: `xwiki:XWiki.${user}`, clientId: "c1",
    authentikRefresh: "rt", xwikiToken: BEARER, consentId: "x", tokenExpiresAt: Date.now() + 1e7,
  });
  return sid;
}

function expiredTokenFor(sessionId) {
  const payload = {
    sid: sessionId, pagePath: "Main.WebHome", filename: "f.bin",
    contentType: "application/octet-stream", exp: Date.now() - 1000, nonce: "expired-nonce",
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
  return `${payloadB64}.${sig}`;
}

function makeApp({ store, xwikiClient, maxBytes } = {}) {
  const app = express();
  const client = xwikiClient || { putAttachmentBytes: mock.fn(async () => "https://xwiki.example.com/bin/download/Main/WebHome/f.bin") };
  app.use(createUploadRouter({ sessionSecret: SECRET, xwikiClient: client, store, maxBytes }));
  return { app, client };
}

const put = (app, token, body = "hello") =>
  request(app).put(`/uploads/${token}`).set("Content-Type", "application/octet-stream").send(Buffer.from(body));

test("PUT /uploads/:token accepts a valid token and forwards bytes with the session's bearer ctx", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store);
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", contentType: "text/plain", secret: SECRET });
  const { app, client } = makeApp({ store });

  const res = await put(app, token);

  assert.equal(res.status, 201);
  assert.equal(res.text, "https://xwiki.example.com/bin/download/Main/WebHome/f.bin");
  assert.equal(client.putAttachmentBytes.mock.calls.length, 1);
  const call = client.putAttachmentBytes.mock.calls[0].arguments;
  assert.equal(call[0], "Main.WebHome");
  assert.equal(call[1], "f.bin");
  assert.ok(Buffer.from(call[2]).equals(Buffer.from("hello")));
  assert.equal(call[3], "text/plain");
  assert.deepEqual(call[4], {
    sessionId, userId: "alice", xwikiUser: "xwiki:XWiki.alice", xwikiToken: BEARER, tokenVersion: 1,
  });
});

test("the XWiki request carries Authorization: Bearer (real client, stubbed fetcher)", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store);
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const seen = [];
  const fetcher = async (url, opts = {}) => {
    seen.push({ url: String(url), headers: opts.headers || {} });
    return {
      status: 200, ok: true, headers: new Map([["XWiki-Form-Token", "ft"]]),
      json: async () => ({}), text: async () => "",
    };
  };
  const xwikiClient = createXWikiClient({ baseUrl: "https://xwiki.example.com", wiki: "xwiki", fetcher });
  const { app } = makeApp({ store, xwikiClient });

  const res = await put(app, token);
  assert.equal(res.status, 201);
  assert.ok(seen.length >= 2);
  for (const r of seen) {
    assert.equal(r.headers.Authorization, `Bearer ${BEARER}`);
    assert.equal(r.headers.Cookie, undefined);
  }
});

test("two parallel PUTs with the same URL: exactly one 201, the other 409", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store);
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const { app, client } = makeApp({ store });

  const [a, b] = await Promise.all([put(app, token), put(app, token, "second")]);

  assert.deepEqual([a.status, b.status].sort(), [201, 409]);
  assert.equal(client.putAttachmentBytes.mock.calls.length, 1);
});

test("a new store on the same file (restart) still rejects the used URL with 409", async () => {
  const { store, file } = newStore();
  const sessionId = await newSession(store);
  const { token, payload } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  assert.equal((await put(makeApp({ store }).app, token)).status, 201);

  const reopened = openStore({ file, key: KEY });
  assert.equal(reopened.read().uploadNonces[payload.nonce], payload.exp);
  const { app, client } = makeApp({ store: reopened });
  const res = await put(app, token);
  assert.equal(res.status, 409);
  assert.equal(client.putAttachmentBytes.mock.calls.length, 0);
});

test("PUT /uploads/:token rejects an expired token", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store, "bob");
  const { app } = makeApp({ store });
  assert.equal((await put(app, expiredTokenFor(sessionId))).status, 401);
});

test("PUT /uploads/:token rejects a tampered/invalid-signature token", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store, "carol");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const { app } = makeApp({ store });
  assert.equal((await put(app, `${token.slice(0, -2)}xx`)).status, 401);
});

test("PUT /uploads/:token rejects an oversized body (nonce stays consumed)", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store, "erin");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const { app, client } = makeApp({ store, maxBytes: 4 });

  const res = await put(app, token, "too many bytes");
  assert.equal(res.status, 413);
  assert.equal(client.putAttachmentBytes.mock.calls.length, 0);
  assert.equal((await put(app, token, "ok")).status, 409);
});

test("PUT /uploads/:token rejects a token whose session no longer exists", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store, "frank");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  await store.mutate((s) => { delete s.sessions[sessionId]; });
  const { app, client } = makeApp({ store });

  assert.equal((await put(app, token)).status, 401);
  assert.equal(client.putAttachmentBytes.mock.calls.length, 0);
});

test("XWiki auth error gives 401, keeps the session and leaves the nonce consumed", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store, "grace");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const client = { putAttachmentBytes: mock.fn(async () => { throw new XWikiAuthError("expired"); }) };
  const { app } = makeApp({ store, xwikiClient: client });

  const res = await put(app, token);
  assert.equal(res.status, 401);
  assert.ok(store.read().sessions[sessionId]);
  assert.equal((await put(app, token)).status, 409);
});

test("PUT /uploads/:token returns 502 on a generic XWiki write failure", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store, "henry");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const client = { putAttachmentBytes: mock.fn(async () => { throw new Error("boom"); }) };
  const { app } = makeApp({ store, xwikiClient: client });
  assert.equal((await put(app, token)).status, 502);
});

test("a failing store write during reservation gives 503 and uploads nothing", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store, "ida");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const broken = { ...store, mutate: async () => { throw new Error("disk full"); } };
  const { app, client } = makeApp({ store: broken });

  const res = await put(app, token);
  assert.equal(res.status, 503);
  assert.equal(res.type, "text/plain");
  assert.equal(client.putAttachmentBytes.mock.calls.length, 0);
});

test("502 and 413 bodies are fixed texts; an upstream error message with a secret never leaks", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store, "jack");
  const mint = () => mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET }).token;
  const SENTINEL = "SENTINEL-BEARER-xyz";
  const client = { putAttachmentBytes: mock.fn(async () => { throw new Error(`bad header Bearer ${SENTINEL}`); }) };
  const r502 = await put(makeApp({ store, xwikiClient: client }).app, mint());
  assert.equal(r502.status, 502);
  assert.equal(r502.text, "Upload to XWiki failed");
  assert.ok(!r502.text.includes(SENTINEL));
  const r413 = await put(makeApp({ store, maxBytes: 4 }).app, mint(), "too many bytes");
  assert.equal(r413.status, 413);
  assert.equal(r413.text, "Upload too large or unreadable");
});

test("at now == exp the token is rejected; a present nonce counts as used even when expired", async () => {
  const { store } = newStore();
  const sessionId = await newSession(store, "kim");
  const { token, payload } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const { app } = makeApp({ store });
  await store.mutate((s) => { s.uploadNonces[payload.nonce] = 1; }); // expired entry, not yet pruned
  assert.equal((await put(app, token)).status, 409);

  const { token: t2, payload: p2 } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const realNow = Date.now;
  Date.now = () => p2.exp;
  try {
    assert.equal((await put(app, t2)).status, 401);
  } finally {
    Date.now = realNow;
  }
});

test("app level: PUT with Content-Type application/json and a >100 KB body is not eaten by the global parsers", async () => {
  const { createApp } = await import("../src/app.js");
  const { store } = newStore();
  const sessionId = await newSession(store, "lena");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const xwikiClient = { putAttachmentBytes: mock.fn(async () => "https://x/f.bin") };
  const app = createApp({
    sessionSecret: SECRET, mcpBaseUrl: "https://xwiki.example.com/mcp", store, xwikiClient,
    xwikiTokens: {}, authentik: {}, authDebug: false, extraOrigins: [], extraRedirectUris: [],
  });
  const big = Buffer.alloc(200 * 1024, 97).toString();
  const res = await request(app).put(`/mcp/uploads/${token}`).set("Content-Type", "application/json").send(big);
  assert.equal(res.status, 201);
  assert.equal(xwikiClient.putAttachmentBytes.mock.calls[0].arguments[2].length, big.length);
});
