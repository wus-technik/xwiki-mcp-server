import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import request from "supertest";
import express from "express";
import { createUploadRouter } from "../src/upload-route.js";
import { mintUploadToken } from "../src/upload-token.js";
import { createSession, deleteSession } from "../src/session-store.js";
import { XWikiAuthError } from "../src/xwiki-client.js";

const SECRET = "test-secret-32-chars-minimum-pad";

function expiredTokenFor(sessionId) {
  const payload = {
    sid: sessionId, pagePath: "Main.WebHome", filename: "f.bin",
    contentType: "application/octet-stream", exp: Date.now() - 1000, nonce: "expired-nonce",
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
  return `${payloadB64}.${sig}`;
}

function makeApp({ xwikiClient, maxBytes } = {}) {
  const app = express();
  const client = xwikiClient || { putAttachmentBytes: mock.fn(async () => "https://xwiki.example.com/bin/download/Main/WebHome/f.bin") };
  app.use(createUploadRouter({ sessionSecret: SECRET, xwikiClient: client, maxBytes }));
  return { app, client };
}

test("PUT /uploads/:token accepts a valid token and forwards bytes to putAttachmentBytes", async () => {
  const sessionId = createSession("alice", "XWIKI_SESSION=abc");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", contentType: "text/plain", secret: SECRET });
  const { app, client } = makeApp();

  const res = await request(app).put(`/uploads/${token}`).set("Content-Type", "application/octet-stream").send(Buffer.from("hello"));

  assert.equal(res.status, 201);
  assert.equal(res.text, "https://xwiki.example.com/bin/download/Main/WebHome/f.bin");
  assert.equal(client.putAttachmentBytes.mock.calls.length, 1);
  const call = client.putAttachmentBytes.mock.calls[0].arguments;
  assert.equal(call[0], "Main.WebHome");
  assert.equal(call[1], "f.bin");
  assert.ok(Buffer.from(call[2]).equals(Buffer.from("hello")));
  assert.equal(call[3], "text/plain");
  assert.equal(call[4].xwikiCookie, "XWIKI_SESSION=abc");
});

test("PUT /uploads/:token rejects an expired token", async () => {
  const sessionId = createSession("bob", "XWIKI_SESSION=abc");
  const expiredToken = expiredTokenFor(sessionId);
  const { app } = makeApp();
  const res = await request(app).put(`/uploads/${expiredToken}`).set("Content-Type", "application/octet-stream").send(Buffer.from("hello"));
  assert.equal(res.status, 401);
});

test("PUT /uploads/:token rejects a tampered/invalid-signature token", async () => {
  const sessionId = createSession("carol", "XWIKI_SESSION=abc");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const tampered = `${token.slice(0, -2)}xx`;
  const { app } = makeApp();
  const res = await request(app).put(`/uploads/${tampered}`).set("Content-Type", "application/octet-stream").send(Buffer.from("hello"));
  assert.equal(res.status, 401);
});

test("PUT /uploads/:token rejects a reused (already-consumed) token", async () => {
  const sessionId = createSession("dan", "XWIKI_SESSION=abc");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const { app } = makeApp();

  const first = await request(app).put(`/uploads/${token}`).set("Content-Type", "application/octet-stream").send(Buffer.from("hello"));
  assert.equal(first.status, 201);

  const second = await request(app).put(`/uploads/${token}`).set("Content-Type", "application/octet-stream").send(Buffer.from("hello again"));
  assert.equal(second.status, 409);
});

test("PUT /uploads/:token rejects an oversized body", async () => {
  const sessionId = createSession("erin", "XWIKI_SESSION=abc");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const { app, client } = makeApp({ maxBytes: 4 });

  const res = await request(app).put(`/uploads/${token}`).set("Content-Type", "application/octet-stream").send(Buffer.from("too many bytes"));
  assert.equal(res.status, 413);
  assert.equal(client.putAttachmentBytes.mock.calls.length, 0);
});

test("PUT /uploads/:token rejects a token whose session no longer exists", async () => {
  const sessionId = createSession("frank", "XWIKI_SESSION=abc");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  deleteSession(sessionId);
  const { app } = makeApp();

  const res = await request(app).put(`/uploads/${token}`).set("Content-Type", "application/octet-stream").send(Buffer.from("hello"));
  assert.equal(res.status, 401);
});

test("PUT /uploads/:token returns 401 and does not consume the token when XWiki write fails with auth error", async () => {
  const sessionId = createSession("grace", "XWIKI_SESSION=abc");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const client = { putAttachmentBytes: mock.fn(async () => { throw new XWikiAuthError("expired"); }) };
  const { app } = makeApp({ xwikiClient: client });

  const res = await request(app).put(`/uploads/${token}`).set("Content-Type", "application/octet-stream").send(Buffer.from("hello"));
  assert.equal(res.status, 401);
});

test("PUT /uploads/:token returns 502 on a generic XWiki write failure", async () => {
  const sessionId = createSession("henry", "XWIKI_SESSION=abc");
  const { token } = mintUploadToken({ sessionId, pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET });
  const client = { putAttachmentBytes: mock.fn(async () => { throw new Error("boom"); }) };
  const { app } = makeApp({ xwikiClient: client });

  const res = await request(app).put(`/uploads/${token}`).set("Content-Type", "application/octet-stream").send(Buffer.from("hello"));
  assert.equal(res.status, 502);
});
