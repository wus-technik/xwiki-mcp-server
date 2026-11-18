import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApp } from "../src/app.js";
import { openStore } from "../src/store.js";

const KEY = Buffer.alloc(32, 7);
const mk = (storeOverride) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "reg-"));
  const store = storeOverride ?? openStore({ file: path.join(dir, "s.json"), key: KEY });
  const app = createApp({ sessionSecret: "test-secret-32-chars-minimum-pad", store, extraRedirectUris: [] });
  return { app, store };
};

for (const url of ["/register", "/mcp/oauth/register"]) {
  test(`POST ${url} stores client and answers 201`, async () => {
    const { app, store } = mk();
    const res = await request(app).post(url).send({
      client_name: "Test", redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], evil: "x",
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.client_name, "Test");
    assert.deepEqual(res.body.redirect_uris, ["https://claude.ai/api/mcp/auth_callback"]);
    assert.equal(res.body.token_endpoint_auth_method, "none");
    assert.deepEqual(res.body.grant_types, ["authorization_code", "refresh_token"]);
    assert.deepEqual(res.body.response_types, ["code"]);
    assert.equal(typeof res.body.client_id_issued_at, "number");
    assert.equal(res.body.evil, undefined);
    const c = store.read().clients[res.body.client_id];
    assert.equal(c.clientName, "Test");
    assert.deepEqual(c.redirectUris, ["https://claude.ai/api/mcp/auth_callback"]);
  });

  test(`POST ${url} rejects disallowed redirect`, async () => {
    const { app, store } = mk();
    const res = await request(app).post(url).send({ redirect_uris: ["https://evil.example/cb"] });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: "invalid_redirect_uri" });
    assert.deepEqual(store.read().clients, {});
  });
}

test("bad redirect_uris give invalid_redirect_uri", async () => {
  const { app } = mk();
  const many = Array.from({ length: 21 }, (_, i) => `http://localhost:${i + 1}/a`);
  for (const body of [{}, { redirect_uris: "x" }, { redirect_uris: [] }, { redirect_uris: [1] }, { redirect_uris: many }]) {
    const res = await request(app).post("/register").send(body);
    assert.equal(res.status, 400, JSON.stringify(body).slice(0, 40));
    assert.deepEqual(res.body, { error: "invalid_redirect_uri" });
  }
});

test("invalid redirect wins over bad client_name", async () => {
  const { app } = mk();
  const res = await request(app).post("/register").send({ redirect_uris: ["https://evil.example/cb"], client_name: 5 });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "invalid_redirect_uri" });
});

test("bad client_name type gives invalid_client_metadata", async () => {
  const { app } = mk();
  const res = await request(app).post("/register").send({ redirect_uris: ["http://localhost:1/a"], client_name: 5 });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, "invalid_client_metadata");
});

for (const url of ["/register", "/mcp/oauth/register"]) {
  test(`malformed JSON on ${url} gives JSON 400`, async () => {
    const { app } = mk();
    const res = await request(app).post(url).set("Content-Type", "application/json").send("{");
    assert.equal(res.status, 400);
    assert.match(res.headers["content-type"], /json/);
    assert.equal(res.body.error, "invalid_client_metadata");
  });
}

test("malformed JSON elsewhere gives invalid_request", async () => {
  const { app } = mk();
  const res = await request(app).post("/token").set("Content-Type", "application/json").send("{");
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "invalid_request" });
});

test("201 is sent only after the write resolved", async () => {
  const { store } = mk();
  let release, signalEntered;
  const gate = new Promise((r) => { release = r; });
  const entered = new Promise((r) => { signalEntered = r; });
  const slow = { ...store, mutate: async (fn) => { signalEntered(); await gate; return store.mutate(fn); } };
  const { app } = mk(slow);
  let done = false;
  const p = request(app).post("/register").send({ redirect_uris: ["http://localhost:1/a"] }).then((r) => { done = true; return r; });
  await entered;
  await new Promise((r) => setImmediate(r));
  assert.equal(done, false);
  release();
  const res = await p;
  assert.equal(res.status, 201);
  assert.ok(store.read().clients[res.body.client_id]);
});

test("missing store gives 500, no client_id", async () => {
  const app = createApp({ sessionSecret: "test-secret-32-chars-minimum-pad", extraRedirectUris: [] });
  const res = await request(app).post("/register").send({ redirect_uris: ["http://localhost:1/a"] });
  assert.equal(res.status, 500);
  assert.equal(res.body.client_id, undefined);
});

test("long client_name is truncated, default name applied", async () => {
  const { app } = mk();
  const a = await request(app).post("/register").send({ client_name: "x".repeat(500), redirect_uris: ["http://localhost:1/a"] });
  assert.equal(a.body.client_name.length, 200);
  const b = await request(app).post("/register").send({ redirect_uris: ["http://localhost:1/a"] });
  assert.equal(b.body.client_name, "unbenannter Client");
});

test("mutate failure gives 500 without client_id", async () => {
  const { store } = mk();
  const failing = { ...store, mutate: async () => { throw new Error("disk full"); } };
  const { app } = mk(failing);
  const res = await request(app).post("/register").send({ redirect_uris: ["http://localhost:1/a"] });
  assert.equal(res.status, 500);
  assert.equal(res.body.client_id, undefined);
  assert.equal(res.body.error, "server_error");
});

test("DCR accepts the ChatGPT connector/oauth/{id} redirect URI", async () => {
  const { app } = mk();
  const uri = "https://chatgpt.com/connector/oauth/abc_DEF-123";
  const res = await request(app).post("/register").send({ client_name: "ChatGPT", redirect_uris: [uri] });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  assert.deepEqual(res.body.redirect_uris, [uri]);
});

for (const uri of [
  "https://chatgpt.com/connector/oauth/",
  "https://chatgpt.com/connector/oauth",
  "https://chatgpt.com/connector/oauth/a/b",
  "https://chatgpt.com.evil.example/connector/oauth/x",
  "https://chatgpt.com:8443/connector/oauth/x",
  "https://chatgpt.com/connector/oauth/x?a=1",
  "https://chatgpt.com/connector/oauth/x#f",
  "http://chatgpt.com/connector/oauth/x",
  "https://chatgpt.com/connector/oauth/x%2Fy",
]) {
  test(`DCR rejects ${uri}`, async () => {
    const { app } = mk();
    const res = await request(app).post("/register").send({ redirect_uris: [uri] });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, "invalid_redirect_uri");
  });
}
