import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import express from "express";
import { createSseRouter } from "../src/sse-handler.js";
import { createSession } from "../src/session-store.js";
import { SignJWT } from "jose";

const SECRET = "test-secret-32-chars-minimum-pad";
const jwtSecret = new TextEncoder().encode(SECRET);

async function makeToken(userId, xwikiCookie) {
  const sessionId = createSession(userId, xwikiCookie);
  return new SignJWT({ sub: userId, sid: sessionId })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("1h")
    .setIssuedAt()
    .sign(jwtSecret);
}

function makeSseApp(overrides = {}) {
  const app = express();
  app.use(express.json());
  const router = createSseRouter({
    sessionSecret: SECRET,
    xwikiClient: {
      search: async () => [],
      getPage: async () => ({ title: "", content: "", author: "", modified: "" }),
      createPage: async () => "",
    },
    ...overrides,
  });
  app.use(router);
  return app;
}

test("GET /sse without auth returns 401", async () => {
  const app = makeSseApp();
  const res = await request(app).get("/sse");
  assert.equal(res.status, 401);
});

test("POST /messages with unknown sessionId returns 400", async () => {
  const app = makeSseApp();
  const res = await request(app)
    .post("/messages?sessionId=nonexistent")
    .send({ jsonrpc: "2.0", method: "initialize", id: 1 });
  assert.equal(res.status, 400);
});
