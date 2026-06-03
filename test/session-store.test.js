import { test } from "node:test";
import assert from "node:assert/strict";
import {
  storeAuthState, consumeAuthState,
  storeAuthCode, consumeAuthCode,
  createSession, getSession, deleteSession,
} from "../src/session-store.js";

test("consumeAuthState returns data and removes it", () => {
  storeAuthState("state1", { redirect_uri: "http://client/cb", code_challenge: "abc" });
  const data = consumeAuthState("state1");
  assert.equal(data.redirect_uri, "http://client/cb");
  assert.equal(consumeAuthState("state1"), undefined);
});

test("consumeAuthCode returns data once then null", () => {
  const code = "code1";
  storeAuthCode(code, "sess1", "challenge1");
  const data = consumeAuthCode(code);
  assert.equal(data.sessionId, "sess1");
  assert.equal(data.codeChallenge, "challenge1");
  assert.equal(consumeAuthCode(code), null);
});

test("createSession and getSession round-trip", () => {
  const id = createSession("user1", "XWIKI_SESSION=abc");
  const session = getSession(id);
  assert.equal(session.userId, "user1");
  assert.equal(session.xwikiCookie, "XWIKI_SESSION=abc");
});

test("deleteSession removes the session", () => {
  const id = createSession("user2", "cookie");
  deleteSession(id);
  assert.equal(getSession(id), null);
});

test("getSession returns null for unknown id", () => {
  assert.equal(getSession("nonexistent"), null);
});
