// AUTH_DEBUG logger: request path without query string (it may carry access_token or code).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createAuthDebugLogger } from "../src/auth-debug.js";

function capture(fn) {
  const lines = [];
  const orig = { info: console.info, warn: console.warn };
  console.info = (...a) => lines.push(a.join(" "));
  console.warn = (...a) => lines.push(a.join(" "));
  try { fn(); } finally { Object.assign(console, orig); }
  return lines;
}

test("debug log contains the path but not the query string", () => {
  const logger = createAuthDebugLogger(true);
  const req = {
    method: "GET",
    originalUrl: "/mcp/oauth/authorize?access_token=SECRET-AT&code=SECRET-CODE",
    url: "/oauth/authorize?access_token=SECRET-AT&code=SECRET-CODE",
    headers: { "user-agent": "ua" },
  };
  const lines = capture(() => {
    logger.info("evt", req, { sid: "abcdefgh" });
    logger.warn("evt2", req);
  });
  assert.equal(lines.length, 2);
  for (const l of lines) {
    assert.ok(l.includes('"path":"/mcp/oauth/authorize"'), l);
    assert.ok(!l.includes("SECRET"), l);
    assert.ok(!l.includes("?"), l);
  }
});

test("disabled logger writes nothing", () => {
  const lines = capture(() => createAuthDebugLogger(false).info("evt", { originalUrl: "/x?y=1", headers: {} }));
  assert.deepEqual(lines, []);
});
