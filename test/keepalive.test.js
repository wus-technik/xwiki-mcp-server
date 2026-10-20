import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { configureSessionPersistence, createSession } from "../src/session-store.js";
import { runKeepAlive } from "../src/keepalive.js";

test("runKeepAlive touches every live XWiki session with its own cookie", async () => {
  configureSessionPersistence(null, { reset: true });
  createSession("alice", "JSESSIONID=a1");
  createSession("bob", "JSESSIONID=b1");
  const xwikiClient = { touchSession: mock.fn(async () => 200) };

  await runKeepAlive({ xwikiClient });

  const cookies = xwikiClient.touchSession.mock.calls.map((c) => c.arguments[0].xwikiCookie).sort();
  assert.deepEqual(cookies, ["JSESSIONID=a1", "JSESSIONID=b1"]);
});

test("runKeepAlive keeps going when one session's touch fails", async () => {
  configureSessionPersistence(null, { reset: true });
  createSession("alice", "JSESSIONID=a1");
  createSession("bob", "JSESSIONID=b1");
  let n = 0;
  const xwikiClient = { touchSession: mock.fn(async () => { if (n++ === 0) throw new Error("boom"); return 200; }) };

  await runKeepAlive({ xwikiClient });

  assert.equal(xwikiClient.touchSession.mock.callCount(), 2);
});
