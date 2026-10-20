import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  configureSessionPersistence, createSession, getSession, deleteSession, listSessions,
} from "../src/session-store.js";

function tmpFile() {
  return join(mkdtempSync(join(tmpdir(), "xwiki-mcp-")), "sessions.json");
}

test("sessions survive a reload from the persistence file", () => {
  const file = tmpFile();
  configureSessionPersistence(file);
  const id = createSession("alice", "JSESSIONID=a1");
  assert.ok(existsSync(file));

  // Simulate a fresh process: drop memory state, then load from disk.
  configureSessionPersistence(file, { reset: true });
  const s = getSession(id);
  assert.equal(s.userId, "alice");
  assert.equal(s.xwikiCookie, "JSESSIONID=a1");
});

test("deleteSession is written through to the file", () => {
  const file = tmpFile();
  configureSessionPersistence(file);
  const id = createSession("bob", "JSESSIONID=b1");
  deleteSession(id);
  configureSessionPersistence(file, { reset: true });
  assert.equal(getSession(id), null);
});

test("expired sessions are dropped on load", () => {
  const file = tmpFile();
  writeFileSync(file, JSON.stringify({
    old: { userId: "carol", xwikiCookie: "c", expiresAt: Date.now() - 1000 },
    live: { userId: "dave", xwikiCookie: "d", expiresAt: Date.now() + 60_000 },
  }));
  configureSessionPersistence(file, { reset: true });
  assert.equal(getSession("old"), null);
  assert.equal(getSession("live").userId, "dave");
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(file, "utf8"))), ["live"]);
});

test("a corrupt persistence file starts with an empty store instead of crashing", () => {
  const file = tmpFile();
  writeFileSync(file, "{not json");
  configureSessionPersistence(file, { reset: true });
  assert.deepEqual(listSessions(), []);
});

test("listSessions returns only live sessions with their ids", () => {
  configureSessionPersistence(null, { reset: true });
  const id = createSession("erin", "JSESSIONID=e1");
  const all = listSessions();
  assert.equal(all.length, 1);
  assert.equal(all[0].sessionId, id);
  assert.equal(all[0].xwikiCookie, "JSESSIONID=e1");
});
