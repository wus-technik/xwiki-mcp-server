import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { callTool, TOOLS } from "../src/tools.js";
import { XWikiAuthError } from "../src/xwiki-client.js";

const SESSION = { userId: "alice", xwikiCookie: "XWIKI_SESSION=abc" };

function makeClient(overrides = {}) {
  return {
    search: mock.fn(async () => [{ title: "Page A", space: "Main", url: "https://xwiki.example.com/bin/view/Main/PageA" }]),
    getPage: mock.fn(async () => ({ title: "Page A", content: "Hello", author: "alice", modified: "2024-01-01" })),
    createPage: mock.fn(async () => "https://xwiki.example.com/bin/view/Main/PageA"),
    ...overrides,
  };
}

test("TOOLS exports array with 3 tool definitions", () => {
  assert.equal(TOOLS.length, 3);
  assert.ok(TOOLS.every((t) => t.name && t.description && t.inputSchema));
});

test("callTool search_xwiki calls client.search and returns JSON", async () => {
  const client = makeClient();
  const result = await callTool("search_xwiki", { query: "home" }, SESSION, client);
  assert.equal(client.search.mock.calls.length, 1);
  assert.equal(client.search.mock.calls[0].arguments[0], "home");
  assert.equal(client.search.mock.calls[0].arguments[2], SESSION);
  const parsed = JSON.parse(result);
  assert.equal(parsed[0].title, "Page A");
});

test("callTool get_xwiki_page calls client.getPage", async () => {
  const client = makeClient();
  const result = await callTool("get_xwiki_page", { page_path: "Main.WebHome" }, SESSION, client);
  assert.equal(client.getPage.mock.calls[0].arguments[0], "Main.WebHome");
  assert.equal(client.getPage.mock.calls[0].arguments[1], SESSION);
  const parsed = JSON.parse(result);
  assert.equal(parsed.title, "Page A");
});

test("callTool create_xwiki_page calls client.createPage", async () => {
  const client = makeClient();
  await callTool("create_xwiki_page", { page_path: "Main.New", title: "New", content: "body" }, SESSION, client);
  assert.equal(client.createPage.mock.calls[0].arguments[0], "Main.New");
  assert.equal(client.createPage.mock.calls[0].arguments[3], SESSION);
});

test("callTool re-throws XWikiAuthError (does not catch it as string)", async () => {
  const client = makeClient({
    search: mock.fn(async () => { throw new XWikiAuthError("XWiki session expired"); }),
  });
  await assert.rejects(
    () => callTool("search_xwiki", { query: "test" }, SESSION, client),
    XWikiAuthError
  );
});

test("callTool returns error string for non-auth errors", async () => {
  const client = makeClient({
    search: mock.fn(async () => { throw new Error("network timeout"); }),
  });
  const result = await callTool("search_xwiki", { query: "test" }, SESSION, client);
  assert.ok(result.startsWith("Error:"));
  assert.ok(result.includes("network timeout"));
});

test("callTool unknown tool returns error string", async () => {
  const client = makeClient();
  const result = await callTool("unknown_tool", {}, SESSION, client);
  assert.ok(result.includes("Unknown tool"));
});
