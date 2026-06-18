import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { createXWikiClient, XWikiAuthError } from "../src/xwiki-client.js";

const BASE_URL = "https://xwiki.example.com";
const COOKIE = "XWIKI_SESSION=test123";
const WIKI = "xwiki";

function mockFetch(status, body, headers = {}) {
  return mock.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[k] ?? null },
    json: async () => body,
    text: async () => JSON.stringify(body),
  }));
}

test("search sends Cookie header and returns mapped results", async () => {
  const fetcher = mockFetch(200, {
    searchResults: [{ title: "Home", pageName: "WebHome", space: "Main", pageFullName: "Main.WebHome" }]
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const results = await client.search("home", 5, { xwikiCookie: COOKIE });
  const call = fetcher.mock.calls[0];
  assert.ok(call.arguments[1].headers.Cookie.includes("XWIKI_SESSION=test123"));
  assert.equal(results[0].title, "Home");
});

test("getPage returns page fields", async () => {
  const fetcher = mockFetch(200, { title: "Home", content: "Hello", author: "alice", modified: "2024-01-01" });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const page = await client.getPage("Main.WebHome", { xwikiCookie: COOKIE });
  assert.equal(page.title, "Home");
  assert.equal(page.content, "Hello");
  assert.equal(page.totalContentLength, 5);
  assert.equal(page.contentTruncated, false);
});

test("getPage can return a section by heading", async () => {
  const content = [
    "= Intro =",
    "hello",
    "",
    "== Details ==",
    "alpha",
    "",
    "== Details ==",
    "beta",
    "",
    "= End =",
    "bye",
  ].join("\n");
  const fetcher = mockFetch(200, { title: "Home", content, author: "alice", modified: "2024-01-01" });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const page = await client.getPage("Main.WebHome", { heading: "Details", headingOccurrence: 2 }, { xwikiCookie: COOKIE });
  assert.equal(page.headingMatched, "Details");
  assert.equal(page.headingOccurrence, 2);
  assert.equal(page.headingLevel, 2);
  assert.equal(page.content, "== Details ==\nbeta");
  assert.equal(page.contentTruncated, true);
  assert.equal(page.totalContentLength, 18);
  assert.equal(page.sourceContentLength, content.length);
});

test("getPage can slice content after heading extraction", async () => {
  const content = [
    "= Intro =",
    "hello",
    "",
    "== Details ==",
    "alphabet",
    "",
    "= End =",
    "bye",
  ].join("\n");
  const fetcher = mockFetch(200, { title: "Home", content, author: "alice", modified: "2024-01-01" });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const page = await client.getPage(
    "Main.WebHome",
    { heading: "Details", contentOffset: 3, contentLength: 7 },
    { xwikiCookie: COOKIE },
  );
  assert.equal(page.content, "Details");
  assert.equal(page.contentOffset, 3);
  assert.equal(page.contentLength, 7);
  assert.equal(page.totalContentLength, 22);
  assert.equal(page.sourceContentLength, content.length);
  assert.equal(page.contentTruncated, true);
});

test("getPage can omit content while keeping metadata", async () => {
  const fetcher = mockFetch(200, { title: "Home", content: "Hello", author: "alice", modified: "2024-01-01" });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const page = await client.getPage("Main.WebHome", { includeContent: false }, { xwikiCookie: COOKIE });
  assert.equal(page.content, undefined);
  assert.equal(page.contentLength, 0);
  assert.equal(page.totalContentLength, 5);
  assert.equal(page.contentTruncated, true);
});

test("getPage throws when requested heading is missing", async () => {
  const fetcher = mockFetch(200, { title: "Home", content: "= Intro =\nHello", author: "alice", modified: "2024-01-01" });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.getPage("Main.WebHome", { heading: "Missing" }, { xwikiCookie: COOKIE }),
    /Heading not found: Missing/
  );
});

test("createPage fetches form token before PUT", async () => {
  const calls = [];
  const fetcher = mock.fn(async (url, opts) => {
    calls.push({ url, method: opts?.method || "GET" });
    if (opts?.method === "PUT") {
      return { ok: true, status: 201, headers: { get: () => null }, text: async () => "" };
    }
    // GET for form token
    return {
      ok: true, status: 200,
      headers: { get: (k) => k === "XWiki-Form-Token" ? "tok-abc" : null },
      json: async () => ({}),
    };
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await client.createPage("Main.TestPage", "Test", "content", { xwikiCookie: COOKIE });
  assert.equal(calls[0].method, "GET");
  assert.equal(calls[1].method, "PUT");
});

test("search throws XWikiAuthError on 401", async () => {
  const fetcher = mockFetch(401, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.search("test", 5, { xwikiCookie: COOKIE }),
    XWikiAuthError
  );
});

test("getPage throws XWikiAuthError on 401", async () => {
  const fetcher = mockFetch(401, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.getPage("Main.WebHome", { xwikiCookie: COOKIE }),
    XWikiAuthError
  );
});

test("createPage throws XWikiAuthError on 401 during form token fetch", async () => {
  const fetcher = mockFetch(401, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.createPage("Main.TestPage", "Test", "content", { xwikiCookie: COOKIE }),
    XWikiAuthError
  );
});

test("getPage throws generic error on 403 (not XWikiAuthError)", async () => {
  const fetcher = mockFetch(403, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.getPage("Main.WebHome", { xwikiCookie: COOKIE }),
    (err) => !(err instanceof XWikiAuthError) && err.message.includes("Access denied")
  );
});
