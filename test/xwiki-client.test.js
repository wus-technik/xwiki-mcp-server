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

test("search can include parsed headings per result", async () => {
  const fetcher = mock.fn(async (url) => {
    if (url.includes("/search?")) {
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        json: async () => ({
          searchResults: [{ title: "Home", pageName: "WebHome", space: "Main", pageFullName: "Main.WebHome" }],
        }),
      };
    }

    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({
        title: "Home",
        content: "= Intro =\nHello\n\n== Hetzner Object Storage ==\nBody\n\n== RustFS ==", author: "alice", modified: "2024-01-01",
      }),
    };
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const results = await client.search("home", 5, { includeHeadings: true }, { xwikiCookie: COOKIE });
  assert.deepEqual(results[0].headings, [
    { title: "Intro", level: 1, occurrence: 1 },
    { title: "Hetzner Object Storage", level: 2, occurrence: 1 },
    { title: "RustFS", level: 2, occurrence: 1 },
  ]);
});

test("getPage returns page fields", async () => {
  const fetcher = mockFetch(200, {
    title: "Home", content: "Hello", author: "alice", modified: "2024-01-01", syntax: "markdown/1.2",
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const page = await client.getPage("Main.WebHome", { xwikiCookie: COOKIE });
  assert.equal(page.title, "Home");
  assert.equal(page.content, "Hello");
  assert.equal(page.syntax, "markdown/1.2");
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

test("getPage can return a section by heading in Markdown syntax", async () => {
  const content = [
    "# Intro",
    "hello",
    "",
    "## Details",
    "alpha",
    "",
    "## Details",
    "beta",
    "",
    "# End",
    "bye",
  ].join("\n");
  const fetcher = mockFetch(200, { title: "Home", content, author: "alice", modified: "2024-01-01" });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const page = await client.getPage("Main.WebHome", { heading: "Details", headingOccurrence: 2 }, { xwikiCookie: COOKIE });
  assert.equal(page.headingMatched, "Details");
  assert.equal(page.headingOccurrence, 2);
  assert.equal(page.headingLevel, 2);
  assert.equal(page.content, "## Details\nbeta");
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

test("createPage sends Markdown as the page syntax by default", async () => {
  let putBody = "";
  const fetcher = mock.fn(async (url, opts) => {
    if (opts?.method === "PUT") {
      putBody = opts.body;
      return { ok: true, status: 201, headers: { get: () => null }, text: async () => "" };
    }
    return {
      ok: true, status: 200,
      headers: { get: (k) => k === "XWiki-Form-Token" ? "tok-abc" : null },
      json: async () => ({}),
    };
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await client.createPage("Main.TestPage", "Test", "content", { xwikiCookie: COOKIE });
  assert.match(putBody, /<syntax>markdown\/1\.2<\/syntax>/);
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

test("uploadAttachment returns a publicUrl-based download link when configured", async () => {
  const sourceUrl = "http://xwiki-internal:8080/files/report.pdf";
  const fetcher = mock.fn(async (url, opts) => {
    if (url === sourceUrl) {
      return {
        ok: true, status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => new TextEncoder().encode("hello pdf").buffer,
      };
    }
    if (opts?.method === "PUT") {
      return { ok: true, status: 201, headers: { get: () => null }, text: async () => "" };
    }
    return {
      ok: true, status: 200,
      headers: { get: (k) => (k === "XWiki-Form-Token" ? "tok-abc" : null) },
      json: async () => ({}),
    };
  });
  const client = createXWikiClient({
    baseUrl: "http://xwiki-internal:8080",
    publicUrl: "https://xwiki.example.com/",
    wiki: WIKI,
    fetcher,
  });
  const url = await client.uploadAttachment(
    "Main.TestPage",
    "report.pdf",
    { sourceUrl },
    { xwikiCookie: COOKIE },
  );
  assert.equal(url, "https://xwiki.example.com/bin/download/Main/TestPage/report.pdf");
  assert.ok(fetcher.mock.calls.every((c) => !c.arguments[0].startsWith("https://xwiki.example.com")));
});

test("uploadAttachment fetches bytes server-side from source_url and PUTs them", async () => {
  const sourceUrl = `${BASE_URL}/files/report.pdf`;
  let putBody;
  const fetcher = mock.fn(async (url, opts) => {
    if (url === sourceUrl) {
      return {
        ok: true, status: 200,
        headers: { get: (k) => (k === "content-length" ? "9" : null) },
        arrayBuffer: async () => new TextEncoder().encode("hello pdf").buffer,
      };
    }
    if (opts?.method === "PUT") {
      putBody = opts.body;
      return { ok: true, status: 201, headers: { get: () => null }, text: async () => "" };
    }
    return {
      ok: true, status: 200,
      headers: { get: (k) => (k === "XWiki-Form-Token" ? "tok-abc" : null) },
      json: async () => ({}),
    };
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const url = await client.uploadAttachment(
    "Main.TestPage",
    "report.pdf",
    { sourceUrl },
    { xwikiCookie: COOKIE },
  );
  assert.ok(Buffer.from(putBody).equals(Buffer.from("hello pdf")));
  assert.equal(url, `${BASE_URL}/bin/download/Main/TestPage/report.pdf`);
});

test("uploadAttachment rejects non-http(s) source_url schemes", async () => {
  const fetcher = mock.fn(async () => { throw new Error("must not be called"); });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl: "file:///etc/passwd" }, { xwikiCookie: COOKIE }),
    /must use http or https/
  );
  assert.equal(fetcher.mock.calls.length, 0);
});

test("uploadAttachment rejects source_url pointing at a loopback address", async () => {
  const fetcher = mock.fn(async () => { throw new Error("must not be called"); });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl: "http://127.0.0.1/secret" }, { xwikiCookie: COOKIE }),
    /disallowed internal\/private address/
  );
  assert.equal(fetcher.mock.calls.length, 0);
});

test("uploadAttachment rejects source_url pointing at a private address", async () => {
  const fetcher = mock.fn(async () => { throw new Error("must not be called"); });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl: "http://10.1.2.3/secret" }, { xwikiCookie: COOKIE }),
    /disallowed internal\/private address/
  );
  assert.equal(fetcher.mock.calls.length, 0);
});

test("uploadAttachment rejects source_url pointing at the cloud metadata / link-local address", async () => {
  const fetcher = mock.fn(async () => { throw new Error("must not be called"); });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment(
      "Main.TestPage",
      "data.bin",
      { sourceUrl: "http://169.254.169.254/latest/meta-data/" },
      { xwikiCookie: COOKIE },
    ),
    /disallowed internal\/private address/
  );
  assert.equal(fetcher.mock.calls.length, 0);
});

test("uploadAttachment allows source_url on the trusted internal XWiki host without a DNS check", async () => {
  // Uses an internal-looking hostname that would otherwise fail DNS resolution,
  // proving the trusted-host exception (not the IP check) is what let it through.
  const internalBaseUrl = "http://xwiki-postgres-tomcat-web:8080";
  const sourceUrl = `${internalBaseUrl}/files/report.pdf`;
  const fetcher = mock.fn(async (url, opts) => {
    if (url === sourceUrl) {
      return {
        ok: true, status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => new TextEncoder().encode("hi").buffer,
      };
    }
    if (opts?.method === "PUT") {
      return { ok: true, status: 201, headers: { get: () => null }, text: async () => "" };
    }
    return {
      ok: true, status: 200,
      headers: { get: (k) => (k === "XWiki-Form-Token" ? "tok-abc" : null) },
      json: async () => ({}),
    };
  });
  const client = createXWikiClient({ baseUrl: internalBaseUrl, wiki: WIKI, fetcher });
  await client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl }, { xwikiCookie: COOKIE });
  assert.equal(fetcher.mock.calls.some((c) => c.arguments[0] === sourceUrl), true);
});

test("uploadAttachment rejects an oversized source_url response via Content-Length", async () => {
  const sourceUrl = `${BASE_URL}/huge.bin`;
  const fetcher = mock.fn(async (url) => {
    if (url === sourceUrl) {
      return {
        ok: true, status: 200,
        headers: { get: (k) => (k === "content-length" ? String(60 * 1024 * 1024) : null) },
        arrayBuffer: async () => new ArrayBuffer(0),
      };
    }
    throw new Error("must not reach form token / PUT");
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl }, { xwikiCookie: COOKIE }),
    /exceeds maximum allowed size/
  );
});

test("uploadAttachment rejects an oversized source_url body even when Content-Length is missing", async () => {
  const sourceUrl = `${BASE_URL}/huge.bin`;
  const fetcher = mock.fn(async (url) => {
    if (url === sourceUrl) {
      return {
        ok: true, status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => new ArrayBuffer(51 * 1024 * 1024),
      };
    }
    throw new Error("must not reach form token / PUT");
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl }, { xwikiCookie: COOKIE }),
    /exceeds maximum allowed size/
  );
});

test("uploadAttachment throws when source_url is not given", async () => {
  const fetcher = mockFetch(200, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", {}, { xwikiCookie: COOKIE }),
    /source_url is required/
  );
});

test("uploadAttachment throws XWikiAuthError on 401 during form token fetch", async () => {
  const sourceUrl = `${BASE_URL}/files/data.bin`;
  const fetcher = mock.fn(async (url) => {
    if (url === sourceUrl) {
      return {
        ok: true, status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => new TextEncoder().encode("hi").buffer,
      };
    }
    return { ok: false, status: 401, headers: { get: () => null }, json: async () => ({}) };
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl }, { xwikiCookie: COOKIE }),
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

test("links use publicUrl and encode path segments; REST calls stay on baseUrl", async () => {
  const fetcher = mock.fn(async (url) => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    json: async () => (url.includes("/search?")
      ? { searchResults: [{ title: "Docker Struktur", pageName: "WebHome", space: "IT.Virtualisierung.Docker Struktur", pageFullName: "IT.Virtualisierung.Docker Struktur.WebHome" }] }
      : {}),
    text: async () => "",
  }));
  const client = createXWikiClient({
    baseUrl: "http://xwiki-internal:8080",
    publicUrl: "https://xwiki.example.com/",
    wiki: WIKI,
    fetcher,
  });
  const results = await client.search("docker", 5, { xwikiCookie: COOKIE });
  assert.equal(results[0].url, "https://xwiki.example.com/bin/view/IT/Virtualisierung/Docker%20Struktur/WebHome");
  assert.ok(fetcher.mock.calls[0].arguments[0].startsWith("http://xwiki-internal:8080/rest/"));
});

test("links fall back to baseUrl when no publicUrl is given", async () => {
  const fetcher = mockFetch(200, {
    searchResults: [{ title: "Home", pageName: "WebHome", space: "Main", pageFullName: "Main.WebHome" }],
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const results = await client.search("home", 5, { xwikiCookie: COOKIE });
  assert.equal(results[0].url, `${BASE_URL}/bin/view/Main/WebHome`);
});
