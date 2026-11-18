import { test, mock } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createXWikiClient, XWikiAuthError, isDisallowedIp } from "../src/xwiki-client.js";

const BASE_URL = "https://xwiki.example.com";
const SESSION = { sessionId: "s1", userId: "alice", xwikiUser: "XWiki.alice", xwikiToken: "tok", tokenVersion: 1 };
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

// An XWiki REST fake: answers the form-token GET, PUTs and page/search GETs, and records
// every call so tests can check the auth headers of each one.
function xwikiFake({ status = 200 } = {}) {
  return mock.fn(async (url, opts = {}) => {
    const method = opts.method || "GET";
    if (method === "PUT") {
      return { ok: status < 300, status: status === 200 ? 201 : status, headers: { get: () => null }, text: async () => "" };
    }
    return {
      ok: status < 300,
      status,
      headers: { get: (k) => (k === "XWiki-Form-Token" ? "form-abc" : null) },
      json: async () => (url.includes("/search?")
        ? { searchResults: [{ title: "Home", pageName: "WebHome", space: "Main", pageFullName: "Main.WebHome" }] }
        : { title: "Home", content: "= Intro =\nHello", author: "alice", modified: "2024-01-01" }),
      text: async () => "",
    };
  });
}

function assertBearerOnly(headers) {
  assert.equal(headers.Authorization, "Bearer tok");
  assert.equal(headers.Accept, "application/json");
  assert.ok(
    !Object.keys(headers).some((k) => k.toLowerCase() === "cookie"),
    "no Cookie header may be sent to XWiki",
  );
}

// source_url fetches go over node:http, not over `fetcher`. The tests reach a local server on
// 127.0.0.1 through the configured (trusted) XWiki host name, which the injected `sourceLookup`
// maps to 127.0.0.1 — the trusted XWiki host is the only name whose resolved address is not
// IP-checked, so no extra test-only allow switch is needed. Untrusted names in these tests are
// mapped to private addresses and must be refused before any connection.
async function withSourceServer(handler, fn) {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    handler(req, res);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await fn(server.address().port, seen);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

function mapLookup(map) {
  return mock.fn(async (hostname) => {
    if (Object.hasOwn(map, hostname)) return [{ address: map[hostname], family: map[hostname].includes(":") ? 6 : 4 }];
    throw new Error(`ENOTFOUND ${hostname}`);
  });
}

test("search sends the bearer token and returns mapped results", async () => {
  const fetcher = mockFetch(200, {
    searchResults: [{ title: "Home", pageName: "WebHome", space: "Main", pageFullName: "Main.WebHome" }]
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const results = await client.search("home", 5, SESSION);
  const call = fetcher.mock.calls[0];
  assertBearerOnly(call.arguments[1].headers);
  assert.equal(results[0].title, "Home");
});

test("every XWiki REST call sends Authorization: Bearer and no Cookie", async () => {
  const fetcher = xwikiFake();
  await withSourceServer((req, res) => res.end("bytes"), async (port, seen) => {
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`,
      wiki: WIKI,
      fetcher,
      sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await client.search("home", 5, { includeHeadings: true }, SESSION);
    await client.getPage("Main.WebHome", SESSION);
    await client.getPage("Main.WebHome", { heading: "Intro" }, SESSION);
    await client.createPage("Main.New", "New", "body", SESSION);
    await client.uploadAttachment("Main.New", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/a.bin` }, SESSION);
    await client.putAttachmentBytes("Main.New", "b.bin", Buffer.from("b"), "text/plain", SESSION);
    // the source_url host never sees XWiki credentials
    assert.equal(seen.length, 1);
    assert.equal(seen[0].headers.authorization, undefined);
    assert.equal(seen[0].headers.cookie, undefined);
  });
  assert.ok(fetcher.mock.calls.length >= 9);
  for (const call of fetcher.mock.calls) assertBearerOnly(call.arguments[1].headers);
  const puts = fetcher.mock.calls.filter((c) => c.arguments[1].method === "PUT");
  assert.equal(puts.length, 3);
  for (const put of puts) assert.equal(put.arguments[1].headers["XWiki-Form-Token"], "form-abc");
});

test("a session without xwikiToken is a programming error, not an auth error", async () => {
  const fetcher = xwikiFake();
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.getPage("Main.WebHome", { sessionId: "s1", userId: "alice" }),
    (err) => !(err instanceof XWikiAuthError) && /missing XWiki token/.test(err.message),
  );
  assert.equal(fetcher.mock.calls.length, 0);
});

test("the client no longer offers touchSession", () => {
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher: xwikiFake() });
  assert.equal(client.touchSession, undefined);
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
  const results = await client.search("home", 5, { includeHeadings: true }, SESSION);
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
  const page = await client.getPage("Main.WebHome", SESSION);
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
  const page = await client.getPage("Main.WebHome", { heading: "Details", headingOccurrence: 2 }, SESSION);
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
    SESSION,
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
  const page = await client.getPage("Main.WebHome", { includeContent: false }, SESSION);
  assert.equal(page.content, undefined);
  assert.equal(page.contentLength, 0);
  assert.equal(page.totalContentLength, 5);
  assert.equal(page.contentTruncated, true);
});

test("getPage throws when requested heading is missing", async () => {
  const fetcher = mockFetch(200, { title: "Home", content: "= Intro =\nHello", author: "alice", modified: "2024-01-01" });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.getPage("Main.WebHome", { heading: "Missing" }, SESSION),
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
  const page = await client.getPage("Main.WebHome", { heading: "Details", headingOccurrence: 2 }, SESSION);
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
  await client.createPage("Main.TestPage", "Test", "content", SESSION);
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
  await client.createPage("Main.TestPage", "Test", "content", SESSION);
  assert.match(putBody, /<syntax>markdown\/1\.2<\/syntax>/);
});

test("search throws XWikiAuthError on 401", async () => {
  const fetcher = mockFetch(401, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.search("test", 5, SESSION),
    XWikiAuthError
  );
});

test("getPage throws XWikiAuthError on 401", async () => {
  const fetcher = mockFetch(401, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.getPage("Main.WebHome", SESSION),
    XWikiAuthError
  );
});

test("createPage throws XWikiAuthError on 401 during form token fetch", async () => {
  const fetcher = mockFetch(401, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.createPage("Main.TestPage", "Test", "content", SESSION),
    XWikiAuthError
  );
});

test("uploadAttachment rejects non-http(s) source_url schemes", async () => {
  const fetcher = mock.fn(async () => { throw new Error("must not be called"); });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl: "file:///etc/passwd" }, SESSION),
    /must use http or https/
  );
  assert.equal(fetcher.mock.calls.length, 0);
});

test("uploadAttachment rejects source_url pointing at a loopback address", async () => {
  const fetcher = mock.fn(async () => { throw new Error("must not be called"); });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl: "http://127.0.0.1/secret" }, SESSION),
    /disallowed internal\/private address/
  );
  assert.equal(fetcher.mock.calls.length, 0);
});

test("uploadAttachment rejects source_url pointing at a private address", async () => {
  const fetcher = mock.fn(async () => { throw new Error("must not be called"); });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", { sourceUrl: "http://10.1.2.3/secret" }, SESSION),
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
      SESSION,
    ),
    /disallowed internal\/private address/
  );
  assert.equal(fetcher.mock.calls.length, 0);
});

test("uploadAttachment throws when source_url is not given", async () => {
  const fetcher = mockFetch(200, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.uploadAttachment("Main.TestPage", "data.bin", {}, SESSION),
    /source_url is required/
  );
});

test("getPage throws generic error on 403 (not XWikiAuthError)", async () => {
  const fetcher = mockFetch(403, {});
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(
    () => client.getPage("Main.WebHome", SESSION),
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
  const results = await client.search("docker", 5, SESSION);
  assert.equal(results[0].url, "https://xwiki.example.com/bin/view/IT/Virtualisierung/Docker%20Struktur/WebHome");
  assert.ok(fetcher.mock.calls[0].arguments[0].startsWith("http://xwiki-internal:8080/rest/"));
});

test("links fall back to baseUrl when no publicUrl is given", async () => {
  const fetcher = mockFetch(200, {
    searchResults: [{ title: "Home", pageName: "WebHome", space: "Main", pageFullName: "Main.WebHome" }],
  });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const results = await client.search("home", 5, SESSION);
  assert.equal(results[0].url, `${BASE_URL}/bin/view/Main/WebHome`);
});


test("putAttachmentBytes / createPage PUT answered with 401 throws XWikiAuthError", async () => {
  const fetcher = mock.fn(async (url, opts = {}) => (opts.method === "PUT"
    ? { ok: false, status: 401, headers: { get: () => null }, text: async () => "" }
    : { ok: true, status: 200, headers: { get: () => "form-abc" }, json: async () => ({}) }));
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await assert.rejects(() => client.createPage("Main.P", "P", "c", SESSION), XWikiAuthError);
  await assert.rejects(() => client.putAttachmentBytes("Main.P", "a.bin", Buffer.from("a"), undefined, SESSION), XWikiAuthError);
});

// ---- source_url: fetched over node:http(s) with a checking lookup ----

test("uploadAttachment fetches bytes server-side from source_url and PUTs them with a publicUrl link", async () => {
  const fetcher = xwikiFake();
  await withSourceServer((req, res) => {
    res.setHeader("content-length", "9");
    res.end("hello pdf");
  }, async (port) => {
    const client = createXWikiClient({
      baseUrl: `http://xwiki-internal:${port}`,
      publicUrl: "https://xwiki.example.com/",
      wiki: WIKI,
      fetcher,
      sourceLookup: mapLookup({ "xwiki-internal": "127.0.0.1" }),
    });
    const url = await client.uploadAttachment(
      "Main.TestPage",
      "report.pdf",
      { sourceUrl: `http://xwiki-internal:${port}/files/report.pdf` },
      SESSION,
    );
    assert.equal(url, "https://xwiki.example.com/bin/download/Main/TestPage/report.pdf");
  });
  const put = fetcher.mock.calls.find((c) => c.arguments[1].method === "PUT");
  assert.ok(Buffer.from(put.arguments[1].body).equals(Buffer.from("hello pdf")));
  assert.ok(fetcher.mock.calls.every((c) => /^http:\/\/xwiki-internal:\d+\/rest\//.test(c.arguments[0])));
});

test("source_url on the trusted XWiki host may resolve to a private address", async () => {
  await withSourceServer((req, res) => res.end("hi"), async (port, seen) => {
    const lookup = mapLookup({ "xwiki-postgres-tomcat-web": "127.0.0.1" });
    const client = createXWikiClient({
      baseUrl: `http://xwiki-postgres-tomcat-web:${port}`,
      wiki: WIKI,
      fetcher: xwikiFake(),
      sourceLookup: lookup,
    });
    await client.uploadAttachment(
      "Main.TestPage", "data.bin", { sourceUrl: `http://xwiki-postgres-tomcat-web:${port}/f` }, SESSION,
    );
    assert.equal(seen.length, 1);
    assert.equal(lookup.mock.calls.length, 1);
  });
});

test("source_url host that resolves to 10.0.0.1 at connect time is refused", async () => {
  const fetcher = xwikiFake();
  const lookup = mapLookup({ "files.example.org": "10.0.0.1" });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher, sourceLookup: lookup });
  await assert.rejects(
    () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: "http://files.example.org/a.bin" }, SESSION),
    /disallowed internal\/private address/,
  );
  assert.equal(lookup.mock.calls.length, 1);
  assert.equal(lookup.mock.calls[0].arguments[0], "files.example.org");
  assert.equal(fetcher.mock.calls.length, 0);
});

test("source_url host resolving to an IPv4-mapped loopback address is refused", async () => {
  const client = createXWikiClient({
    baseUrl: BASE_URL, wiki: WIKI, fetcher: xwikiFake(), sourceLookup: mapLookup({ "m.example.org": "::ffff:7f00:1" }),
  });
  await assert.rejects(
    () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: "https://m.example.org/a" }, SESSION),
    /disallowed internal\/private address/,
  );
});

test("source_url 302 to http://127.0.0.1/... is refused before connecting", async () => {
  await withSourceServer((req, res) => {
    res.statusCode = 302;
    res.setHeader("location", `http://127.0.0.1:${req.socket.localPort}/secret`);
    res.end();
  }, async (port, seen) => {
    const fetcher = xwikiFake();
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`, wiki: WIKI, fetcher, sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/start` }, SESSION),
      /disallowed internal\/private address/,
    );
    assert.deepEqual(seen.map((s) => s.url), ["/start"]);
    assert.equal(fetcher.mock.calls.length, 0);
  });
});

test("source_url redirect to a name resolving to a private address is refused", async () => {
  await withSourceServer((req, res) => {
    res.statusCode = 307;
    res.setHeader("location", "http://intranet.example.org/x");
    res.end();
  }, async (port) => {
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`,
      wiki: WIKI,
      fetcher: xwikiFake(),
      sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1", "intranet.example.org": "192.168.1.5" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/start` }, SESSION),
      /disallowed internal\/private address/,
    );
  });
});

test("source_url redirect to a non-http scheme is refused", async () => {
  await withSourceServer((req, res) => {
    res.statusCode = 301;
    res.setHeader("location", "file:///etc/passwd");
    res.end();
  }, async (port) => {
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`, wiki: WIKI, fetcher: xwikiFake(), sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/start` }, SESSION),
      /must use http or https/,
    );
  });
});

function redirectChain(req, res) {
  const n = Number(req.url.split("/").pop());
  res.statusCode = 302;
  res.setHeader("location", `/r/${n + 1}`); // relative, resolved against the current URL
  res.end();
}

test("source_url: six redirects in a row fail with too many redirects", async () => {
  await withSourceServer(redirectChain, async (port, seen) => {
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`, wiki: WIKI, fetcher: xwikiFake(), sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/r/0` }, SESSION),
      /too many redirects/,
    );
    assert.equal(seen.length, 6); // the original request plus five followed redirects
  });
});

test("source_url: five redirects are followed", async () => {
  await withSourceServer((req, res) => {
    if (req.url === "/r/5") return res.end("done");
    return redirectChain(req, res);
  }, async (port, seen) => {
    const fetcher = xwikiFake();
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`, wiki: WIKI, fetcher, sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/r/0` }, SESSION);
    assert.equal(seen.length, 6);
    const put = fetcher.mock.calls.find((c) => c.arguments[1].method === "PUT");
    assert.equal(Buffer.from(put.arguments[1].body).toString(), "done");
  });
});

test("source_url non-2xx answer is an error", async () => {
  await withSourceServer((req, res) => { res.statusCode = 404; res.end(); }, async (port) => {
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`, wiki: WIKI, fetcher: xwikiFake(), sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/x` }, SESSION),
      /Failed to fetch source_url: 404/,
    );
  });
});

test("uploadAttachment rejects an oversized source_url response via Content-Length", async () => {
  await withSourceServer((req, res) => {
    res.writeHead(200, { "content-length": String(60 * 1024 * 1024) });
    res.write("x");
  }, async (port) => {
    const fetcher = xwikiFake();
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`, wiki: WIKI, fetcher, sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/huge` }, SESSION),
      /exceeds maximum allowed size/,
    );
    assert.equal(fetcher.mock.calls.length, 0);
  });
});

test("uploadAttachment rejects an oversized source_url body even when Content-Length is missing", async () => {
  const chunk = Buffer.alloc(1024 * 1024, 0x61);
  await withSourceServer((req, res) => {
    let sent = 0;
    const pump = () => {
      while (sent < 52 && !res.destroyed) {
        sent += 1;
        if (!res.write(chunk)) return res.once("drain", pump);
      }
      return res.end();
    };
    res.on("error", () => {});
    pump();
  }, async (port) => {
    const fetcher = xwikiFake();
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`, wiki: WIKI, fetcher, sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/huge` }, SESSION),
      /exceeds maximum allowed size/,
    );
    assert.equal(fetcher.mock.calls.length, 0);
  });
});

test("uploadAttachment throws XWikiAuthError on 401 during form token fetch", async () => {
  await withSourceServer((req, res) => res.end("hi"), async (port) => {
    const fetcher = mock.fn(async () => ({ ok: false, status: 401, headers: { get: () => null }, json: async () => ({}) }));
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`, wiki: WIKI, fetcher, sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/a` }, SESSION),
      XWikiAuthError,
    );
  });
});

test("isDisallowedIp covers internal, special and IPv4-mapped ranges", () => {
  const blocked = [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
    "0.0.0.0", "100.64.0.1", "100.127.255.255", "224.0.0.1", "239.255.255.250", "255.255.255.255",
    "::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1",
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:a00:1", "::ffff:169.254.169.254", "0:0:0:0:0:ffff:7f00:1",
    // the whole IPv4-mapped prefix ::ffff:0:0/96 is refused, public embedded addresses too
    "::ffff:8.8.8.8", "::ffff:808:808", "0:0:0:0:0:ffff:0808:0808",
    "not-an-ip", "1.2.3",
  ];
  const allowed = ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111"];
  for (const ip of blocked) assert.equal(isDisallowedIp(ip), true, ip);
  for (const ip of allowed) assert.equal(isDisallowedIp(ip), false, ip);
});

// ---- hardening after review: credentials in source_url, trusted host pinned to its port ----

test("source_url with userinfo is refused before any connection", async () => {
  const lookup = mapLookup({ "files.example.org": "93.184.216.34" });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher: xwikiFake(), sourceLookup: lookup });
  for (const sourceUrl of ["http://user:pw@files.example.org/a", "https://user@files.example.org/a", "http://:pw@files.example.org/a"]) {
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl }, SESSION),
      /source_url must not contain credentials/,
      sourceUrl,
    );
  }
  assert.equal(lookup.mock.calls.length, 0);
});

test("source_url redirect to a URL with userinfo is refused", async () => {
  await withSourceServer((req, res) => {
    if (req.url !== "/start") {
      res.end("must not be reached");
      return;
    }
    res.statusCode = 302;
    res.setHeader("location", `http://user:pw@xwiki.internal:${req.socket.localPort}/next`);
    res.end();
  }, async (port, seen) => {
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${port}`, wiki: WIKI, fetcher: xwikiFake(), sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/start` }, SESSION),
      /source_url must not contain credentials/,
    );
    assert.deepEqual(seen.map((s) => s.url), ["/start"]);
  });
});

test("the trusted XWiki host is exempt only on the configured port", async () => {
  await withSourceServer((req, res) => res.end("hi"), async (port, seen) => {
    // baseUrl names another port on the same host: the source server's port is not exempt,
    // so its private address is checked and refused
    const otherPort = port === 65535 ? port - 1 : port + 1;
    const client = createXWikiClient({
      baseUrl: `http://xwiki.internal:${otherPort}`, wiki: WIKI, fetcher: xwikiFake(), sourceLookup: mapLookup({ "xwiki.internal": "127.0.0.1" }),
    });
    await assert.rejects(
      () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: `http://xwiki.internal:${port}/a` }, SESSION),
      /disallowed internal\/private address/,
    );
    assert.equal(seen.length, 0);
  });
});

test("the trusted-host exemption compares scheme-default ports", async () => {
  const lookup = mapLookup({ "xwiki.internal": "10.0.0.5" });
  // baseUrl https without port = 443; source on http (port 80) of the same host is not exempt
  const client = createXWikiClient({ baseUrl: "https://xwiki.internal", wiki: WIKI, fetcher: xwikiFake(), sourceLookup: lookup });
  await assert.rejects(
    () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: "http://xwiki.internal/a" }, SESSION),
    /disallowed internal\/private address/,
  );
  await assert.rejects(
    () => client.uploadAttachment("Main.P", "a.bin", { sourceUrl: "https://xwiki.internal:8443/a" }, SESSION),
    /disallowed internal\/private address/,
  );
});

// --- search scopes and dedupe ---------------------------------------------------------------

test("search queries page name, title and content scopes and keeps the limit", async () => {
  const fetcher = mockFetch(200, { searchResults: [] });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  await client.search("EdooboxMCP", 7, SESSION);
  const url = new URL(fetcher.mock.calls[0].arguments[0]);
  assert.equal(url.pathname, "/rest/wikis/xwiki/search");
  assert.equal(url.searchParams.get("q"), "EdooboxMCP");
  assert.deepEqual(url.searchParams.getAll("scope").sort(), ["content", "name", "title"]);
  assert.equal(url.searchParams.get("number"), "7");
});

test("search dedupes results by page id (same page hit via name, title and content)", async () => {
  const hit = { title: "EdooboxMCP", pageName: "WebHome", space: "IT.LLM.MCP.EdooboxMCP", pageFullName: "IT.LLM.MCP.EdooboxMCP.WebHome", id: "xwiki:IT.LLM.MCP.EdooboxMCP.WebHome" };
  const other = { title: "Other", pageName: "WebHome", space: "IT.Other", pageFullName: "IT.Other.WebHome", id: "xwiki:IT.Other.WebHome" };
  const fetcher = mockFetch(200, { searchResults: [hit, { ...hit }, other, { ...hit }] });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const results = await client.search("EdooboxMCP", 10, SESSION);
  assert.deepEqual(results.map((r) => r.title), ["EdooboxMCP", "Other"]);
});

test("search returns at most limit results after dedupe", async () => {
  const mk = (n) => ({ title: `P${n}`, pageName: "WebHome", space: `S${n}`, pageFullName: `S${n}.WebHome`, id: `xwiki:S${n}.WebHome` });
  const fetcher = mockFetch(200, { searchResults: [mk(1), mk(1), mk(2), mk(3), mk(4)] });
  const client = createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
  const results = await client.search("p", 2, SESSION);
  assert.deepEqual(results.map((r) => r.title), ["P1", "P2"]);
});

// --- headings inside code blocks ------------------------------------------------------------

function pageClient(content) {
  const fetcher = mock.fn(async (url) => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    json: async () => (url.includes("/search?")
      ? { searchResults: [{ title: "Doc", pageName: "WebHome", space: "IT", pageFullName: "IT.WebHome" }] }
      : { title: "Doc", content, author: "alice", modified: "2024-01-01" }),
  }));
  return createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
}

const XWIKI_CODE_PAGE = [
  "= Setup =",
  "Run this:",
  "{{code language=\"bash\"}}",
  "# auf docker101",
  "= not a heading =",
  "{{/code}}",
  "{{{",
  "== verbatim ==",
  "}}}",
  "{{code}}# inline{{/code}}",
  "= Next =",
  "done",
].join("\n");

const MARKDOWN_CODE_PAGE = [
  "# Setup",
  "```bash",
  "# auf docker101",
  "```",
  "~~~",
  "## tilde comment",
  "~~~",
  "````",
  "```",
  "# still code",
  "````",
  "# Next",
  "done",
].join("\n");

test("headings inside XWiki {{code}} and {{{ }}} blocks are ignored", async () => {
  const [r] = await pageClient(XWIKI_CODE_PAGE).search("doc", 5, { includeHeadings: true }, SESSION);
  assert.deepEqual(r.headings.map((h) => h.title), ["Setup", "Next"]);
});

test("headings inside fenced Markdown code blocks (``` and ~~~) are ignored", async () => {
  const [r] = await pageClient(MARKDOWN_CODE_PAGE).search("doc", 5, { includeHeadings: true }, SESSION);
  assert.deepEqual(r.headings.map((h) => h.title), ["Setup", "Next"]);
});

for (const [label, content] of [["XWiki", XWIKI_CODE_PAGE], ["Markdown", MARKDOWN_CODE_PAGE]]) {
  test(`section extraction (${label}) runs across code blocks and cannot target a code comment`, async () => {
    const client = pageClient(content);
    const page = await client.getPage("IT.WebHome", { heading: "Setup" }, SESSION);
    assert.ok(page.content.includes("# auf docker101"), "code block belongs to the section");
    assert.ok(!page.content.includes("Next"), "section ends at the next real heading");
    await assert.rejects(() => client.getPage("IT.WebHome", { heading: "auf docker101" }, SESSION), /Heading not found/);
  });
}

// --- code block detection: self-closing macros, openers after prose, inline code, syntax ------

function syntaxClient(content, syntax) {
  const fetcher = mock.fn(async (url) => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    json: async () => (url.includes("/search?")
      ? { searchResults: [{ title: "Doc", pageName: "WebHome", space: "IT", pageFullName: "IT.WebHome" }] }
      : { title: "Doc", content, author: "alice", modified: "2024-01-01", ...(syntax ? { syntax } : {}) }),
  }));
  return createXWikiClient({ baseUrl: BASE_URL, wiki: WIKI, fetcher });
}
const headingTitles = async (content, syntax) =>
  (await syntaxClient(content, syntax).search("doc", 5, { includeHeadings: true }, SESSION))[0].headings.map((h) => h.title);

for (const syntax of ["xwiki/2.1", "markdown/1.2", undefined]) {
  test(`self-closing {{code .../}} opens no block (${syntax || "no syntax"})`, async () => {
    const content = ["= Before =", "{{code language=\"bash\" source=\"string:echo x\"/}}", "= Later =", "text"].join("\n");
    assert.deepEqual(await headingTitles(content, syntax), ["Before", "Later"]);
  });

  test(`{{code}} opened after prose and {{/code}} closing mid-line (${syntax || "no syntax"})`, async () => {
    const content = [
      "= Before =",
      "Run: {{code language=\"bash\"}}",
      "= inside =",
      "# auf docker101",
      "echo done {{/code}} and more prose",
      "= After =",
    ].join("\n");
    assert.deepEqual(await headingTitles(content, syntax), ["Before", "After"]);
  });
}

for (const syntax of ["markdown/1.2", undefined]) {
  test(`\`\`\`inline\`\`\` code span on its own line is not a fence (${syntax || "no syntax"})`, async () => {
    const content = ["# Before", "```example```", "# Real", "text", "~~~ info with ` backtick", "# in tilde fence", "~~~", "# End"].join("\n");
    assert.deepEqual(await headingTitles(content, syntax), ["Before", "Real", "End"]);
  });
}

test("xwiki/2.1 page: a bare ``` line is no fence, later = … = headings stay", async () => {
  const content = ["= One =", "```", "= Two =", "text", "= Three ="].join("\n");
  assert.deepEqual(await headingTitles(content, "xwiki/2.1"), ["One", "Two", "Three"]);
  const page = await syntaxClient(content, "xwiki/2.1").getPage("IT.WebHome", { heading: "Two" }, SESSION);
  assert.equal(page.content, "= Two =\ntext");
});

test("markdown/1.2 page: ``` fence still hides # comments; section extraction uses the syntax", async () => {
  const content = ["# One", "```", "# comment", "```", "# Two", "text"].join("\n");
  assert.deepEqual(await headingTitles(content, "markdown/1.2"), ["One", "Two"]);
  const page = await syntaxClient(content, "markdown/1.2").getPage("IT.WebHome", { heading: "One" }, SESSION);
  assert.ok(page.content.includes("# comment"));
});
