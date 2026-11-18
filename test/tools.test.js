import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { callTool, TOOLS } from "../src/tools.js";
import { XWikiAuthError, createXWikiClient } from "../src/xwiki-client.js";

const SESSION = { sessionId: "s1", userId: "alice", xwikiUser: "XWiki.alice", xwikiToken: "tok", tokenVersion: 1 };

function makeClient(overrides = {}) {
  return {
    search: mock.fn(async () => [{ title: "Page A", space: "Main", url: "https://xwiki.example.com/bin/view/Main/PageA" }]),
    getPage: mock.fn(async () => ({ title: "Page A", content: "Hello", author: "alice", modified: "2024-01-01" })),
    createPage: mock.fn(async () => "https://xwiki.example.com/bin/view/Main/PageA"),
    uploadAttachment: mock.fn(async () => "https://xwiki.example.com/bin/download/Main/PageA/report.pdf"),
    ...overrides,
  };
}

test("TOOLS exports array with 5 tool definitions", () => {
  assert.equal(TOOLS.length, 5);
  assert.ok(TOOLS.every((t) => t.name && t.description && t.inputSchema));
});

test("callTool search_xwiki calls client.search and returns JSON", async () => {
  const client = makeClient();
  const result = await callTool("search_xwiki", { query: "home" }, SESSION, client);
  assert.equal(client.search.mock.calls.length, 1);
  assert.equal(client.search.mock.calls[0].arguments[0], "home");
  assert.deepEqual(client.search.mock.calls[0].arguments[2], { includeHeadings: false });
  assert.equal(client.search.mock.calls[0].arguments[3], SESSION);
  const parsed = JSON.parse(result.content[0].text);
  assert.equal(parsed[0].title, "Page A");
});

test("callTool search_xwiki forwards include_headings", async () => {
  const client = makeClient();
  await callTool("search_xwiki", { query: "home", limit: 3, include_headings: true }, SESSION, client);
  assert.equal(client.search.mock.calls[0].arguments[1], 3);
  assert.deepEqual(client.search.mock.calls[0].arguments[2], { includeHeadings: true });
  assert.equal(client.search.mock.calls[0].arguments[3], SESSION);
});

test("callTool get_xwiki_page calls client.getPage", async () => {
  const client = makeClient();
  const result = await callTool("get_xwiki_page", { page_path: "Main.WebHome" }, SESSION, client);
  assert.equal(client.getPage.mock.calls[0].arguments[0], "Main.WebHome");
  assert.deepEqual(client.getPage.mock.calls[0].arguments[1], {
    includeContent: true,
    heading: undefined,
    headingOccurrence: undefined,
    contentOffset: 0,
    contentLength: undefined,
  });
  assert.equal(client.getPage.mock.calls[0].arguments[2], SESSION);
  const parsed = JSON.parse(result.content[0].text);
  assert.equal(parsed.title, "Page A");
});

test("callTool get_xwiki_page forwards heading and slice options", async () => {
  const client = makeClient();
  await callTool("get_xwiki_page", {
    page_path: "Main.WebHome",
    heading: "Details",
    heading_occurrence: 2,
    content_offset: 4,
    content_length: 10,
    include_content: false,
  }, SESSION, client);
  assert.deepEqual(client.getPage.mock.calls[0].arguments[1], {
    includeContent: false,
    heading: "Details",
    headingOccurrence: 2,
    contentOffset: 4,
    contentLength: 10,
  });
});

test("callTool create_xwiki_page calls client.createPage", async () => {
  const client = makeClient();
  await callTool("create_xwiki_page", { page_path: "Main.New", title: "New", content: "body" }, SESSION, client);
  assert.equal(client.createPage.mock.calls[0].arguments[0], "Main.New");
  assert.equal(client.createPage.mock.calls[0].arguments[3], SESSION);
});

test("callTool upload_xwiki_attachment calls client.uploadAttachment", async () => {
  const client = makeClient();
  const result = await callTool(
    "upload_xwiki_attachment",
    { page_path: "Main.New", filename: "report.pdf", source_url: "https://example.com/report.pdf", content_type: "application/pdf" },
    SESSION,
    client,
  );
  assert.equal(client.uploadAttachment.mock.calls[0].arguments[0], "Main.New");
  assert.equal(client.uploadAttachment.mock.calls[0].arguments[1], "report.pdf");
  assert.deepEqual(client.uploadAttachment.mock.calls[0].arguments[2], {
    sourceUrl: "https://example.com/report.pdf",
    contentType: "application/pdf",
  });
  assert.equal(client.uploadAttachment.mock.calls[0].arguments[3], SESSION);
  assert.ok(result.content[0].text.startsWith("Attachment uploaded:"));
});

test("callTool get_xwiki_upload_url mints a token and returns an uploadUrl/curlCommand", async () => {
  const client = makeClient();
  const toolConfig = { sessionSecret: "test-secret-32-chars-minimum-pad", mcpBaseUrl: "https://mcp.example.com/mcp" };
  const sessionCtx = { ...SESSION, sessionId: "sess-123" };
  const result = await callTool(
    "get_xwiki_upload_url",
    { page_path: "Main.New", filename: "photo.png" },
    sessionCtx,
    client,
    toolConfig,
  );
  const parsed = JSON.parse(result.content[0].text);
  assert.ok(parsed.uploadUrl.startsWith("https://mcp.example.com/mcp/uploads/"));
  assert.ok(parsed.curlCommand.includes(parsed.uploadUrl));
  assert.ok(parsed.curlCommand.startsWith("curl -T"));
  assert.ok(parsed.expiresInSeconds > 0 && parsed.expiresInSeconds <= 300);
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

test("callTool returns an isError result for non-auth errors", async () => {
  const client = makeClient({
    search: mock.fn(async () => { throw new Error("network timeout"); }),
  });
  const result = await callTool("search_xwiki", { query: "test" }, SESSION, client);
  assert.equal(result.isError, true);
  assert.equal(result.content.length, 1);
  assert.equal(result.content[0].type, "text");
  assert.equal(result.content[0].text, "Error: network timeout");
  assert.equal(result.structuredContent, undefined);
});

test("callTool unknown tool throws JSON-RPC -32602 Invalid params (no tool result)", async () => {
  const client = makeClient();
  await assert.rejects(
    () => callTool("unknown_tool", {}, SESSION, client),
    (e) => e.code === -32602 && e.message === "Unknown tool: unknown_tool",
  );
});

// --- structuredContent / outputSchema / annotations (MCP 2025-06-18+) -----------------------

// Minimal JSON Schema check for the subset the tool schemas use: type (string or list),
// properties, required, items, additionalProperties: false. Returns a list of problems.
function validate(schema, value, at = "$") {
  const errs = [];
  const types = [].concat(schema.type || []);
  const typeOf = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v);
  if (types.length) {
    const t = typeOf(value);
    const ok = types.includes(t) || (t === "integer" && types.includes("number"));
    if (!ok) return [`${at}: expected ${types.join("|")}, got ${t}`];
  }
  if (typeOf(value) === "object") {
    for (const k of schema.required || []) if (!(k in value)) errs.push(`${at}.${k}: required`);
    for (const [k, v] of Object.entries(value)) {
      if (schema.properties?.[k]) errs.push(...validate(schema.properties[k], v, `${at}.${k}`));
      else if (schema.additionalProperties === false) errs.push(`${at}.${k}: not allowed`);
    }
  }
  if (typeOf(value) === "array" && schema.items) value.forEach((v, i) => errs.push(...validate(schema.items, v, `${at}[${i}]`)));
  return errs;
}

function realClient() {
  const content = "= Intro =\nHello\n\n== Details ==\nMore text";
  const fetcher = async (url) => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    json: async () => (url.includes("/search?")
      ? { searchResults: [
        { title: "Home", pageName: "WebHome", space: "Main", pageFullName: "Main.WebHome" },
        { pageName: "Other", space: "IT", pageFullName: "IT.Other" },
      ] }
      : { title: "Home", content, author: "alice", modified: "2024-01-01", syntax: "xwiki/2.1" }),
  });
  return createXWikiClient({ baseUrl: "https://xwiki.example.com", wiki: "xwiki", fetcher });
}

const toolByName = (n) => TOOLS.find((t) => t.name === n);
const UPLOAD_CFG = { sessionSecret: "test-secret-32-chars-minimum-pad", mcpBaseUrl: "https://mcp.example.com/mcp" };

const STRUCTURED_CASES = [
  ["search_xwiki", { query: "home" }],
  ["search_xwiki", { query: "home", include_headings: true }],
  ["get_xwiki_page", { page_path: "Main.WebHome" }],
  ["get_xwiki_page", { page_path: "Main.WebHome", include_content: false }],
  ["get_xwiki_page", { page_path: "Main.WebHome", heading: "Details" }],
  ["get_xwiki_page", { page_path: "Main.WebHome", content_offset: 3, content_length: 5 }],
  ["get_xwiki_upload_url", { page_path: "Main.WebHome", filename: "a.png" }],
];

for (const [name, args] of STRUCTURED_CASES) {
  test(`${name} ${JSON.stringify(args)}: structuredContent validates against outputSchema, text unchanged`, async () => {
    const tool = toolByName(name);
    assert.equal(tool.outputSchema?.type, "object", "outputSchema must be an object schema");
    const result = await callTool(name, args, SESSION, realClient(), UPLOAD_CFG);
    assert.equal(result.isError, undefined);
    const sc = result.structuredContent;
    assert.ok(sc && typeof sc === "object" && !Array.isArray(sc), "structuredContent must be a JSON object");
    assert.deepEqual(validate(tool.outputSchema, sc), []);
    // The text block keeps exactly today's JSON (search: the bare array).
    assert.equal(result.content.length, 1);
    assert.equal(result.content[0].type, "text");
    const parsed = JSON.parse(result.content[0].text);
    if (name === "search_xwiki") {
      assert.deepEqual(sc, { results: parsed });
      assert.ok(Array.isArray(parsed));
    } else {
      assert.deepEqual(sc, parsed);
    }
    // ChatGPT renders a tool result as {} when its JSON carries a key named "content".
    assert.deepEqual(contentKeys(parsed), [], "text JSON must not contain a key named content");
    assert.deepEqual(contentKeys(sc), [], "structuredContent must not contain a key named content");
  });
}

function contentKeys(v, at = "$") {
  if (Array.isArray(v)) return v.flatMap((x, i) => contentKeys(x, `${at}[${i}]`));
  if (!v || typeof v !== "object") return [];
  return Object.entries(v).flatMap(([k, x]) => [...(k === "content" ? [`${at}.${k}`] : []), ...contentKeys(x, `${at}.${k}`)]);
}

test("get_xwiki_page returns the page body as page_content (pretty JSON, same order)", async () => {
  const client = realClient();
  const result = await callTool("get_xwiki_page", { page_path: "Main.WebHome" }, SESSION, client);
  const page = await client.getPage("Main.WebHome", { includeContent: true, contentOffset: 0 }, SESSION);
  const expected = Object.fromEntries(Object.entries(page).map(([k, v]) => [k === "content" ? "page_content" : k, v]));
  assert.equal(result.content[0].text, JSON.stringify(expected, null, 2));
  assert.equal(result.structuredContent.page_content, page.content);
  assert.ok(toolByName("get_xwiki_page").outputSchema.properties.page_content);
  assert.equal(toolByName("get_xwiki_page").outputSchema.properties.content, undefined);
});

test("create and upload tools return text only (no structuredContent)", async () => {
  const client = makeClient();
  const created = await callTool("create_xwiki_page", { page_path: "Main.New", title: "New", content: "x" }, SESSION, client);
  assert.equal(created.content[0].text, "Page created/updated: https://xwiki.example.com/bin/view/Main/PageA");
  assert.equal(created.structuredContent, undefined);
  assert.equal(created.isError, undefined);
});

test("every tool has a title and annotations matching its behaviour", () => {
  const expected = {
    search_xwiki: { readOnlyHint: true, openWorldHint: false },
    get_xwiki_page: { readOnlyHint: true, openWorldHint: false },
    create_xwiki_page: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    upload_xwiki_attachment: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    get_xwiki_upload_url: { readOnlyHint: true, idempotentHint: false },
  };
  for (const tool of TOOLS) {
    assert.equal(typeof tool.title, "string", tool.name);
    assert.ok(tool.title.length > 0, tool.name);
    for (const [k, v] of Object.entries(expected[tool.name])) assert.equal(tool.annotations?.[k], v, `${tool.name}.${k}`);
  }
  for (const n of ["search_xwiki", "get_xwiki_page", "get_xwiki_upload_url"]) assert.ok(toolByName(n).outputSchema, n);
  for (const n of ["create_xwiki_page", "upload_xwiki_attachment"]) assert.equal(toolByName(n).outputSchema, undefined, n);
});
