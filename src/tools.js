import { XWikiAuthError } from "./xwiki-client.js";
import { mintUploadToken } from "./upload-token.js";

// Output schemas (MCP 2025-06-18+): structuredContent must be a JSON object, so search wraps
// its array as { results }. Nullable fields mirror what XWiki may leave empty.
const NULLABLE_STRING = { type: ["string", "null"] };
const NULLABLE_INT = { type: ["integer", "null"] };

const HEADINGS_SCHEMA = {
  type: "array",
  items: {
    type: "object",
    properties: {
      title: { type: "string" },
      level: { type: "integer" },
      occurrence: { type: "integer" },
    },
    required: ["title", "level", "occurrence"],
  },
};

const SEARCH_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    results: {
      type: "array",
      items: {
        type: "object",
        properties: {
          title: NULLABLE_STRING,
          space: NULLABLE_STRING,
          url: { type: "string" },
          headings: HEADINGS_SCHEMA,
        },
        required: ["url"],
      },
    },
  },
  required: ["results"],
};

// The page body is "page_content", never "content": ChatGPT shows a tool result as {} when
// its JSON carries a key named "content".
const PAGE_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    title: NULLABLE_STRING,
    author: NULLABLE_STRING,
    modified: { type: ["string", "number", "null"] },
    syntax: NULLABLE_STRING,
    page_content: { type: "string", description: "Page body (or the requested section/slice of it)" },
    contentOffset: { type: "integer" },
    contentLength: { type: "integer" },
    totalContentLength: { type: "integer" },
    contentTruncated: { type: "boolean" },
    sourceContentLength: { type: "integer" },
    headingMatched: NULLABLE_STRING,
    headingOccurrence: NULLABLE_INT,
    headingLevel: NULLABLE_INT,
  },
  required: ["contentOffset", "contentLength", "totalContentLength", "contentTruncated", "sourceContentLength"],
};

const UPLOAD_URL_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    uploadUrl: { type: "string" },
    curlCommand: { type: "string" },
    expiresInSeconds: { type: "integer" },
  },
  required: ["uploadUrl", "curlCommand", "expiresInSeconds"],
};

export const TOOLS = [
  {
    name: "search_xwiki",
    title: "Search XWiki",
    description: "Search XWiki articles",
    annotations: { readOnlyHint: true, openWorldHint: false },
    outputSchema: SEARCH_OUTPUT_SCHEMA,
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query" },
        limit: { type: "number", description: "Max results (default 10)" },
        include_headings: {
          type: "boolean",
          description: "Include parsed page headings for each search result (default false)",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "get_xwiki_page",
    title: "Read XWiki page",
    description: "Get XWiki page content. The page body is returned in the field `page_content`.",
    annotations: { readOnlyHint: true, openWorldHint: false },
    outputSchema: PAGE_OUTPUT_SCHEMA,
    inputSchema: {
      type: "object",
      properties: {
        page_path: { type: "string", description: "Page path (e.g. Main.WebHome)" },
        include_content: {
          type: "boolean",
          description: "Whether to include page content in the response (default true)",
        },
        heading: {
          type: "string",
          description: "Optional heading name to extract a single section by heading title",
        },
        heading_occurrence: {
          type: "number",
          description: "Optional 1-based occurrence when the same heading appears multiple times (default 1)",
        },
        content_offset: {
          type: "number",
          description: "Optional character offset for partial content retrieval (default 0)",
        },
        content_length: {
          type: "number",
          description: "Optional maximum number of content characters to return",
        },
      },
      required: ["page_path"],
    },
  },
  {
    name: "create_xwiki_page",
    title: "Create or update XWiki page",
    description: "Create or update XWiki page",
    // Overwrites an existing page; the same call twice leaves the same page.
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    inputSchema: {
      type: "object",
      properties: {
        page_path: { type: "string", description: "Page path" },
        title: { type: "string", description: "Title" },
        content: {
          type: "string",
          description: "Page content in CommonMark Markdown syntax (this wiki's default document syntax)",
        },
      },
      required: ["page_path", "title", "content"],
    },
  },
  {
    name: "upload_xwiki_attachment",
    title: "Upload XWiki attachment from URL",
    // May replace an attachment of the same name; fetches from an arbitrary URL.
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    description:
      "Upload a file as an attachment to an XWiki page FROM A URL YOU ALREADY HAVE (e.g. a Jira attachment link, an email/Teams attachment link, or an intranet share URL) — the server fetches the bytes itself over HTTP(S), they never pass through you. Do NOT use this if the file only exists on your local machine with no existing URL for it; use `get_xwiki_upload_url` for that instead.",
    inputSchema: {
      type: "object",
      properties: {
        page_path: { type: "string", description: "Page path (e.g. Main.WebHome)" },
        filename: { type: "string", description: "Attachment filename, including extension (e.g. report.pdf)" },
        source_url: {
          type: "string",
          description: "HTTP(S) URL the server fetches the file from itself (bytes never pass through the calling client). Required.",
        },
        content_type: {
          type: "string",
          description: "MIME type of the file (default application/octet-stream)",
        },
      },
      required: ["page_path", "filename", "source_url"],
    },
  },
  {
    name: "get_xwiki_upload_url",
    title: "Get XWiki upload URL",
    // Mints a single-use URL; XWiki itself is not changed by this call.
    annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: false },
    outputSchema: UPLOAD_URL_OUTPUT_SCHEMA,
    description:
      "Get a short-lived (5 minute), single-use upload URL for attaching a file that exists ONLY on your local filesystem (no existing URL anywhere) to an XWiki page. This tool does not upload anything itself — it only issues the URL. You must then run the returned `curlCommand` yourself (e.g. via a shell/Bash tool), substituting in the real local file path, to `curl -T <local-file-path> \"<uploadUrl>\"` and send the bytes directly over HTTPS. Do NOT use this if you already have an http(s) URL for the file; use `upload_xwiki_attachment` with `source_url` instead.",
    inputSchema: {
      type: "object",
      properties: {
        page_path: { type: "string", description: "Page path (e.g. Main.WebHome)" },
        filename: { type: "string", description: "Attachment filename, including extension (e.g. report.pdf)" },
        content_type: {
          type: "string",
          description: "MIME type of the file (default application/octet-stream)",
        },
      },
      required: ["page_path", "filename"],
    },
  },
];

// CallToolResult with a text block only (create/upload results, errors).
const textResult = (text, isError = false) => (isError
  ? { content: [{ type: "text", text }], isError: true }
  : { content: [{ type: "text", text }] });

// CallToolResult with structuredContent plus the same JSON as text block (older clients).
// JSON round trip: undefined fields drop out of both exactly as JSON.stringify drops them.
function structuredResult(structured, textValue = structured) {
  return {
    content: [{ type: "text", text: JSON.stringify(textValue, null, 2) }],
    structuredContent: JSON.parse(JSON.stringify(structured)),
  };
}

// Renames the page body "content" → "page_content" and keeps the key order.
function pageResult(page) {
  return Object.fromEntries(Object.entries(page || {}).map(([k, v]) => [k === "content" ? "page_content" : k, v]));
}

// Returns a CallToolResult. Tool failures are results with isError: true; an XWikiAuthError
// propagates, because the /mcp handler ends the session or retries with a renewed token.
export async function callTool(name, args, sessionCtx, xwikiClient, toolConfig = {}) {
  try {
    if (name === "search_xwiki") {
      const { query, limit = 10, include_headings = false } = args;
      const results = await xwikiClient.search(query, limit, { includeHeadings: include_headings }, sessionCtx);
      return structuredResult({ results }, results);
    }
    if (name === "get_xwiki_page") {
      const {
        page_path,
        include_content = true,
        heading,
        heading_occurrence,
        content_offset = 0,
        content_length,
      } = args;
      const page = await xwikiClient.getPage(page_path, {
        includeContent: include_content,
        heading,
        headingOccurrence: heading_occurrence,
        contentOffset: content_offset,
        contentLength: content_length,
      }, sessionCtx);
      return structuredResult(pageResult(page));
    }
    if (name === "create_xwiki_page") {
      const { page_path, title, content } = args;
      const url = await xwikiClient.createPage(page_path, title, content, sessionCtx);
      return textResult(`Page created/updated: ${url}`);
    }
    if (name === "upload_xwiki_attachment") {
      const { page_path, filename, source_url, content_type } = args;
      const url = await xwikiClient.uploadAttachment(
        page_path,
        filename,
        { sourceUrl: source_url, contentType: content_type },
        sessionCtx,
      );
      return textResult(`Attachment uploaded: ${url}`);
    }
    if (name === "get_xwiki_upload_url") {
      const { page_path, filename, content_type } = args;
      const { token, payload } = mintUploadToken({
        sessionId: sessionCtx.sessionId,
        pagePath: page_path,
        filename,
        contentType: content_type,
        secret: toolConfig.sessionSecret,
      });
      const uploadUrl = `${toolConfig.mcpBaseUrl}/uploads/${token}`;
      return structuredResult({
        uploadUrl,
        curlCommand: `curl -T <PATH_PLACEHOLDER> "${uploadUrl}"`,
        expiresInSeconds: Math.round((payload.exp - Date.now()) / 1000),
      });
    }
    return textResult(`Unknown tool: ${name}`, true);
  } catch (e) {
    if (e instanceof XWikiAuthError) throw e;
    return textResult(`Error: ${e.message}`, true);
  }
}
