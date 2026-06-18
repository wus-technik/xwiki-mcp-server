import { XWikiAuthError } from "./xwiki-client.js";

export const TOOLS = [
  {
    name: "search_xwiki",
    description: "Search XWiki articles",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query" },
        limit: { type: "number", description: "Max results (default 10)" },
      },
      required: ["query"],
    },
  },
  {
    name: "get_xwiki_page",
    description: "Get XWiki page content",
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
    description: "Create or update XWiki page",
    inputSchema: {
      type: "object",
      properties: {
        page_path: { type: "string", description: "Page path" },
        title: { type: "string", description: "Title" },
        content: { type: "string", description: "Content in XWiki syntax" },
      },
      required: ["page_path", "title", "content"],
    },
  },
];

export async function callTool(name, args, sessionCtx, xwikiClient) {
  try {
    if (name === "search_xwiki") {
      const { query, limit = 10 } = args;
      const results = await xwikiClient.search(query, limit, sessionCtx);
      return JSON.stringify(results, null, 2);
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
      return JSON.stringify(page, null, 2);
    }
    if (name === "create_xwiki_page") {
      const { page_path, title, content } = args;
      const url = await xwikiClient.createPage(page_path, title, content, sessionCtx);
      return `Page created/updated: ${url}`;
    }
    return `Unknown tool: ${name}`;
  } catch (e) {
    if (e instanceof XWikiAuthError) throw e;
    return `Error: ${e.message}`;
  }
}
