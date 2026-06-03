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
      const { page_path } = args;
      const page = await xwikiClient.getPage(page_path, sessionCtx);
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
