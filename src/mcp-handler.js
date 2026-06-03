import { TOOLS, callTool } from "./tools.js";

const SERVER_INFO = { name: "xwiki-mcp", version: "2.0.0" };
const PROTOCOL_VERSION = "2024-11-05";

export async function handleMcpRequest(method, params, sessionCtx, xwikiClient) {
  if (method === "initialize") {
    return {
      protocolVersion: PROTOCOL_VERSION,
      serverInfo: SERVER_INFO,
      capabilities: { tools: {} },
    };
  }
  if (method === "tools/list") {
    return { tools: TOOLS };
  }
  if (method === "tools/call") {
    const { name, arguments: args } = params || {};
    const text = await callTool(name, args || {}, sessionCtx, xwikiClient);
    return { content: [{ type: "text", text }] };
  }
  if (method === "notifications/initialized") {
    return null;
  }
  throw Object.assign(new Error("Method not found"), { code: -32601 });
}
