import { TOOLS, callTool } from "./tools.js";

const SERVER_INFO = { name: "xwiki-mcp", version: "2.0.0" };
// Newest first; the first entry is the fallback for unknown requested versions.
export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

export async function handleMcpRequest(method, params, sessionCtx, xwikiClient, toolConfig = {}) {
  if (method === "initialize") {
    const requested = params?.protocolVersion;
    return {
      protocolVersion: SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : SUPPORTED_PROTOCOL_VERSIONS[0],
      serverInfo: SERVER_INFO,
      capabilities: { tools: {} },
    };
  }
  if (method === "tools/list") {
    return { tools: TOOLS };
  }
  if (method === "tools/call") {
    const { name, arguments: args } = params || {};
    const text = await callTool(name, args || {}, sessionCtx, xwikiClient, toolConfig);
    return { content: [{ type: "text", text }] };
  }
  if (method === "notifications/initialized") {
    return null;
  }
  throw Object.assign(new Error("Method not found"), { code: -32601 });
}
