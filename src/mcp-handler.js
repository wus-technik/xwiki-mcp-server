import { TOOLS, callTool } from "./tools.js";

const SERVER_INFO = { name: "xwiki-mcp", version: "2.0.0" };
// Newest first. The order carries no meaning for negotiation: the fallback is explicit.
export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
// Answered in `initialize` when the client requests a version we do not support.
export const FALLBACK_PROTOCOL_VERSION = "2025-06-18";

export async function handleMcpRequest(method, params, sessionCtx, xwikiClient, toolConfig = {}) {
  if (method === "initialize") {
    const requested = params?.protocolVersion;
    return {
      protocolVersion: SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : FALLBACK_PROTOCOL_VERSION,
      serverInfo: SERVER_INFO,
      capabilities: { tools: {} },
    };
  }
  if (method === "tools/list") {
    return { tools: TOOLS };
  }
  if (method === "tools/call") {
    const { name, arguments: args } = params || {};
    return callTool(name, args || {}, sessionCtx, xwikiClient, toolConfig);
  }
  if (method === "notifications/initialized") {
    return null;
  }
  throw Object.assign(new Error("Method not found"), { code: -32601 });
}
