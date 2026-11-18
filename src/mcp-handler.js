import { TOOLS, callTool } from "./tools.js";

const SERVER_INFO = { name: "xwiki-mcp", version: "2.0.0" };
// Newest first.
export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
// Answered in `initialize` when the client requests a version we do not support (the spec:
// the server SHOULD answer with the latest version it supports).
export const LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];

// MCP-Protocol-Version header check. Accepted: a supported version, or a well-formed date
// version newer than our newest one (claude.ai and openai-mcp send e.g. 2026-07-28 on
// follow-up requests); such a newer version is treated as LATEST_PROTOCOL_VERSION.
// Unknown older versions and malformed values are refused.
export function isAcceptedProtocolVersionHeader(version) {
  if (SUPPORTED_PROTOCOL_VERSIONS.includes(version)) return true;
  return typeof version === "string" && /^\d{4}-\d{2}-\d{2}$/.test(version) && version > LATEST_PROTOCOL_VERSION;
}

export async function handleMcpRequest(method, params, sessionCtx, xwikiClient, toolConfig = {}) {
  if (method === "initialize") {
    const requested = params?.protocolVersion;
    return {
      protocolVersion: SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : LATEST_PROTOCOL_VERSION,
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
