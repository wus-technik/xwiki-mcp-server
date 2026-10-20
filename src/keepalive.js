import { listSessions } from "./session-store.js";

// Tomcat drops an idle XWiki session after 30 minutes, which used to force a browser re-login
// although the MCP token was valid for 7 days. Touching each captured session well inside that
// window keeps it alive for the life of the MCP session.
export const KEEPALIVE_INTERVAL_MS = 10 * 60 * 1000;

export async function runKeepAlive({ xwikiClient }) {
  for (const session of listSessions()) {
    try {
      const status = await xwikiClient.touchSession(session);
      if (status >= 400) console.warn(`[keepalive] user=${session.userId} XWiki answered ${status}`);
    } catch (e) {
      console.warn(`[keepalive] user=${session.userId} failed: ${e.message}`);
    }
  }
}

export function startKeepAlive({ xwikiClient, intervalMs = KEEPALIVE_INTERVAL_MS }) {
  const timer = setInterval(() => runKeepAlive({ xwikiClient }), intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
