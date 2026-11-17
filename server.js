import { createApp } from "./src/app.js";
import { loadConfig, validateConfig } from "./src/config.js";
import { configureSessionPersistence } from "./src/session-store.js";
import { startKeepAlive } from "./src/keepalive.js";

const cfg = loadConfig();
try {
  validateConfig(cfg);
} catch (e) {
  console.error(`[config] ${e.message}`);
  process.exit(1);
}

configureSessionPersistence(cfg.storeFile);

const app = createApp(cfg);
startKeepAlive({ xwikiClient: app.locals.xwikiClient });
app.listen(cfg.port, "0.0.0.0", () => {
  console.log(`MCP XWiki on http://0.0.0.0:${cfg.port}`);
});
