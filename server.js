import { createApp } from "./src/app.js";
import { loadConfig, validateConfig } from "./src/config.js";
import { configureSessionPersistence } from "./src/session-store.js";
import { startKeepAlive } from "./src/keepalive.js";
import { openStore } from "./src/store.js";

const cfg = loadConfig();
try {
  validateConfig(cfg);
} catch (e) {
  console.error(`[config] ${e.message}`);
  process.exit(1);
}

let store;
try {
  store = openStore({ file: cfg.storeFile, key: cfg.tokenEncKey });
} catch (e) {
  console.error(`[store] cannot open STORE_FILE ${cfg.storeFile}: ${e.message}`);
  process.exit(1);
}

// Legacy session store stays memory-only (STORE_FILE belongs to the encrypted store);
// removed together with the legacy store in a later task.
configureSessionPersistence();

const app = createApp({ ...cfg, store });
startKeepAlive({ xwikiClient: app.locals.xwikiClient });
app.listen(cfg.port, "0.0.0.0", () => {
  console.log(`MCP XWiki on http://0.0.0.0:${cfg.port}`);
});
