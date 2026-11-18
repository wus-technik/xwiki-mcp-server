import { createApp } from "./src/app.js";
import { loadConfig, validateConfig } from "./src/config.js";
import { openStore } from "./src/store.js";
import { startBackground } from "./src/sessions.js";

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

const app = createApp({ ...cfg, store });
// Daily reconcile with Authentik (first run after 5 min) and hourly XWiki token cleanups.
startBackground(app.locals.deps);
app.listen(cfg.port, "0.0.0.0", () => {
  console.log(`MCP XWiki on http://0.0.0.0:${cfg.port}`);
});
