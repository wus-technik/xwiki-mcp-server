import { createApp } from "./src/app.js";
import { PORT, SESSION_FILE } from "./src/config.js";
import { configureSessionPersistence } from "./src/session-store.js";
import { startKeepAlive } from "./src/keepalive.js";

configureSessionPersistence(SESSION_FILE);

const app = createApp();
startKeepAlive({ xwikiClient: app.locals.xwikiClient });
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP XWiki on http://0.0.0.0:${PORT}`);
});
