import { createApp } from "./src/app.js";
import { PORT } from "./src/config.js";

const app = createApp();
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP XWiki on http://0.0.0.0:${PORT}`);
});
