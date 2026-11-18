import test from "node:test";
import assert from "node:assert/strict";
import { loadConfig, validateConfig } from "../src/config.js";

const base = {
  PORT: "3000",
  XWIKI_URL: "http://xwiki:8080/",
  XWIKI_WIKI: "xwiki",
  OAUTH_CLIENT_ID: "cid",
  OAUTH_CLIENT_SECRET: "csecret",
  OAUTH_REDIRECT_URI: "https://x.example/mcp/oauth/callback",
  AUTHENTIK_ISSUER: "https://auth.example/",
  MCP_BASE_URL: "https://x.example/mcp/",
  SESSION_SECRET: "s".repeat(32),
  TOKEN_ENC_KEY: Buffer.alloc(32, 1).toString("base64"),
  STORE_FILE: "/tmp/x.json",
};

test("gueltige Konfiguration wird akzeptiert", () => {
  const cfg = loadConfig(base);
  assert.doesNotThrow(() => validateConfig(cfg));
  assert.equal(cfg.xwikiUrl, "http://xwiki:8080");
  assert.equal(cfg.mcpBaseUrl, "https://x.example/mcp");
  assert.equal(cfg.xwikiPublicUrl, "http://xwiki:8080");
  assert.equal(cfg.tokenEncKey.length, 32);
});
test("validateConfig lehnt kurzes SESSION_SECRET ab", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, SESSION_SECRET: "kurz" })), /SESSION_SECRET/);
});
test("validateConfig lehnt fehlenden TOKEN_ENC_KEY ab", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, TOKEN_ENC_KEY: "" })), /TOKEN_ENC_KEY/);
});
test("validateConfig lehnt TOKEN_ENC_KEY ungleich 32 Byte ab", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, TOKEN_ENC_KEY: Buffer.alloc(16).toString("base64") })), /32/);
});
test("ALLOWED_GROUPS hat den Default AdminsIT,xwiki_redaktion", () => {
  assert.deepEqual(loadConfig(base).allowedGroups, ["AdminsIT", "xwiki_redaktion"]);
});
test("Listen-Variablen werden an Kommas getrennt", () => {
  const cfg = loadConfig({ ...base, ALLOWED_GROUPS: "A, B", EXTRA_REDIRECT_URIS: "http://a/cb,http://b/cb", EXTRA_ORIGINS: "https://o" });
  assert.deepEqual(cfg.allowedGroups, ["A", "B"]);
  assert.deepEqual(cfg.extraRedirectUris, ["http://a/cb", "http://b/cb"]);
  assert.deepEqual(cfg.extraOrigins, ["https://o"]);
});
test("STORE_FILE ist Pflicht", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, STORE_FILE: "" })), /STORE_FILE/);
});
test("TLS-Bypass in Produktion wird abgelehnt", () => {
  const cfg = loadConfig({ ...base, NODE_ENV: "production", NODE_TLS_REJECT_UNAUTHORIZED: "0" });
  assert.throws(() => validateConfig(cfg), /NODE_TLS_REJECT_UNAUTHORIZED/);
});
const k = Buffer.alloc(32, 1).toString("base64");
test("TOKEN_ENC_KEY mit angehaengtem Muell wird abgelehnt", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, TOKEN_ENC_KEY: k + "!!" })), /TOKEN_ENC_KEY/);
});
test("TOKEN_ENC_KEY mit ungueltigem Zeichen wird abgelehnt", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, TOKEN_ENC_KEY: k.slice(0, 10) + "!" + k.slice(11) })), /TOKEN_ENC_KEY/);
});
test("SESSION_SECRET aus Leerzeichen wird abgelehnt", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, SESSION_SECRET: " ".repeat(32) })), /SESSION_SECRET/);
});
test("STORE_FILE aus Leerzeichen gilt als fehlend", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, STORE_FILE: "   " })), /STORE_FILE/);
});
test("NODE_ENV mit Leerraum umgeht den TLS-Produktionsschutz nicht", () => {
  const cfg = loadConfig({ ...base, NODE_ENV: "production ", NODE_TLS_REJECT_UNAUTHORIZED: "0" });
  assert.throws(() => validateConfig(cfg), /NODE_TLS_REJECT_UNAUTHORIZED/);
});

test("authentikAppSlug: Default xwiki-mcp, Env getrimmt", () => {
  assert.equal(loadConfig(base).authentikAppSlug, "xwiki-mcp");
  assert.equal(loadConfig({ ...base, AUTHENTIK_APP_SLUG: "  other-app " }).authentikAppSlug, "other-app");
});
