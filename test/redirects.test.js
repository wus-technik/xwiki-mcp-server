import { test } from "node:test";
import assert from "node:assert/strict";
import { isAllowedRedirect, redirectMatches, isAllowedOrigin } from "../src/redirects.js";

test("isAllowedRedirect accepts loopback and known hosts", () => {
  for (const u of [
    "http://localhost:3118/callback",
    "http://127.0.0.1:50000/cb",
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
  ]) assert.equal(isAllowedRedirect(u, []), true, u);
});

test("isAllowedRedirect rejects others", () => {
  for (const u of [
    "https://evil.example/cb",
    "http://localhost.evil.example/cb",
    "https://claude.ai/api/mcp/auth_callback/../x",
    "https://claude.ai/api/mcp/auth_callback#frag",
    "https://user@claude.ai/api/mcp/auth_callback",
    "https://localhost:3000/cb",
    "javascript:alert(1)",
    "http://localhost:3000/a/%2e%2e/b",
    "http://@localhost:3/cb",
    "http://:@localhost:3/cb",
    "HTTP://LOCALHOST:4/cb",
    "http://127.1:4/cb",
    "http://Localhost:4/cb",
    "",
    null,
  ]) assert.equal(isAllowedRedirect(u, []), false, String(u));
});

test("extra redirect URIs match exactly", () => {
  const extra = ["https://app.example/cb"];
  assert.equal(isAllowedRedirect("https://app.example/cb", extra), true);
  assert.equal(isAllowedRedirect("https://app.example/cb2", extra), false);
});

test("redirectMatches: loopback ignores only the port", () => {
  const reg = ["http://localhost:3118/callback"];
  assert.equal(redirectMatches(reg, "http://localhost:4000/callback"), true);
  assert.equal(redirectMatches(reg, "http://localhost:4000/other"), false);
  assert.equal(redirectMatches(reg, "http://127.0.0.1:3118/callback"), false);
  assert.equal(redirectMatches(reg, "http://localhost:4000/callback?x=1"), false);
  assert.equal(redirectMatches(reg, "https://localhost:4000/callback"), false);
});

test("redirectMatches: loopback compares raw components except the port", () => {
  const reg = ["http://localhost:3/cb"];
  assert.equal(redirectMatches(reg, "HTTP://LOCALHOST:4/cb"), false);
  assert.equal(redirectMatches(reg, "http://localhost:4/cb?"), false);
  assert.equal(redirectMatches(["http://127.0.0.1:3/cb"], "http://127.1:4/cb"), false);
  assert.equal(redirectMatches(["http://localhost:4/"], "http://localhost:3"), false);
  assert.equal(redirectMatches(["http://localhost:4/"], "http://localhost/"), true);
  assert.equal(redirectMatches(reg, "http://@localhost:4/cb"), false);
});

test("redirectMatches: non-loopback is exact", () => {
  const reg = ["https://claude.ai/api/mcp/auth_callback"];
  assert.equal(redirectMatches(reg, "https://claude.ai/api/mcp/auth_callback"), true);
  assert.equal(redirectMatches(reg, "https://claude.ai/api/mcp/auth_callback/"), false);
  assert.equal(redirectMatches(reg, "https://claude.ai:444/api/mcp/auth_callback"), false);
  assert.equal(redirectMatches(reg, "https://claude.ai/api/mcp/auth_callback/../x"), false);
});

test("isAllowedOrigin", () => {
  const base = "https://xwiki.example.com/mcp";
  assert.equal(isAllowedOrigin("https://claude.ai", base, []), true);
  assert.equal(isAllowedOrigin("https://chatgpt.com", base, []), true);
  assert.equal(isAllowedOrigin("https://xwiki.example.com", base, []), true);
  assert.equal(isAllowedOrigin("https://evil.example", base, []), false);
  assert.equal(isAllowedOrigin("https://claude.ai:8443", base, []), false);
  assert.equal(isAllowedOrigin("https://x.example", base, ["https://x.example"]), true);
});
