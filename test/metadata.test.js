import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import express from "express";
import { mountMetadata, resourceMetadata, asMetadata, sendUnauthorized } from "../src/metadata.js";

const base = "https://xwiki.wus-technik.com/mcp";
const cfg = { mcpBaseUrl: base };

function makeApp() {
  const app = express();
  mountMetadata(app, cfg);
  app.get("/unauth", (_req, res) => sendUnauthorized(res, cfg, { error: "invalid_token", description: 'bad "x"\\y\r\nz' }));
  app.get("/unauth-bare", (_req, res) => sendUnauthorized(res, cfg, {}));
  return app;
}

for (const p of [
  "/.well-known/oauth-protected-resource",
  "/.well-known/oauth-protected-resource/mcp",
  "/mcp/.well-known/oauth-protected-resource",
]) {
  test(`resource metadata at ${p}`, async () => {
    const res = await request(makeApp()).get(p);
    assert.equal(res.status, 200);
    assert.equal(res.body.resource, base);
    assert.deepEqual(res.body.authorization_servers, [base]);
    assert.deepEqual(res.body.scopes_supported, ["xwiki"]);
    assert.deepEqual(res.body.bearer_methods_supported, ["header"]);
  });
}

for (const p of [
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-authorization-server/mcp",
  "/mcp/.well-known/oauth-authorization-server",
  "/.well-known/openid-configuration/mcp",
  "/mcp/.well-known/openid-configuration",
]) {
  test(`AS metadata at ${p}`, async () => {
    const res = await request(makeApp()).get(p);
    assert.equal(res.status, 200);
    assert.equal(res.body.issuer, base);
    assert.ok(res.body.grant_types_supported.includes("refresh_token"));
    assert.deepEqual(res.body, asMetadata(cfg));
  });
}

test("AS metadata endpoints and capabilities", () => {
  const m = asMetadata(cfg);
  assert.equal(m.authorization_endpoint, `${base}/oauth/authorize`);
  assert.equal(m.token_endpoint, `${base}/oauth/token`);
  assert.equal(m.registration_endpoint, `${base}/oauth/register`);
  assert.equal(m.revocation_endpoint, `${base}/oauth/revoke`);
  assert.deepEqual(m.grant_types_supported, ["authorization_code", "refresh_token"]);
  assert.deepEqual(m.token_endpoint_auth_methods_supported, ["none"]);
  assert.deepEqual(m.revocation_endpoint_auth_methods_supported, ["none"]);
  assert.deepEqual(m.scopes_supported, ["xwiki"]);
  assert.deepEqual(resourceMetadata(cfg).resource, base);
});

test("sendUnauthorized sets challenge with error and escaped description", async () => {
  const res = await request(makeApp()).get("/unauth");
  assert.equal(res.status, 401);
  const h = res.headers["www-authenticate"];
  assert.ok(h.startsWith(`Bearer realm="${base}", resource_metadata="${base}/.well-known/oauth-protected-resource"`));
  assert.ok(h.includes(', error="invalid_token"'));
  assert.ok(h.includes(', error_description="bad \\"x\\"\\\\yz"'));
  assert.equal(res.body.error, "invalid_token");
});

test("sendUnauthorized without args", async () => {
  const res = await request(makeApp()).get("/unauth-bare");
  assert.equal(res.status, 401);
  assert.equal(res.headers["www-authenticate"], `Bearer realm="${base}", resource_metadata="${base}/.well-known/oauth-protected-resource"`);
  assert.deepEqual(res.body, { error: "unauthorized" });
});
