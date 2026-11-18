// End-to-end: the real modules (oauth, sessions, authentik, xwiki-tokens, xwiki-client,
// store) against in-process fakes of Authentik and XWiki on 127.0.0.1. The test plays the
// browser (cookie jar, redirects) and the MCP client (DCR, PKCE, token, /mcp calls).
import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { createApp } from "../src/app.js";
import { openStore } from "../src/store.js";
import { runCleanups } from "../src/sessions.js";
import { fakeXWiki } from "./helpers/fake-xwiki.js";
import { fakeAuthentik } from "./helpers/fake-authentik.js";

const BASE = "https://xwiki.example.com/mcp";
const ORIGIN = new URL(BASE).origin;
const CLIENT_CB = "https://claude.ai/api/mcp/auth_callback";
const USERNAME = "zurman.o";
const XWIKI_USER = "xwiki:XWiki.zurmano";
const PAGES = [
  { space: "Main", pageName: "Handbuch", title: "Handbuch MCP", content: "# Handbuch\n\nVerbinden mit XWiki." },
];

async function setup(t) {
  const xw = await fakeXWiki({ pages: PAGES });
  const ak = await fakeAuthentik({
    clientId: "mcp-client",
    clientSecret: "mcp-client-secret",
    users: { [USERNAME]: { sub: "a".repeat(64), groups: ["xwiki_redaktion"] } },
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "e2e-"));
  const store = openStore({ file: path.join(dir, "store.json"), key: randomBytes(32) });
  const app = createApp({
    sessionSecret: randomBytes(32).toString("base64"),
    mcpBaseUrl: BASE,
    store,
    xwikiUrl: xw.url,
    xwikiPublicUrl: "https://xwiki.example.com",
    xwikiWiki: "xwiki",
    authentikIssuer: ak.issuer,
    authentikAppSlug: "xwiki-mcp",
    oauthClientId: "mcp-client",
    oauthClientSecret: "mcp-client-secret",
    oauthRedirectUri: `${BASE}/oauth/callback`,
    allowedGroups: ["AdminsIT", "xwiki_redaktion"],
    extraRedirectUris: [],
    extraOrigins: [],
    authDebug: false,
  });
  t.after(async () => {
    await Promise.all([xw.close(), ak.close()]);
    fs.rmSync(dir, { recursive: true, force: true });
  });
  // The user is logged in at the SSO in the browser (Authentik and, via OIDC, XWiki).
  ak.login(USERNAME);
  xw.ssoLogin(XWIKI_USER);
  return { xw, ak, app, store };
}

// Minimal browser cookie jar for the shared origin of MCP server and XWiki.
function cookieJar() {
  const jar = new Map();
  return {
    absorb(res) {
      for (const raw of res.headers["set-cookie"] || []) {
        const [pair, ...attrs] = raw.split(";").map((s) => s.trim());
        const i = pair.indexOf("=");
        const name = pair.slice(0, i);
        const value = pair.slice(i + 1);
        const expired = attrs.some((a) => /^max-age=0$/i.test(a) || (/^expires=/i.test(a) && Date.parse(a.slice(8)) < Date.now()));
        if (expired || value === "") jar.delete(name);
        else jar.set(name, value);
      }
    },
    header: () => [...jar].map(([k, v]) => `${k}=${v}`).join("; "),
    has: (name) => jar.has(name),
  };
}

const field = (html, name) => new RegExp(`name="${name}" value="([^"]*)"`).exec(html)?.[1];

// Full login as an MCP client would drive it; returns the token response.
async function login({ app, xw }) {
  // DCR
  const reg = await request(app).post("/mcp/oauth/register").send({ client_name: "Claude", redirect_uris: [CLIENT_CB] });
  assert.equal(reg.status, 201, reg.text);
  const clientId = reg.body.client_id;

  // PKCE + authorize
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const browser = cookieJar();
  const auth = await request(app).get("/mcp/oauth/authorize").query({
    response_type: "code", client_id: clientId, redirect_uri: CLIENT_CB, state: "client-state",
    code_challenge: challenge, code_challenge_method: "S256", resource: BASE,
  });
  assert.equal(auth.status, 302, auth.text);
  browser.absorb(auth);
  assert.ok(browser.has("xmcp_flow"));

  // Authentik (SSO session present) → back to /mcp/oauth/callback with a code
  const akRes = await fetch(auth.headers.location, { redirect: "manual" });
  assert.equal(akRes.status, 302);
  const cbUrl = new URL(akRes.headers.get("location"));
  assert.equal(`${cbUrl.origin}${cbUrl.pathname}`, `${BASE}/oauth/callback`);
  const cb = await request(app).get(cbUrl.pathname + cbUrl.search).set("Cookie", browser.header());
  assert.equal(cb.status, 302, cb.text);

  // XWiki login (same origin as the MCP server) → session cookie → xredirect to /complete
  const xwLogin = new URL(cb.headers.location);
  assert.equal(xwLogin.origin, ORIGIN);
  assert.equal(xwLogin.pathname, "/bin/login/XWiki/XWikiLogin");
  const xl = await request(xw.url).get(xwLogin.pathname + xwLogin.search).redirects(0);
  assert.equal(xl.status, 302);
  browser.absorb(xl);
  assert.ok(browser.has("JSESSIONID"));
  const completePath = xl.headers.location;
  assert.match(completePath, /^\/mcp\/oauth\/complete\?t=/);

  // First login of this user with this client: consent page
  const complete = await request(app).get(completePath).set("Cookie", browser.header());
  assert.equal(complete.status, 200, complete.text);
  assert.match(complete.text, /Zugriff auf XWiki erlauben\?/);
  const consent = await request(app).post("/mcp/oauth/consent").type("form").set("Cookie", browser.header())
    .send({ t: field(complete.text, "t"), csrf: field(complete.text, "csrf"), action: "allow" });
  assert.equal(consent.status, 302, consent.text);
  const back = new URL(consent.headers.location);
  assert.equal(`${back.origin}${back.pathname}`, CLIENT_CB);
  assert.equal(back.searchParams.get("state"), "client-state");

  // Code → tokens
  const tok = await request(app).post("/mcp/oauth/token").type("form").send({
    grant_type: "authorization_code", code: back.searchParams.get("code"), code_verifier: verifier,
    client_id: clientId, redirect_uri: CLIENT_CB, resource: BASE,
  });
  assert.equal(tok.status, 200, tok.text);
  assert.ok(tok.body.access_token && tok.body.refresh_token);
  return { clientId, tokens: tok.body, browser };
}

function search(app, accessToken) {
  return request(app).post("/mcp").set("Authorization", `Bearer ${accessToken}`).send({
    jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search_xwiki", arguments: { query: "handbuch" } },
  });
}

function assertSearchOk(res) {
  assert.equal(res.status, 200, res.text);
  assert.equal(res.body.error, undefined);
  const results = JSON.parse(res.body.result.content[0].text);
  assert.deepEqual(results.map((r) => r.title), ["Handbuch MCP"]);
  assert.equal(results[0].url, "https://xwiki.example.com/bin/view/Main/Handbuch");
}

function refresh(app, clientId, refreshToken) {
  return request(app).post("/mcp/oauth/token").type("form").send({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId });
}

// The one consent created by the login (name "xwiki-mcp – <client> – <date>").
function mcpConsents(xw) {
  return xw.consents(XWIKI_USER).filter((c) => c.name.startsWith("xwiki-mcp – "));
}

test("full flow survives xwiki restart", async (t) => {
  const ctx = await setup(t);
  const { app, xw, ak, store } = ctx;
  const { clientId, tokens, browser } = await login(ctx);

  const created = mcpConsents(xw);
  assert.equal(created.length, 1);
  assert.match(created[0].name, /^xwiki-mcp – Claude – \d{4}-\d{2}-\d{2}$/);
  const { consentId } = created[0];
  // The store owns exactly this consent; no pending-create marker is left.
  const state = store.read();
  assert.deepEqual(Object.values(state.sessions).map((s) => s.consentId), [consentId]);
  assert.deepEqual(state.cleanups, {});

  // Tool call: XWiki is reached with the consent token, never with the browser cookie.
  const before = xw.requests.length;
  assertSearchOk(await search(app, tokens.access_token));
  const toolRequests = xw.requests.slice(before);
  assert.ok(toolRequests.length > 0);
  assert.ok(toolRequests.every((r) => r.auth === "bearer"));

  // XWiki restart (Review Focus 3): browser cookies die, the bearer stays valid.
  xw.restart();
  const stale = await fetch(`${xw.url}/rest/`, { headers: { Cookie: browser.header() } });
  assert.equal(stale.status, 200);
  assert.equal(stale.headers.get("XWiki-User"), null, "the old browser cookie is dead after the restart");
  assertSearchOk(await search(app, tokens.access_token));

  // Refresh: new pair, both usable.
  const r1 = await refresh(app, clientId, tokens.refresh_token);
  assert.equal(r1.status, 200, r1.text);
  assert.notEqual(r1.body.refresh_token, tokens.refresh_token);
  // (The access token may be byte-identical within the same second: same claims, same iat.)
  assert.ok(r1.body.access_token);
  assertSearchOk(await search(app, r1.body.access_token));
  assert.equal(mcpConsents(xw).length, 1, "no XWiki token renewal (90 days left)");

  // User loses the allowed groups in Authentik: next refresh ends the session …
  ak.removeFromGroups(USERNAME);
  const r2 = await refresh(app, clientId, r1.body.refresh_token);
  assert.equal(r2.status, 400);
  assert.equal(r2.body.error, "invalid_grant");
  // … and the session's XWiki consent is deleted (background cleanup, awaited here).
  await runCleanups(app.locals.deps);
  assert.deepEqual(mcpConsents(xw), []);
  assert.deepEqual(store.read().sessions, {});
  assert.deepEqual(store.read().cleanups, {});
  const after = await search(app, r1.body.access_token);
  assert.equal(after.status, 401);
});

test("revoke deletes xwiki token", async (t) => {
  const ctx = await setup(t);
  const { app, xw, store } = ctx;
  const { tokens } = await login(ctx);
  assert.equal(mcpConsents(xw).length, 1);

  const rev = await request(app).post("/mcp/oauth/revoke").type("form").send({ token: tokens.refresh_token, token_type_hint: "refresh_token" });
  assert.equal(rev.status, 200, rev.text);
  await runCleanups(app.locals.deps);

  assert.deepEqual(mcpConsents(xw), []);
  assert.deepEqual(store.read().sessions, {});
  assert.deepEqual(store.read().cleanups, {});
  assert.equal((await search(app, tokens.access_token)).status, 401);
});

test("deactivated authentik user: refresh fails and the xwiki token is deleted", async (t) => {
  const ctx = await setup(t);
  const { app, xw, ak } = ctx;
  const { clientId, tokens } = await login(ctx);
  assert.equal(mcpConsents(xw).length, 1);

  ak.deactivate(USERNAME);
  const r = await refresh(app, clientId, tokens.refresh_token);
  assert.equal(r.status, 400);
  assert.equal(r.body.error, "invalid_grant");
  await runCleanups(app.locals.deps);
  assert.deepEqual(mcpConsents(xw), []);
});
