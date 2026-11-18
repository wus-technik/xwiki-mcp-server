import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApp } from "../src/app.js";
import { openStore } from "../src/store.js";
import { createSession } from "../src/sessions.js";
import { AuthentikRejected } from "../src/authentik.js";
import { XWikiTokenError } from "../src/xwiki-tokens.js";

const KEY = Buffer.alloc(32, 7);
const SECRET = "test-secret-32-chars-minimum-pad";
const BASE = "https://xwiki.example.com/mcp";
const DAY = 86400000;
const T0 = Date.UTC(2026, 10, 18, 9, 0, 0);
const USER = "xwiki:XWiki.maxmustermann";
const CID = "client-1";
const CID_LOCAL = "client-local";
const CLAUDE_CB = "https://claude.ai/api/mcp/auth_callback";
const LOCAL_CB = "http://localhost/cb?a=1";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

function tmpStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "login-"));
  const file = path.join(dir, "s.json");
  return { file, store: openStore({ file, key: KEY }) };
}

async function setup(opts = {}) {
  const { file, store } = tmpStore();
  await store.mutate((s) => {
    s.clients[CID] = { clientId: CID, clientName: "Claude <b>", redirectUris: [CLAUDE_CB], createdAt: 1, lastUsedAt: 1 };
    s.clients[CID_LOCAL] = { clientId: CID_LOCAL, clientName: "Codex", redirectUris: [LOCAL_CB], createdAt: 1, lastUsedAt: 1 };
    if (opts.seed) opts.seed(s);
  });
  const clock = { now: T0 };
  const calls = { exchange: [], checkUser: [], whoami: [], createToken: [], find: [], deleteToken: [] };
  let tokenN = 0;
  const authentik = {
    authorizeUrl: ({ state, nonce }) => `https://auth.example.com/application/o/authorize/?state=${state}&nonce=${nonce}`,
    exchangeCode: async (code, nonce) => {
      calls.exchange.push({ code, nonce });
      return { sub: "sub-1", username: "max.mustermann", refreshToken: "AK-REFRESH-SECRET", accessToken: "AK-ACCESS-SECRET" };
    },
    checkUser: async (at) => {
      calls.checkUser.push(at);
      if (opts.checkUser) await opts.checkUser(at);
    },
    refresh: async () => { throw new Error("not used"); },
  };
  let whoamiImpl = null;
  const xwikiTokens = {
    whoami: async (auth) => {
      calls.whoami.push(auth);
      if (whoamiImpl) return whoamiImpl(auth);
      return "whoami" in opts ? opts.whoami : USER;
    },
    createToken: async (auth, args) => {
      calls.createToken.push({ auth, args });
      if (opts.createToken) return opts.createToken(auth, args);
      tokenN += 1;
      return { token: `XW-TOKEN-SECRET-${tokenN}`, consentId: `${USER}^XWiki.OIDC.ConsentClass[${tokenN}]`, expiresAt: clock.now + 90 * DAY };
    },
    findTokensByPrefix: async (auth, xwikiUser, prefix) => {
      calls.find.push({ auth, xwikiUser, prefix });
      if (opts.findTokensByPrefix) return opts.findTokensByPrefix(auth, xwikiUser, prefix);
      return [];
    },
    deleteToken: async (auth, target) => {
      calls.deleteToken.push({ auth, target });
      return "deleted";
    },
  };
  const app = createApp({
    sessionSecret: SECRET,
    mcpBaseUrl: BASE,
    store,
    authentik,
    xwikiTokens,
    now: () => clock.now,
    extraRedirectUris: [],
    authDebug: !!opts.authDebug,
  });
  return { app, store, file, calls, clock, setWhoami: (fn) => { whoamiImpl = fn; } };
}

function authorizeQuery(over = {}) {
  return {
    response_type: "code",
    client_id: CID,
    redirect_uri: CLAUDE_CB,
    state: "client-state",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    ...over,
  };
}

function flowCookie(res) {
  const raw = (res.headers["set-cookie"] || []).find((c) => c.startsWith("xmcp_flow="));
  return raw ? raw.split(";")[0] : null;
}

function assertFlowHeaders(res) {
  assert.equal(res.headers["referrer-policy"], "no-referrer");
  assert.match(res.headers["cache-control"] || "", /no-store/);
}

// Runs /authorize → callback → complete; returns the complete response plus context.
async function toComplete(ctx, over = {}, { url = "/authorize" } = {}) {
  const a = await request(ctx.app).get(url).query(authorizeQuery(over));
  assert.equal(a.status, 302, a.text);
  const flow = flowCookie(a);
  const state = new URL(a.headers.location).searchParams.get("state");
  const cb = await request(ctx.app).get("/mcp/oauth/callback").query({ code: "ak-code", state }).set("Cookie", flow);
  assert.equal(cb.status, 302, cb.text);
  const loc = new URL(cb.headers.location);
  const completePath = loc.searchParams.get("xredirect");
  const cookie = `${flow}; JSESSIONID=xw-session-secret`;
  const res = await request(ctx.app).get(completePath).set("Cookie", cookie);
  const t = new URL(completePath, "https://x").searchParams.get("t");
  return { res, cookie, t, flow };
}

function consentFields(html) {
  const field = (name) => {
    const m = new RegExp(`name="${name}" value="([^"]*)"`).exec(html);
    return m && m[1];
  };
  return { t: field("t"), csrf: field("csrf") };
}

async function fullLogin(ctx, over = {}) {
  const c = await toComplete(ctx, over);
  if (c.res.status !== 200) return c.res;
  const f = consentFields(c.res.text);
  return request(ctx.app).post("/mcp/oauth/consent").type("form").set("Cookie", c.cookie)
    .send({ t: f.t, csrf: f.csrf, action: "allow" });
}

test("/authorize: unregistrierte client_id -> 400", async () => {
  const ctx = await setup();
  const res = await request(ctx.app).get("/authorize").query(authorizeQuery({ client_id: "nope" }));
  assert.equal(res.status, 400);
  assert.equal(res.headers.location, undefined);
  assertFlowHeaders(res);
});

test("/authorize: nicht passende redirect_uri -> 400", async () => {
  const ctx = await setup();
  for (const redirect_uri of ["https://evil.example/cb", "https://claude.ai/api/mcp/auth_callback/x", "http://localhost/cb"]) {
    const res = await request(ctx.app).get("/mcp/oauth/authorize").query(authorizeQuery({ redirect_uri }));
    assert.equal(res.status, 400, redirect_uri);
    assert.equal(res.headers.location, undefined);
  }
});

test("/authorize: resource ungleich mcpBaseUrl -> 400 invalid_target", async () => {
  const ctx = await setup();
  const res = await request(ctx.app).get("/authorize").query(authorizeQuery({ resource: "https://other" }));
  assert.equal(res.status, 400);
  assert.match(res.text, /invalid_target/);
});

test("/authorize: fehlende PKCE/state/response_type -> 400", async () => {
  const ctx = await setup();
  for (const over of [{ response_type: "token" }, { code_challenge_method: "plain" }, { state: undefined }, { code_challenge: undefined }, { code_challenge: "short" }]) {
    const q = authorizeQuery(over);
    for (const k of Object.keys(q)) if (q[k] === undefined) delete q[k];
    const res = await request(ctx.app).get("/authorize").query(q);
    assert.equal(res.status, 400, JSON.stringify(over));
  }
});

test("/authorize: setzt Flow-Cookie und leitet zu Authentik", async () => {
  const ctx = await setup();
  for (const url of ["/authorize", "/mcp/oauth/authorize"]) {
    const res = await request(ctx.app).get(url).query(authorizeQuery({ resource: BASE }));
    assert.equal(res.status, 302);
    assert.ok(res.headers.location.startsWith("https://auth.example.com/application/o/authorize/"));
    const raw = res.headers["set-cookie"].find((c) => c.startsWith("xmcp_flow="));
    assert.match(raw, /; Secure/);
    assert.match(raw, /; HttpOnly/);
    assert.match(raw, /; SameSite=Lax/);
    assert.match(raw, /; Path=\/mcp\/oauth/);
    assert.match(raw, /Max-Age=600/);
    assertFlowHeaders(res);
  }
});

test("Callback ohne oder mit falschem xmcp_flow-Cookie -> 400, kein Code-Tausch", async () => {
  const ctx = await setup();
  const a = await request(ctx.app).get("/authorize").query(authorizeQuery());
  const state = new URL(a.headers.location).searchParams.get("state");
  const none = await request(ctx.app).get("/mcp/oauth/callback").query({ code: "c", state });
  assert.equal(none.status, 400);
  assertFlowHeaders(none);
  const a2 = await request(ctx.app).get("/authorize").query(authorizeQuery());
  const state2 = new URL(a2.headers.location).searchParams.get("state");
  const wrong = await request(ctx.app).get("/mcp/oauth/callback").query({ code: "c", state: state2 }).set("Cookie", "xmcp_flow=other");
  assert.equal(wrong.status, 400);
  assert.equal(ctx.calls.exchange.length, 0);
});

test("Callback: Benutzer nicht in erlaubter Gruppe -> 403", async () => {
  const ctx = await setup({ checkUser: async () => { throw new AuthentikRejected(); } });
  const a = await request(ctx.app).get("/authorize").query(authorizeQuery());
  const state = new URL(a.headers.location).searchParams.get("state");
  const res = await request(ctx.app).get("/mcp/oauth/callback").query({ code: "c", state }).set("Cookie", flowCookie(a));
  assert.equal(res.status, 403);
  assert.equal(res.headers.location, undefined);
  assert.deepEqual(ctx.calls.checkUser, ["AK-ACCESS-SECRET"]);
  assert.ok(!res.text.includes("AK-"));
});

test("Callback leitet ueber den XWiki-Login nach /mcp/oauth/complete", async () => {
  const ctx = await setup();
  const a = await request(ctx.app).get("/authorize").query(authorizeQuery());
  const loc = new URL(a.headers.location);
  const cb = await request(ctx.app).get("/mcp/oauth/callback")
    .query({ code: "ak-code", state: loc.searchParams.get("state") }).set("Cookie", flowCookie(a));
  assert.equal(cb.status, 302);
  assertFlowHeaders(cb);
  const target = new URL(cb.headers.location);
  assert.equal(target.origin + target.pathname, "https://xwiki.example.com/bin/login/XWiki/XWikiLogin");
  assert.match(target.searchParams.get("xredirect"), /^\/mcp\/oauth\/complete\?t=[A-Za-z0-9_-]+$/);
  assert.deepEqual(ctx.calls.exchange, [{ code: "ak-code", nonce: loc.searchParams.get("nonce") }]);
  // state is single-use
  const again = await request(ctx.app).get("/mcp/oauth/callback")
    .query({ code: "ak-code", state: loc.searchParams.get("state") }).set("Cookie", flowCookie(a));
  assert.equal(again.status, 400);
});

test("Complete mit whoami = anderer Benutzer -> 403, keine Sitzung, createToken nicht aufgerufen", async () => {
  for (const whoami of ["xwiki:XWiki.other", null]) {
    const ctx = await setup({ whoami });
    const { res } = await toComplete(ctx);
    assert.equal(res.status, 403);
    assert.equal(res.headers.location, undefined);
    assertFlowHeaders(res);
    assert.equal(ctx.calls.createToken.length, 0);
    assert.deepEqual(ctx.store.read().sessions, {});
    assert.deepEqual(ctx.store.read().cleanups, {});
  }
});

test("Complete ohne passendes xmcp_flow -> 400", async () => {
  const ctx = await setup();
  const { t } = await toComplete(ctx);
  const res = await request(ctx.app).get(`/mcp/oauth/complete?t=${t}`).set("Cookie", "xmcp_flow=x; JSESSIONID=y");
  assert.equal(res.status, 400);
});

test("Complete ohne Zustimmung -> Zustimmungsseite mit CSRF-Feld, escaped", async () => {
  const ctx = await setup();
  const { res, cookie } = await toComplete(ctx);
  assert.equal(res.status, 200);
  assert.match(res.headers["content-type"], /html/);
  assertFlowHeaders(res);
  assert.match(res.text, /nicht geprüft/);
  assert.match(res.text, /Claude &lt;b&gt;/);
  assert.ok(!res.text.includes("Claude <b>"));
  assert.match(res.text, /https:\/\/claude\.ai/);
  assert.match(res.text, /maxmustermann/);
  assert.match(res.text, /action="\/mcp\/oauth\/consent"/);
  assert.ok(consentFields(res.text).csrf);
  assert.match(res.text, /Zulassen/);
  assert.match(res.text, /Abbrechen/);
  assert.equal(ctx.calls.createToken.length, 0);
  assert.ok(!res.text.includes("xw-session-secret"));
  assert.ok(cookie);
});

test("POST /mcp/oauth/consent ohne gueltiges CSRF -> 403", async () => {
  const ctx = await setup();
  const { res, cookie } = await toComplete(ctx);
  const { t, csrf } = consentFields(res.text);
  for (const body of [{ t, action: "allow" }, { t, csrf: (csrf[0] === "x" ? "y" : "x") + csrf.slice(1), action: "allow" }, { t, csrf: "", action: "allow" }]) {
    const r = await request(ctx.app).post("/mcp/oauth/consent").type("form").set("Cookie", cookie).send(body);
    assert.equal(r.status, 403);
    assertFlowHeaders(r);
  }
  assert.equal(ctx.calls.createToken.length, 0);
  assert.deepEqual(ctx.store.read().grants, {});
});

test("Zustimmung erteilt -> Code, Grant, Sitzung; zweiter Login ohne Zustimmungsseite", async () => {
  const ctx = await setup();
  const res = await fullLogin(ctx);
  assert.equal(res.status, 302, res.text);
  assertFlowHeaders(res);
  const loc = new URL(res.headers.location);
  assert.equal(loc.origin + loc.pathname, CLAUDE_CB);
  assert.equal(loc.searchParams.get("state"), "client-state");
  const code = loc.searchParams.get("code");
  assert.ok(code);

  const st = ctx.store.read();
  assert.deepEqual(st.grants[`sub-1|${CID}`], { at: T0 });
  const sessions = Object.values(st.sessions);
  assert.equal(sessions.length, 1);
  const s = sessions[0];
  assert.equal(s.sub, "sub-1");
  assert.equal(s.xwikiUser, USER);
  assert.equal(s.clientId, CID);
  assert.equal(s.tokenVersion, 1);
  assert.equal(s.tokenExpiresAt, T0 + 90 * DAY);
  assert.equal(s.lastClientRefreshAt, T0);
  assert.equal(ctx.store.openField(s.xwikiTokenSealed, `session:${s.sid}:xwikiToken`), "XW-TOKEN-SECRET-1");
  assert.equal(ctx.store.openField(s.authentikRefreshSealed, `session:${s.sid}:authentikRefresh`), "AK-REFRESH-SECRET");
  assert.deepEqual(st.families[s.familyId], { familyId: s.familyId, sid: s.sid, clientId: CID, currentHash: null, spentHashes: [], replay: null });
  assert.deepEqual(st.cleanups, {});
  assert.equal(st.clients[CID].lastUsedAt, T0);

  const raw = fs.readFileSync(ctx.file, "utf8");
  for (const secret of ["XW-TOKEN-SECRET", "AK-REFRESH-SECRET", "xw-session-secret"]) assert.ok(!raw.includes(secret), secret);

  const [ct] = ctx.calls.createToken;
  assert.deepEqual(ct.args, { xwikiUser: USER, appName: "xwiki-mcp – Claude <b> – 2026-11-18", days: 90 });
  assert.match(ct.auth.cookie, /JSESSIONID=xw-session-secret/);
  assert.ok(!ct.auth.cookie.includes("xmcp_flow"));

  const codeData = ctx.app.locals.oauth.consumeCode(code);
  assert.equal(codeData.sid, s.sid);
  assert.equal(codeData.clientId, CID);
  assert.equal(codeData.redirectUri, CLAUDE_CB);
  assert.equal(codeData.codeChallenge, CHALLENGE);
  assert.equal(ctx.app.locals.oauth.consumeCode(code), null, "single use");

  // second login: no consent page, straight redirect with a fresh code
  const second = await toComplete(ctx);
  assert.equal(second.res.status, 302);
  assert.ok(new URL(second.res.headers.location).searchParams.get("code"));
  assert.equal(new URL(second.res.headers.location).searchParams.get("iss"), BASE, "RFC 9207 iss on the success redirect");
  assert.equal(Object.keys(ctx.store.read().sessions).length, 2);
});

test("redirect_uri mit Query behaelt a=1; Loopback als lokales Programm angezeigt", async () => {
  const ctx = await setup();
  const c = await toComplete(ctx, { client_id: CID_LOCAL, redirect_uri: "http://localhost:53682/cb?a=1" });
  assert.equal(c.res.status, 200);
  assert.match(c.res.text, /lokales Programm auf diesem Rechner/);
  const f = consentFields(c.res.text);
  const res = await request(ctx.app).post("/mcp/oauth/consent").type("form").set("Cookie", c.cookie)
    .send({ t: f.t, csrf: f.csrf, action: "allow" });
  assert.equal(res.status, 302);
  const loc = new URL(res.headers.location);
  assert.equal(loc.origin + loc.pathname, "http://localhost:53682/cb");
  assert.equal(loc.searchParams.get("a"), "1");
  assert.ok(loc.searchParams.get("code"));
  assert.equal(loc.searchParams.get("state"), "client-state");
});

test("Abbrechen -> access_denied an redirect_uri, kein Grant, keine Sitzung", async () => {
  const ctx = await setup();
  const c = await toComplete(ctx);
  const f = consentFields(c.res.text);
  const res = await request(ctx.app).post("/mcp/oauth/consent").type("form").set("Cookie", c.cookie)
    .send({ t: f.t, csrf: f.csrf, action: "deny" });
  assert.equal(res.status, 302);
  const loc = new URL(res.headers.location);
  assert.equal(loc.searchParams.get("error"), "access_denied");
  assert.equal(loc.searchParams.get("state"), "client-state");
  assert.equal(loc.searchParams.get("iss"), BASE, "RFC 9207 iss on the error redirect");
  assert.equal(loc.searchParams.get("code"), null);
  assert.deepEqual(ctx.store.read().grants, {});
  assert.deepEqual(ctx.store.read().sessions, {});
  // the pending completion is gone
  const again = await request(ctx.app).post("/mcp/oauth/consent").type("form").set("Cookie", c.cookie)
    .send({ t: f.t, csrf: f.csrf, action: "allow" });
  assert.equal(again.status, 400);
});

test("createToken wirft login_required -> Fehlerseite, kein Code, kein Cleanup-Rest", async () => {
  const ctx = await setup({
    seed: (s) => { s.grants[`sub-1|${CID}`] = { at: 1 }; },
    createToken: async () => { throw new XWikiTokenError("login_required", 302); },
  });
  const { res } = await toComplete(ctx);
  assert.ok(res.status >= 400, String(res.status));
  assert.equal(res.headers.location, undefined);
  assertFlowHeaders(res);
  assert.match(res.headers["content-type"], /html/);
  assert.equal(ctx.calls.createToken.length, 1);
  const st = ctx.store.read();
  assert.deepEqual(st.cleanups, {});
  assert.deepEqual(st.sessions, {});
  assert.deepEqual(st.families, {});
});

test("createToken scheitert anders -> Fehlerseite, pending-create bleibt stehen", async () => {
  const ctx = await setup({
    seed: (s) => { s.grants[`sub-1|${CID}`] = { at: 1 }; },
    createToken: async () => { throw new XWikiTokenError("unavailable"); },
  });
  const { res } = await toComplete(ctx);
  assert.ok(res.status >= 500, String(res.status));
  assert.equal(res.headers.location, undefined);
  const cleanups = Object.values(ctx.store.read().cleanups);
  assert.equal(cleanups.length, 1);
  assert.equal(cleanups[0].reason, "pending-create");
  assert.equal(cleanups[0].xwikiUser, USER);
  assert.equal(cleanups[0].appName, "xwiki-mcp – Claude <b> – 2026-11-18");
  assert.equal(cleanups[0].consentId, null);
  assert.deepEqual(ctx.store.read().sessions, {});
});

test("pending-create wird vor dem Anlegen geschrieben", async () => {
  let seen;
  const ctx = await setup({
    seed: (s) => { s.grants[`sub-1|${CID}`] = { at: 1 }; },
    createToken: async () => {
      seen = Object.values(ctx.store.read().cleanups);
      return { token: "XW-TOKEN-SECRET-x", consentId: `${USER}^XWiki.OIDC.ConsentClass[9]`, expiresAt: T0 + 90 * DAY };
    },
  });
  const { res } = await toComplete(ctx);
  assert.equal(res.status, 302);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].reason, "pending-create");
  assert.deepEqual(ctx.store.read().cleanups, {});
});

test("R16: alte pending-create-Reste werden beim Login mit Cookie aufgeraeumt", async () => {
  const usedConsent = `${USER}^XWiki.OIDC.ConsentClass[1]`;
  const ctx = await setup({
    seed: (s) => {
      s.grants[`sub-1|${CID}`] = { at: 1 };
      s.cleanups.old = { id: "old", reason: "pending-create", xwikiUser: USER, appName: "xwiki-mcp – Claude – 2026-11-01", consentId: null, xwikiTokenSealed: null, createdAt: 1, attempts: 0, lastError: null };
      s.cleanups.foreign = { id: "foreign", reason: "pending-create", xwikiUser: "xwiki:XWiki.other", appName: "xwiki-mcp – X – 2026-11-01", consentId: null, xwikiTokenSealed: null, createdAt: 1, attempts: 0, lastError: null };
      s.sessions.live = { sid: "live", consentId: usedConsent, xwikiUser: USER };
    },
    findTokensByPrefix: async () => [
      { consentId: usedConsent, name: "xwiki-mcp – Claude – 2026-11-01", expiresAt: 0 },
      { consentId: `${USER}^XWiki.OIDC.ConsentClass[2]`, name: "xwiki-mcp – Claude – 2026-11-01", expiresAt: 0 },
    ],
  });
  const { res } = await toComplete(ctx);
  assert.equal(res.status, 302);
  assert.deepEqual(ctx.calls.find.map((f) => [f.xwikiUser, f.prefix]), [[USER, "xwiki-mcp – Claude – 2026-11-01"]]);
  assert.match(ctx.calls.find[0].auth.cookie, /JSESSIONID/);
  assert.deepEqual(ctx.calls.deleteToken.map((d) => d.target), [{ xwikiUser: USER, consentId: `${USER}^XWiki.OIDC.ConsentClass[2]` }]);
  assert.match(ctx.calls.deleteToken[0].auth.cookie, /JSESSIONID/);
  const cleanups = ctx.store.read().cleanups;
  assert.equal(cleanups.old, undefined);
  assert.ok(cleanups.foreign);
});

test("R16: Fehler beim Aufraeumen blockiert den Login nicht", async () => {
  const ctx = await setup({
    seed: (s) => {
      s.grants[`sub-1|${CID}`] = { at: 1 };
      s.cleanups.old = { id: "old", reason: "pending-create", xwikiUser: USER, appName: "xwiki-mcp – Claude – 2026-11-01", consentId: null, xwikiTokenSealed: null, createdAt: 1, attempts: 0, lastError: null };
    },
    findTokensByPrefix: async () => { throw new XWikiTokenError("unavailable"); },
  });
  const { res } = await toComplete(ctx);
  assert.equal(res.status, 302);
  assert.ok(new URL(res.headers.location).searchParams.get("code"));
  assert.ok(ctx.store.read().cleanups.old, "entry kept for a later attempt");
});

test("Codes laufen nach 5 Minuten ab, Pending ist einmalig", async () => {
  const ctx = await setup({ seed: (s) => { s.grants[`sub-1|${CID}`] = { at: 1 }; } });
  const { res, t, cookie } = await toComplete(ctx);
  const code = new URL(res.headers.location).searchParams.get("code");
  const reuse = await request(ctx.app).get(`/mcp/oauth/complete?t=${t}`).set("Cookie", cookie);
  assert.equal(reuse.status, 400);
  ctx.clock.now += 5 * 60 * 1000 + 1;
  assert.equal(ctx.app.locals.oauth.consumeCode(code), null);
});

test("AUTH_DEBUG-Log enthaelt keine Geheimnisse", async () => {
  const lines = [];
  const orig = { info: console.info, warn: console.warn, error: console.error, log: console.log };
  for (const k of Object.keys(orig)) console[k] = (...a) => lines.push(a.join(" "));
  try {
    const ctx = await setup({ authDebug: true });
    const res = await fullLogin(ctx);
    assert.equal(res.status, 302);
  } finally {
    Object.assign(console, orig);
  }
  const all = lines.join("\n");
  assert.ok(lines.length > 0);
  for (const secret of ["XW-TOKEN-SECRET", "AK-REFRESH-SECRET", "AK-ACCESS-SECRET", "xw-session-secret", "ak-code", "xmcp_flow"]) {
    assert.ok(!all.includes(secret), secret);
  }
});

test("createSession schreibt Sitzung und Familie in einem mutate und entfernt pending-create", async () => {
  const { store } = tmpStore();
  await store.mutate((s) => {
    s.clients[CID] = { clientId: CID, clientName: "C", redirectUris: [CLAUDE_CB], createdAt: 1, lastUsedAt: 1 };
    s.cleanups.p1 = { id: "p1", reason: "pending-create", xwikiUser: USER, appName: "a", consentId: null, xwikiTokenSealed: null, createdAt: 1, attempts: 0, lastError: null };
  });
  let mutates = 0;
  const counted = { ...store, mutate: (fn) => { mutates += 1; return store.mutate(fn); } };
  const { sid, familyId } = await createSession(
    { store: counted, cfg: {}, now: () => T0 },
    { sub: "s", userId: "max.mustermann", xwikiUser: USER, clientId: CID, authentikRefresh: "rt", xwikiToken: "tok", consentId: "c1", tokenExpiresAt: T0 + DAY, pendingCleanupId: "p1" },
  );
  assert.equal(mutates, 1);
  const st = store.read();
  assert.equal(st.sessions[sid].familyId, familyId);
  assert.equal(st.sessions[sid].userId, "max.mustermann");
  assert.equal(st.sessions[sid].consentId, "c1");
  assert.equal(st.sessions[sid].createdAt, T0);
  assert.equal(st.families[familyId].sid, sid);
  assert.equal(st.cleanups.p1, undefined);
  assert.throws(() => store.openField(st.sessions[sid].xwikiTokenSealed, `session:other:xwikiToken`));
});

// --- Review fixes (Codex review of 1532dca) ---

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}
const tick = (ms) => new Promise((r) => setTimeout(r, ms));

async function toCallbackDone(ctx) {
  const a = await request(ctx.app).get("/authorize").query(authorizeQuery());
  const flow = flowCookie(a);
  const state = new URL(a.headers.location).searchParams.get("state");
  const cb = await request(ctx.app).get("/mcp/oauth/callback").query({ code: "c", state }).set("Cookie", flow);
  return { path: new URL(cb.headers.location).searchParams.get("xredirect"), cookie: `${flow}; JSESSIONID=x` };
}

test("Parallele /complete-Aufrufe mit Grant: nur einer schliesst ab", async () => {
  const ctx = await setup({ seed: (s) => { s.grants[`sub-1|${CID}`] = { at: 1 }; } });
  const c = await toCallbackDone(ctx);
  const gate = deferred();
  ctx.setWhoami(async () => { await gate.promise; return USER; });
  const p1 = request(ctx.app).get(c.path).set("Cookie", c.cookie).then((r) => r);
  const p2 = request(ctx.app).get(c.path).set("Cookie", c.cookie).then((r) => r);
  await tick(50);
  gate.resolve();
  const [r1, r2] = await Promise.all([p1, p2]);
  const statuses = [r1.status, r2.status].sort();
  assert.equal(statuses[0], 302);
  assert.ok(statuses[1] >= 400, String(statuses[1]));
  assert.equal(ctx.calls.createToken.length, 1);
  assert.equal(Object.keys(ctx.store.read().sessions).length, 1);
});

test("/complete in Arbeit, dann /consent: nur einer schliesst ab", async () => {
  const ctx = await setup();
  const c = await toComplete(ctx); // consent page shown, no grant yet
  assert.equal(c.res.status, 200);
  const f = consentFields(c.res.text);
  const gate = deferred();
  ctx.setWhoami(async () => { await gate.promise; return USER; });
  const pComplete = request(ctx.app).get(`/mcp/oauth/complete?t=${c.t}`).set("Cookie", c.cookie).then((r) => r);
  await tick(30);
  const pConsent = request(ctx.app).post("/mcp/oauth/consent").type("form").set("Cookie", c.cookie)
    .send({ t: f.t, csrf: f.csrf, action: "allow" }).then((r) => r);
  await tick(30);
  gate.resolve();
  const [rc, rp] = await Promise.all([pComplete, pConsent]);
  assert.equal(rc.status, 200, "complete shows the consent page again");
  assert.ok(rp.status >= 400, String(rp.status));
  assert.equal(ctx.calls.createToken.length, 0);
  assert.deepEqual(ctx.store.read().sessions, {});
});

test("/consent in Arbeit, dann /complete: nur einer schliesst ab", async () => {
  const ctx = await setup();
  const c = await toComplete(ctx);
  const f = consentFields(c.res.text);
  const gate = deferred();
  ctx.setWhoami(async () => { await gate.promise; return USER; });
  const q1 = request(ctx.app).post("/mcp/oauth/consent").type("form").set("Cookie", c.cookie)
    .send({ t: f.t, csrf: f.csrf, action: "allow" }).then((r) => r);
  await tick(30);
  const q2 = request(ctx.app).get(`/mcp/oauth/complete?t=${c.t}`).set("Cookie", c.cookie).then((r) => r);
  await tick(30);
  gate.resolve();
  const [a, b] = await Promise.all([q1, q2]);
  assert.equal(a.status, 302);
  assert.ok(b.status >= 400, String(b.status));
  assert.equal(ctx.calls.createToken.length, 1);
  assert.equal(Object.keys(ctx.store.read().sessions).length, 1);
});

test("Zwei /complete im Zustimmungsweg: zweiter abgewiesen, Zustimmung danach genau einmal", async () => {
  const ctx = await setup();
  const c = await toComplete(ctx);
  const f = consentFields(c.res.text);
  const gate = deferred();
  ctx.setWhoami(async () => { await gate.promise; return USER; });
  const p1 = request(ctx.app).get(`/mcp/oauth/complete?t=${c.t}`).set("Cookie", c.cookie).then((r) => r);
  await tick(30);
  const p2 = request(ctx.app).get(`/mcp/oauth/complete?t=${c.t}`).set("Cookie", c.cookie).then((r) => r);
  await tick(30);
  gate.resolve();
  const [r1, r2] = await Promise.all([p1, p2]);
  assert.equal(r1.status, 200);
  assert.ok(r2.status >= 400, String(r2.status));
  ctx.setWhoami(null);
  const ok = await request(ctx.app).post("/mcp/oauth/consent").type("form").set("Cookie", c.cookie)
    .send({ t: f.t, csrf: f.csrf, action: "allow" });
  assert.equal(ok.status, 302);
  assert.equal(ctx.calls.createToken.length, 1);
});

test("resource mit abschliessendem Slash wird akzeptiert, anderer Pfad nicht", async () => {
  const ctx = await setup();
  const ok = await request(ctx.app).get("/authorize").query(authorizeQuery({ resource: `${BASE}/` }));
  assert.equal(ok.status, 302);
  const bad = await request(ctx.app).get("/authorize").query(authorizeQuery({ resource: `${BASE}/x` }));
  assert.equal(bad.status, 400);
  assert.match(bad.text, /invalid_target/);
});

test("Body-Parser-Fehler auf Flow-Pfaden -> deutsche Fehlerseite, JSON sonst", async () => {
  const ctx = await setup();
  const big = await request(ctx.app).post("/mcp/oauth/consent").type("form").send(`t=${"a".repeat(200 * 1024)}`);
  assert.equal(big.status, 413);
  assert.match(big.headers["content-type"], /html/);
  assertFlowHeaders(big);
  assert.match(big.text, /Anmeldung nicht möglich/);
  const bad = await request(ctx.app).post("/mcp/oauth/consent").set("Content-Type", "application/json").send("{");
  assert.equal(bad.status, 400);
  assert.match(bad.headers["content-type"], /html/);
  assertFlowHeaders(bad);
  const tok = await request(ctx.app).post("/mcp/oauth/token").set("Content-Type", "application/json").send("{");
  assert.equal(tok.status, 400);
  assert.deepEqual(tok.body, { error: "invalid_request" });
  const reg = await request(ctx.app).post("/mcp/oauth/register").set("Content-Type", "application/json").send("{");
  assert.deepEqual(reg.body, { error: "invalid_client_metadata" });
});

test("sweep entfernt abgelaufene Eintraege ohne Zugriff", async () => {
  const ctx = await setup();
  const c = await toComplete(ctx);
  assert.equal(c.res.status, 200);
  await request(ctx.app).get("/authorize").query(authorizeQuery());
  const before = ctx.app.locals.oauth.stats();
  assert.equal(before.pendings, 1);
  assert.equal(before.flows, 1);
  ctx.app.locals.oauth.sweep();
  assert.deepEqual(ctx.app.locals.oauth.stats(), before, "nothing expired yet");
  ctx.clock.now += 10 * 60 * 1000 + 1;
  ctx.app.locals.oauth.sweep();
  assert.deepEqual(ctx.app.locals.oauth.stats(), { flows: 0, pendings: 0, codes: 0 });
});

test("Autorisierungsfehler von Authentik -> access_denied mit iss (RFC 9207)", async () => {
  const ctx = await setup();
  const a = await request(ctx.app).get("/authorize").query(authorizeQuery());
  const flow = flowCookie(a);
  const state = new URL(a.headers.location).searchParams.get("state");
  const cb = await request(ctx.app).get("/mcp/oauth/callback").query({ error: "access_denied", state }).set("Cookie", flow);
  assert.equal(cb.status, 302);
  const loc = new URL(cb.headers.location);
  assert.equal(loc.searchParams.get("error"), "access_denied");
  assert.equal(loc.searchParams.get("iss"), BASE);
});
