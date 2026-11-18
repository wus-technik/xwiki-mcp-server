// R17: /token with authorization_code and refresh_token (rotation, replay window, reuse
// detection). Replaces the interim JWT exchange of the login-flow task.
import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { jwtVerify, decodeProtectedHeader } from "jose";
import { createApp } from "../src/app.js";
import { openStore } from "../src/store.js";
import { AuthentikRejected, AuthentikUnavailable } from "../src/authentik.js";

const KEY = Buffer.alloc(32, 9);
const SECRET = "test-secret-32-chars-minimum-pad";
const BASE = "https://xwiki.example.com/mcp";
const DAY = 86400000;
const T0 = Date.UTC(2026, 10, 18, 9, 0, 0);
const USER = "xwiki:XWiki.maxmustermann";
const CID = "client-1";
const CID2 = "client-2";
const CB = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER = "dBjftJeZ4CVP-mJ92K9-hWB7pS3G4V1pE1OE0dE_2Y0";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");
const hash = (t) => createHash("sha256").update(t).digest("hex");

function makeApp({ file, fsImpl, clock, opts = {}, calls }) {
  const store = openStore({ file, key: KEY, ...(fsImpl ? { fs: fsImpl } : {}) });
  let akN = 0;
  const authentik = {
    authorizeUrl: ({ state, nonce }) => `https://auth.example.com/application/o/authorize/?state=${state}&nonce=${nonce}`,
    exchangeCode: async () => ({ sub: "sub-1", username: "max.mustermann", refreshToken: "AK-RT-0", accessToken: "AK-AT-0" }),
    checkUser: async (at) => {
      calls.checkUser.push(at);
      if (opts.checkUser) await opts.checkUser(at);
    },
    refresh: async (rt) => {
      calls.refresh.push(rt);
      if (opts.refresh) return opts.refresh(rt);
      if (opts.refreshDelay) await new Promise((r) => setTimeout(r, opts.refreshDelay));
      akN += 1;
      return { refreshToken: `AK-RT-${akN}`, accessToken: `AK-AT-${akN}` };
    },
  };
  const xwikiTokens = {
    whoami: async () => USER,
    createToken: async () => ({ token: "XW-TOKEN-SECRET", consentId: `${USER}^XWiki.OIDC.ConsentClass[0]`, expiresAt: clock.now + 90 * DAY }),
    findTokensByPrefix: async () => [],
    // endSession starts runCleanups in the background; XWiki "unreachable" keeps the cleanup
    // entries in place so the tests can inspect what endSession recorded.
    deleteToken: async () => { throw Object.assign(new Error("unavailable"), { code: "unavailable" }); },
  };
  const app = createApp({
    sessionSecret: SECRET, mcpBaseUrl: BASE, store, authentik, xwikiTokens,
    now: () => clock.now, extraRedirectUris: [], authDebug: false,
  });
  return { app, store };
}

async function setup(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "token-"));
  const file = path.join(dir, "s.json");
  const seedStore = openStore({ file, key: KEY });
  await seedStore.mutate((s) => {
    s.clients[CID] = { clientId: CID, clientName: "Claude", redirectUris: [CB], createdAt: 1, lastUsedAt: 1 };
    s.clients[CID2] = { clientId: CID2, clientName: "Other", redirectUris: [CB], createdAt: 1, lastUsedAt: 1 };
    // Consent already given: the login goes straight to the code.
    s.grants[`sub-1|${CID}`] = { at: 1 };
  });
  let fail = false;
  const fsImpl = { ...fs, renameSync: (...a) => { if (fail) throw new Error("disk full"); return fs.renameSync(...a); } };
  const clock = { now: T0 };
  const calls = { refresh: [], checkUser: [] };
  const { app, store } = makeApp({ file, fsImpl, clock, opts, calls });
  return { app, store, file, clock, calls, opts, failWrites: (v) => { fail = v; } };
}

async function getCode(ctx, over = {}) {
  const q = {
    response_type: "code", client_id: CID, redirect_uri: CB, state: "st",
    code_challenge: CHALLENGE, code_challenge_method: "S256", ...over,
  };
  const a = await request(ctx.app).get("/authorize").query(q);
  assert.equal(a.status, 302, a.text);
  const flow = (a.headers["set-cookie"] || []).find((c) => c.startsWith("xmcp_flow=")).split(";")[0];
  const state = new URL(a.headers.location).searchParams.get("state");
  const cb = await request(ctx.app).get("/mcp/oauth/callback").query({ code: "ak", state }).set("Cookie", flow);
  const completePath = new URL(cb.headers.location).searchParams.get("xredirect");
  const res = await request(ctx.app).get(completePath).set("Cookie", `${flow}; JSESSIONID=xw`);
  assert.equal(res.status, 302, res.text);
  return new URL(res.headers.location).searchParams.get("code");
}

const codeBody = (code, over = {}) => ({
  grant_type: "authorization_code", code, code_verifier: VERIFIER, client_id: CID, redirect_uri: CB, ...over,
});

async function login(ctx, url = "/token") {
  const code = await getCode(ctx);
  const res = await request(ctx.app).post(url).type("form").send(codeBody(code));
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body;
}

const refresh = (ctx, rt, clientId = CID, url = "/token") =>
  request(ctx.app).post(url).type("form").send({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId });

function onlySession(ctx) {
  const s = Object.values(ctx.store.read().sessions);
  return s.length === 1 ? s[0] : null;
}

function assertNoStore(res) {
  assert.equal(res.headers["cache-control"], "no-store");
  assert.equal(res.headers["pragma"], "no-cache");
}

test("Code-Tausch liefert Access-/Refresh-Token mit den festgelegten Claims", async () => {
  const ctx = await setup();
  const code = await getCode(ctx, { resource: BASE });
  const res = await request(ctx.app).post("/mcp/oauth/token").type("form").send(codeBody(code, { resource: BASE }));
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assertNoStore(res);
  const b = res.body;
  assert.equal(b.token_type, "Bearer");
  assert.equal(b.expires_in, 3600);
  assert.equal(b.scope, "xwiki");
  assert.match(b.refresh_token, /^[A-Za-z0-9_-]{43,}$/);
  assert.equal(decodeProtectedHeader(b.access_token).alg, "HS256");
  const { payload } = await jwtVerify(b.access_token, new TextEncoder().encode(SECRET), { issuer: BASE, audience: BASE, algorithms: ["HS256"], currentDate: new Date(T0) });
  const s = onlySession(ctx);
  assert.equal(payload.sub, "sub-1");
  assert.equal(payload.sid, s.sid);
  assert.equal(payload.client_id, CID);
  assert.equal(payload.ver, 1);
  assert.equal(payload.iat, T0 / 1000);
  assert.equal(payload.exp, T0 / 1000 + 3600);
  const fam = ctx.store.read().families[s.familyId];
  assert.equal(fam.currentHash, hash(b.refresh_token));
  assert.equal(s.lastClientRefreshAt, T0);
  const raw = fs.readFileSync(ctx.file, "utf8");
  assert.ok(!raw.includes(b.refresh_token), "refresh token only stored as hash");
});

test("JSON-Body wird ebenfalls angenommen", async () => {
  const ctx = await setup();
  const code = await getCode(ctx);
  const res = await request(ctx.app).post("/token").send(codeBody(code));
  assert.equal(res.status, 200, JSON.stringify(res.body));
});

test("Code-Tausch mit falscher client_id oder anderer redirect_uri -> invalid_grant", async () => {
  const ctx = await setup();
  for (const over of [{ client_id: CID2 }, { redirect_uri: "https://claude.ai/api/mcp/other" }, { code_verifier: "x".repeat(43) }]) {
    const code = await getCode(ctx);
    const res = await request(ctx.app).post("/token").type("form").send(codeBody(code, over));
    assert.equal(res.status, 400, JSON.stringify(over));
    assert.deepEqual(res.body, { error: "invalid_grant" });
    assertNoStore(res);
    // The code is burned by the failed attempt.
    const again = await request(ctx.app).post("/token").type("form").send(codeBody(code));
    assert.deepEqual(again.body, { error: "invalid_grant" });
  }
});

test("Code ist einmalig", async () => {
  const ctx = await setup();
  const code = await getCode(ctx);
  assert.equal((await request(ctx.app).post("/token").type("form").send(codeBody(code))).status, 200);
  const res = await request(ctx.app).post("/token").type("form").send(codeBody(code));
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "invalid_grant" });
});

test("resource: abweichend -> invalid_target, weggelassen ok", async () => {
  const ctx = await setup();
  let code = await getCode(ctx, { resource: BASE });
  let res = await request(ctx.app).post("/token").type("form").send(codeBody(code, { resource: "https://evil.example.com/mcp" }));
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "invalid_target" });
  code = await getCode(ctx, { resource: BASE });
  res = await request(ctx.app).post("/token").type("form").send(codeBody(code));
  assert.equal(res.status, 200);
});

test("fehlende Parameter -> invalid_request, unbekannter Grant -> unsupported_grant_type", async () => {
  const ctx = await setup();
  for (const body of [{}, { grant_type: "authorization_code", code: "x" }, { grant_type: "refresh_token" }]) {
    const res = await request(ctx.app).post("/token").type("form").send(body);
    assert.equal(res.status, 400, JSON.stringify(body));
    assert.deepEqual(res.body, { error: "invalid_request" });
    assertNoStore(res);
  }
  const res = await request(ctx.app).post("/token").type("form").send({ grant_type: "password" });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "unsupported_grant_type" });
  assertNoStore(res);
});

test("Refresh liefert neues Paar; altes Token in 30 s gleiche Antwort, nach 31 s invalid_grant und Sitzung weg", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  ctx.clock.now += 60_000;
  const r1 = await refresh(ctx, first.refresh_token, CID, "/mcp/oauth/token");
  assert.equal(r1.status, 200, JSON.stringify(r1.body));
  assertNoStore(r1);
  assert.notEqual(r1.body.refresh_token, first.refresh_token);
  assert.notEqual(r1.body.access_token, first.access_token);
  assert.deepEqual(ctx.calls.refresh, ["AK-RT-0"]);
  assert.deepEqual(ctx.calls.checkUser, ["AK-AT-0", "AK-AT-1"]);
  const s = onlySession(ctx);
  assert.equal(s.lastClientRefreshAt, T0 + 60_000);
  assert.equal(ctx.store.openField(s.authentikRefreshSealed, `session:${s.sid}:authentikRefresh`), "AK-RT-1");
  const fam = ctx.store.read().families[s.familyId];
  assert.equal(fam.currentHash, hash(r1.body.refresh_token));
  assert.deepEqual(fam.spentHashes, [hash(first.refresh_token)]);
  assert.equal(fam.replay.hash, hash(first.refresh_token));
  assert.equal(fam.replay.until, T0 + 60_000 + 30_000);

  ctx.clock.now += 29_000;
  const again = await refresh(ctx, first.refresh_token);
  assert.equal(again.status, 200);
  assert.deepEqual(again.body, r1.body);
  assert.equal(ctx.calls.refresh.length, 1, "replay does not call Authentik");

  ctx.clock.now += 2_000; // 31 s after the rotation
  const late = await refresh(ctx, first.refresh_token);
  assert.equal(late.status, 400);
  assert.deepEqual(late.body, { error: "invalid_grant" });
  assert.equal(onlySession(ctx), null, "session ended on reuse");
  const st = ctx.store.read();
  assert.deepEqual(st.families, {});
  const cl = Object.values(st.cleanups);
  assert.equal(cl.length, 1);
  assert.equal(cl[0].reason, "refresh-reuse");
  assert.equal(cl[0].xwikiUser, USER);
  assert.equal(cl[0].consentId, `${USER}^XWiki.OIDC.ConsentClass[0]`);
  assert.equal(ctx.store.openField(cl[0].xwikiTokenSealed, `cleanup:${cl[0].id}:xwikiToken`), "XW-TOKEN-SECRET");
  // The current token of the ended family is dead too.
  const cur = await refresh(ctx, r1.body.refresh_token);
  assert.deepEqual(cur.body, { error: "invalid_grant" });
});

test("Zwei gleichzeitige Refreshs mit demselben Token -> beide 200, gleiche Antwort, Sitzung lebt (Review Focus 1)", async () => {
  const ctx = await setup({ refreshDelay: 30 });
  const first = await login(ctx);
  const [a, b] = await Promise.all([refresh(ctx, first.refresh_token), refresh(ctx, first.refresh_token)]);
  assert.equal(a.status, 200, JSON.stringify(a.body));
  assert.equal(b.status, 200, JSON.stringify(b.body));
  assert.deepEqual(a.body, b.body);
  assert.equal(ctx.calls.refresh.length, 1);
  assert.ok(onlySession(ctx), "session alive");
  const next = await refresh(ctx, a.body.refresh_token);
  assert.equal(next.status, 200);
});

test("Refresh mit Token einer anderen client_id -> invalid_grant", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  const res = await refresh(ctx, first.refresh_token, CID2);
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "invalid_grant" });
  assert.equal(ctx.calls.refresh.length, 0);
  assert.ok(onlySession(ctx), "a wrong client_id does not end the session");
  assert.equal((await refresh(ctx, first.refresh_token)).status, 200);
});

test("Unbekanntes Refresh-Token -> invalid_grant", async () => {
  const ctx = await setup();
  await login(ctx);
  const res = await refresh(ctx, "A".repeat(43));
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "invalid_grant" });
  assert.ok(onlySession(ctx));
});

test("Refresh nach mehr als 30 Tagen ohne Nutzung -> invalid_grant, Sitzung beendet (idle)", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  ctx.clock.now += 30 * DAY + 1;
  const res = await refresh(ctx, first.refresh_token);
  assert.deepEqual(res.body, { error: "invalid_grant" });
  assert.equal(onlySession(ctx), null);
  assert.equal(Object.values(ctx.store.read().cleanups)[0].reason, "idle");
  assert.equal(ctx.calls.refresh.length, 0);
});

test("AuthentikRejected -> invalid_grant, Sitzung weg, Cleanup authentik-rejected", async () => {
  const ctx = await setup({ refresh: async () => { throw new AuthentikRejected(); } });
  const first = await login(ctx);
  const res = await refresh(ctx, first.refresh_token);
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "invalid_grant" });
  assert.equal(onlySession(ctx), null);
  const cl = Object.values(ctx.store.read().cleanups);
  assert.equal(cl.length, 1);
  assert.equal(cl[0].reason, "authentik-rejected");
});

test("checkUser abgelehnt (Gruppe entzogen) -> invalid_grant, Sitzung weg", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  ctx.opts.checkUser = async () => { throw new AuthentikRejected(); };
  const res = await refresh(ctx, first.refresh_token);
  assert.deepEqual(res.body, { error: "invalid_grant" });
  assert.equal(onlySession(ctx), null);
  assert.equal(Object.values(ctx.store.read().cleanups)[0].reason, "authentik-rejected");
});

test("AuthentikUnavailable -> 503 temporarily_unavailable, Refresh-Token weiter gueltig", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  ctx.opts.refresh = async () => { throw new AuthentikUnavailable(); };
  const before = ctx.store.read();
  const res = await refresh(ctx, first.refresh_token);
  assert.equal(res.status, 503);
  assert.deepEqual(res.body, { error: "temporarily_unavailable" });
  assertNoStore(res);
  assert.deepEqual(ctx.store.read(), before, "nothing changed");
  delete ctx.opts.refresh;
  assert.equal((await refresh(ctx, first.refresh_token)).status, 200);
});

test("store.mutate wirft bei der Rotation -> 500, neu geoeffneter Store akzeptiert das alte Token (Review Focus 4)", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  ctx.failWrites(true);
  const res = await refresh(ctx, first.refresh_token);
  assert.equal(res.status, 500);
  assert.deepEqual(res.body, { error: "server_error" });
  assertNoStore(res);
  assert.equal(ctx.calls.refresh.length, 1);

  // "Restart": a new store and app on the same file with a working fs.
  const calls = { refresh: [], checkUser: [] };
  const restarted = makeApp({ file: ctx.file, clock: ctx.clock, calls });
  const r = await request(restarted.app).post("/token").type("form")
    .send({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: CID });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(calls.refresh, ["AK-RT-0"], "server still holds the old Authentik refresh token");
});

test("XWiki-Token mit < 14 Tagen Restlaufzeit: Refresh laeuft trotzdem durch", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  // Refresh every 20 days; at day 80 only 10 days are left on the 90-day XWiki token, so the
  // renewal path runs (placeholder until Task 10) and must not fail the refresh.
  let rt = first.refresh_token;
  for (let i = 0; i < 4; i++) {
    ctx.clock.now += 20 * DAY;
    const r = await refresh(ctx, rt);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    rt = r.body.refresh_token;
  }
  assert.ok(onlySession(ctx));
});

test("Parserfehler auf /token -> invalid_request mit no-store", async () => {
  const ctx = await setup();
  for (const url of ["/token", "/mcp/oauth/token"]) {
    const res = await request(ctx.app).post(url).set("Content-Type", "application/json").send("{");
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: "invalid_request" });
    assertNoStore(res);
  }
});

test("Wiederholung im Fenster mit anderer client_id -> invalid_grant, keine Antwort", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  assert.equal((await refresh(ctx, first.refresh_token)).status, 200);
  const res = await refresh(ctx, first.refresh_token, CID2);
  assert.deepEqual(res.body, { error: "invalid_grant" });
});

test("PKCE-Verifier ausserhalb RFC 7636 (43-128, unreserved) -> invalid_grant, Code verbrannt", async () => {
  const ctx = await setup();
  for (const bad of ["short", `${"a".repeat(42)}+`, "a".repeat(129)]) {
    const challenge = createHash("sha256").update(bad).digest("base64url");
    const code = await getCode(ctx, { code_challenge: challenge });
    const res = await request(ctx.app).post("/token").type("form").send(codeBody(code, { code_verifier: bad }));
    assert.equal(res.status, 400, bad);
    assert.deepEqual(res.body, { error: "invalid_grant" });
    const again = await request(ctx.app).post("/token").type("form").send(codeBody(code));
    assert.deepEqual(again.body, { error: "invalid_grant" });
  }
});

test("Refresh ohne client_id gelingt; andere client_id -> invalid_grant", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  const res = await request(ctx.app).post("/token").type("form").send({ grant_type: "refresh_token", refresh_token: first.refresh_token });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const other = await refresh(ctx, res.body.refresh_token, CID2);
  assert.deepEqual(other.body, { error: "invalid_grant" });
});

test("Zweite Rotation in 30 s schliesst das Fenster des ersten Tokens: A->B->C, dann A -> Wiederverwendung", async () => {
  const ctx = await setup();
  const a = await login(ctx);
  const b = await refresh(ctx, a.refresh_token);
  assert.equal(b.status, 200);
  ctx.clock.now += 5_000;
  const c = await refresh(ctx, b.body.refresh_token);
  assert.equal(c.status, 200);
  ctx.clock.now += 5_000; // A is only 10 s old, but the single replay slot now holds B
  const res = await refresh(ctx, a.refresh_token);
  assert.deepEqual(res.body, { error: "invalid_grant" });
  assert.equal(onlySession(ctx), null);
  assert.equal(Object.values(ctx.store.read().cleanups)[0].reason, "refresh-reuse");
});

test("Wiederholung genau bei now === replay.until -> Wiederverwendung, Sitzung beendet", async () => {
  const ctx = await setup();
  const a = await login(ctx);
  assert.equal((await refresh(ctx, a.refresh_token)).status, 200);
  ctx.clock.now += 30_000;
  const res = await refresh(ctx, a.refresh_token);
  assert.deepEqual(res.body, { error: "invalid_grant" });
  assert.equal(onlySession(ctx), null);
});

// Authentik stub that rotates like the real one: a used refresh token is spent.
function rotatingAuthentik(ctx) {
  const valid = new Set(["AK-RT-0"]);
  let n = 0;
  ctx.opts.refresh = async (rt) => {
    if (!valid.has(rt)) throw new AuthentikRejected();
    valid.delete(rt);
    n += 1;
    valid.add(`AK-RT-R${n}`);
    return { refreshToken: `AK-RT-R${n}`, accessToken: `AK-AT-R${n}` };
  };
}

test("checkUser 503 nach Authentik-Rotation: neues Authentik-RT gesichert, Wiederholung gelingt", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  rotatingAuthentik(ctx);
  ctx.opts.checkUser = async () => { throw new AuthentikUnavailable(); };
  const before = onlySession(ctx);
  const res = await refresh(ctx, first.refresh_token);
  assert.equal(res.status, 503);
  assert.deepEqual(res.body, { error: "temporarily_unavailable" });
  const s = onlySession(ctx);
  assert.equal(ctx.store.openField(s.authentikRefreshSealed, `session:${s.sid}:authentikRefresh`), "AK-RT-R1");
  assert.equal(s.lastClientRefreshAt, before.lastClientRefreshAt, "no MCP rotation");
  assert.equal(ctx.store.read().families[s.familyId].currentHash, hash(first.refresh_token));
  delete ctx.opts.checkUser;
  const retry = await refresh(ctx, first.refresh_token);
  assert.equal(retry.status, 200, JSON.stringify(retry.body));
  assert.deepEqual(ctx.calls.refresh, ["AK-RT-0", "AK-RT-R1"]);
  assert.ok(onlySession(ctx), "session alive");
});

test("Schlussschreiben scheitert nach Authentik-Rotation: Wiederholung nach Neustart nutzt das neue Authentik-RT", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  rotatingAuthentik(ctx);
  // Let the first write (Authentik RT) through, fail the second (rotation).
  let writes = 0;
  const realMutate = ctx.store.mutate.bind(ctx.store);
  ctx.store.mutate = (fn) => {
    writes += 1;
    if (writes === 2) ctx.failWrites(true);
    return realMutate(fn).finally(() => ctx.failWrites(false));
  };
  const res = await refresh(ctx, first.refresh_token);
  assert.equal(res.status, 500);
  const calls = { refresh: [], checkUser: [] };
  const restarted = makeApp({ file: ctx.file, clock: ctx.clock, calls, opts: ctx.opts });
  const r = await request(restarted.app).post("/token").type("form")
    .send({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: CID });
  assert.equal(r.status, 200, JSON.stringify(r.body));
});

test("Sichern des Authentik-RT scheitert -> 500, MCP-Token unveraendert", async () => {
  const ctx = await setup();
  const first = await login(ctx);
  const before = ctx.store.read();
  ctx.failWrites(true);
  const res = await refresh(ctx, first.refresh_token);
  assert.equal(res.status, 500);
  assert.deepEqual(res.body, { error: "server_error" });
  assert.equal(ctx.calls.checkUser.length, 1, "checkUser not reached after the failed write");
  ctx.failWrites(false);
  assert.deepEqual(ctx.store.read(), before);
});
