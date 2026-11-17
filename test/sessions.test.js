// Task 10: end of a session, cleanups, XWiki token renewal, daily reconcile with Authentik,
// background timers and token revocation (RFC 7009).
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { SignJWT } from "jose";
import { openStore } from "../src/store.js";
import { createApp } from "../src/app.js";
import { AuthentikRejected, AuthentikUnavailable } from "../src/authentik.js";
import { XWikiTokenError } from "../src/xwiki-tokens.js";
import {
  createSession, issueTokens, endSession, runCleanups, renewXWikiToken, dailyReconcile, startBackground,
  recoverPendingCreates,
} from "../src/sessions.js";

const KEY = Buffer.alloc(32, 5);
const SECRET = "test-secret-32-chars-minimum-pad";
const BASE = "https://xwiki.example.com/mcp";
const DAY = 86400000;
const MIN = 60000;
const T0 = Date.UTC(2026, 10, 18, 9, 0, 0);
const USER = "xwiki:XWiki.zurmano";
const OTHER = "xwiki:XWiki.other";
const CID = "client-1";
const CB = "https://claude.ai/api/mcp/auth_callback";
const consent = (n, user = USER) => `${user}^XWiki.OIDC.ConsentClass[${n}]`;
const bearerOf = (n, user = USER) => `${user.replace(/^xwiki:/, "")}/${n}/secret${n}`;

function makeDeps(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sessions-"));
  const file = path.join(dir, "s.json");
  const store = openStore({ file, key: KEY });
  const clock = { now: T0 };
  const calls = { deleteToken: [], find: [], createToken: [], refresh: [], checkUser: [] };
  let akN = 0;
  let tokN = 100;
  const authentik = {
    refresh: async (rt) => {
      calls.refresh.push(rt);
      if (opts.refresh) return opts.refresh(rt);
      akN += 1;
      return { refreshToken: `AK-RT-${akN}`, accessToken: `AK-AT-${akN}` };
    },
    checkUser: async (at) => {
      calls.checkUser.push(at);
      if (opts.checkUser) return opts.checkUser(at);
    },
  };
  const xwikiTokens = {
    deleteToken: async (auth, target) => {
      calls.deleteToken.push({ auth, target });
      if (opts.deleteToken) return opts.deleteToken(auth, target);
      return "deleted";
    },
    findTokensByPrefix: async (auth, xwikiUser, prefix) => {
      calls.find.push({ auth, xwikiUser, prefix });
      if (opts.findTokensByPrefix) return opts.findTokensByPrefix(auth, xwikiUser, prefix);
      return [];
    },
    createToken: async (auth, args) => {
      calls.createToken.push({ auth, args });
      if (opts.createToken) return opts.createToken(auth, args);
      tokN += 1;
      return { token: bearerOf(tokN), consentId: consent(tokN), expiresAt: clock.now + 90 * DAY };
    },
  };
  const cfg = { mcpBaseUrl: BASE, sessionSecret: SECRET };
  const deps = { store, cfg, authentik, xwikiTokens, now: () => clock.now };
  return { deps, store, file, clock, calls, opts };
}

async function seedClient(store, clientId = CID, extra = {}) {
  await store.mutate((s) => {
    s.clients[clientId] = { clientId, clientName: "Claude", redirectUris: [CB], createdAt: 1, lastUsedAt: T0, ...extra };
  });
}

async function newSession(ctx, { n = 1, user = USER, clientId = CID, issue = true, tokenExpiresAt } = {}) {
  if (!ctx.store.read().clients[clientId]) await seedClient(ctx.store, clientId);
  const { sid, familyId } = await createSession(ctx.deps, {
    sub: "sub-1", userId: "zurman.o", xwikiUser: user, clientId, authentikRefresh: "AK-RT-0",
    xwikiToken: bearerOf(n, user), consentId: consent(n, user), tokenExpiresAt: tokenExpiresAt ?? ctx.clock.now + 90 * DAY,
  });
  const tokens = issue ? await issueTokens(ctx.deps, { sid, familyId, clientId }) : null;
  return { sid, familyId, tokens };
}

const cleanupsOf = (ctx) => Object.values(ctx.store.read().cleanups);

function captureConsole() {
  const lines = [];
  const orig = { info: console.info, warn: console.warn, error: console.error, log: console.log };
  for (const k of Object.keys(orig)) console[k] = (...a) => lines.push(a.join(" "));
  return { lines, restore: () => Object.assign(console, orig) };
}

// --- endSession / runCleanups ---------------------------------------------------------

test("endSession: Sitzung und Familie weg, Cleanup da; runCleanups mit 'gone' entfernt den Eintrag", async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const ctx = makeDeps({ deleteToken: async () => { await gate; return "gone"; } });
  const { sid, familyId } = await newSession(ctx);
  const id = await endSession(ctx.deps, sid, "revoked");
  const st = ctx.store.read();
  assert.equal(st.sessions[sid], undefined);
  assert.equal(st.families[familyId], undefined);
  assert.equal(st.cleanups[id].reason, "revoked");
  assert.equal(st.cleanups[id].consentId, consent(1));
  assert.equal(st.cleanups[id].xwikiUser, USER);
  release();
  await runCleanups(ctx.deps);
  assert.deepEqual(ctx.store.read().cleanups, {});
  assert.equal(ctx.calls.deleteToken.length, 1);
  assert.deepEqual(ctx.calls.deleteToken[0].auth, { bearer: bearerOf(1) });
  assert.deepEqual(ctx.calls.deleteToken[0].target, { xwikiUser: USER, consentId: consent(1) });
});

test("endSession mit awaitCleanup: Eintrag ist nach der Rueckkehr schon geloescht", async () => {
  const ctx = makeDeps();
  const { sid } = await newSession(ctx);
  await endSession(ctx.deps, sid, "revoked", { awaitCleanup: true });
  assert.deepEqual(ctx.store.read().cleanups, {});
  assert.equal(ctx.calls.deleteToken.length, 1);
});

test("endSession fuer eine schon beendete Sitzung ist ein No-op", async () => {
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("unavailable"); } });
  const { sid } = await newSession(ctx);
  await endSession(ctx.deps, sid, "revoked", { awaitCleanup: true });
  assert.equal(await endSession(ctx.deps, sid, "revoked", { awaitCleanup: true }), null);
  assert.equal(cleanupsOf(ctx).length, 1);
});

test("runCleanups: Fehler -> attempts = 1, lastError nur Code, Eintrag bleibt; kein zweiter Versuch im selben Lauf", async () => {
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("delete_failed"); } });
  const { sid } = await newSession(ctx);
  await endSession(ctx.deps, sid, "idle", { awaitCleanup: true });
  let [c] = cleanupsOf(ctx);
  assert.equal(c.attempts, 1);
  assert.equal(c.lastError, "delete_failed");
  assert.equal(ctx.calls.deleteToken.length, 1);
  await runCleanups(ctx.deps);
  [c] = cleanupsOf(ctx);
  assert.equal(c.attempts, 2);
});

test("runCleanups behandelt login_required/unavailable/unexpected_page nie als erledigt", async () => {
  for (const code of ["login_required", "unavailable", "unexpected_page"]) {
    const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError(code); } });
    const { sid } = await newSession(ctx);
    await endSession(ctx.deps, sid, "xwiki-401", { awaitCleanup: true });
    const [c] = cleanupsOf(ctx);
    assert.equal(c.lastError, code);
    assert.equal(c.attempts, 1);
  }
});

test("runCleanups ist single-flight: zwei gleichzeitige Aufrufe, ein deleteToken je Eintrag", async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const ctx = makeDeps({ deleteToken: async () => { await gate; return "deleted"; } });
  const a = await newSession(ctx, { n: 1 });
  const b = await newSession(ctx, { n: 2 });
  await endSession(ctx.deps, a.sid, "revoked");
  await endSession(ctx.deps, b.sid, "revoked");
  const p1 = runCleanups(ctx.deps);
  const p2 = runCleanups(ctx.deps);
  release();
  await Promise.all([p1, p2]);
  assert.equal(ctx.calls.deleteToken.length, 2);
  assert.deepEqual(ctx.store.read().cleanups, {});
});

test("Review Focus 5: Token im XWiki-Profil geloescht -> 'gone', Eintrag weg, kein weiterer Versuch", async () => {
  const ctx = makeDeps({ deleteToken: async () => "gone" });
  const { sid } = await newSession(ctx);
  await endSession(ctx.deps, sid, "xwiki-401", { awaitCleanup: true });
  await runCleanups(ctx.deps);
  assert.deepEqual(ctx.store.read().cleanups, {});
  assert.equal(ctx.calls.deleteToken.length, 1);
});

test("Eintraege aelter als 7 Tage -> console.warn mit id, xwikiUser, reason, ohne Token", async () => {
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("unavailable"); } });
  const { sid } = await newSession(ctx);
  const id = await endSession(ctx.deps, sid, "idle", { awaitCleanup: true });
  ctx.clock.now += 8 * DAY;
  const out = captureConsole();
  try {
    await runCleanups(ctx.deps);
  } finally {
    out.restore();
  }
  const all = out.lines.join("\n");
  const warn = out.lines.find((l) => l.includes(id));
  assert.ok(warn, all);
  assert.match(warn, /xwiki:XWiki\.zurmano/);
  assert.match(warn, /idle/);
  assert.ok(!all.includes("secret1"), "no token in logs");
});

// --- pending-create in runCleanups (R16) ------------------------------------------------

async function seedPending(ctx, { id = "p-old", user = USER, appName = "xwiki-mcp – Claude – 2026-11-01", createdAt = 1 } = {}) {
  await ctx.store.mutate((s) => {
    s.cleanups[id] = { id, reason: "pending-create", xwikiUser: user, appName, consentId: null, xwikiTokenSealed: null, createdAt, attempts: 0, lastError: null };
  });
}

test("pending-create: ueber findTokensByPrefix mit dem Bearer einer lebenden Sitzung gefunden und geloescht", async () => {
  const appName = "xwiki-mcp – Claude – 2026-11-01";
  const ctx = makeDeps({
    findTokensByPrefix: async () => [
      { consentId: consent(1), name: appName, expiresAt: 0 }, // referenced by the live session
      { consentId: consent(7), name: appName, expiresAt: 0 }, // leftover
      { consentId: consent(8), name: `${appName} (anders)`, expiresAt: 0 }, // other name
    ],
  });
  await newSession(ctx, { n: 1 });
  await seedPending(ctx, { appName });
  await runCleanups(ctx.deps);
  assert.deepEqual(ctx.calls.find.map((f) => [f.auth, f.xwikiUser, f.prefix]), [[{ bearer: bearerOf(1) }, USER, appName]]);
  assert.deepEqual(ctx.calls.deleteToken.map((d) => [d.auth, d.target]), [[{ bearer: bearerOf(1) }, { xwikiUser: USER, consentId: consent(7) }]]);
  assert.deepEqual(ctx.store.read().cleanups, {});
});

test("pending-create ohne lebende Sitzung des Nutzers bleibt unveraendert (keine attempts)", async () => {
  const ctx = makeDeps();
  await newSession(ctx, { n: 1, user: OTHER });
  await seedPending(ctx);
  await runCleanups(ctx.deps);
  assert.equal(ctx.calls.find.length, 0);
  const c = ctx.store.read().cleanups["p-old"];
  assert.equal(c.attempts, 0);
  assert.equal(c.lastError, null);
});

test("pending-create: Fehler bei der Suche -> attempts++, Eintrag bleibt", async () => {
  const ctx = makeDeps({ findTokensByPrefix: async () => { throw new XWikiTokenError("unavailable"); } });
  await newSession(ctx, { n: 1 });
  await seedPending(ctx);
  await runCleanups(ctx.deps);
  const c = ctx.store.read().cleanups["p-old"];
  assert.equal(c.attempts, 1);
  assert.equal(c.lastError, "unavailable");
});

test("pending-create: eine laufende Anlage gleichen Namens (junger pending-Eintrag) wird nicht angefasst", async () => {
  const appName = "xwiki-mcp – Claude – 2026-11-18";
  const ctx = makeDeps({ findTokensByPrefix: async () => [{ consentId: consent(9), name: appName, expiresAt: 0 }] });
  await newSession(ctx, { n: 1 });
  await seedPending(ctx, { id: "p-old", appName });
  await seedPending(ctx, { id: "p-inflight", appName, createdAt: T0 - MIN });
  await runCleanups(ctx.deps);
  assert.equal(ctx.calls.deleteToken.length, 0);
  assert.ok(ctx.store.read().cleanups["p-old"]);
  assert.ok(ctx.store.read().cleanups["p-inflight"]);
});

test("recoverPendingCreates (Login) laesst einen jungen pending-Eintrag einer laufenden Erneuerung in Ruhe", async () => {
  const appName = "xwiki-mcp – Claude – 2026-11-18";
  const ctx = makeDeps({ findTokensByPrefix: async () => [{ consentId: consent(9), name: appName, expiresAt: 0 }] });
  await seedPending(ctx, { id: "p-renewal", appName, createdAt: T0 - MIN });
  await seedPending(ctx, { id: "p-old", appName: "xwiki-mcp – Claude – 2026-11-01" });
  await recoverPendingCreates(ctx.deps, { cookie: "JSESSIONID=x", xwikiUser: USER });
  const st = ctx.store.read();
  assert.ok(st.cleanups["p-renewal"], "in-flight entry kept");
  assert.equal(st.cleanups["p-old"], undefined, "old leftover recovered");
  assert.equal(ctx.calls.deleteToken.length, 0, "the in-flight token is not deleted");
});

// --- renewXWikiToken ----------------------------------------------------------------------

test("renewXWikiToken: tokenVersion + 1, neuer Token, alter als renewed-Cleanup, pending-create weg", async () => {
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("unavailable"); } });
  const { sid } = await newSession(ctx, { n: 1, tokenExpiresAt: T0 + 10 * DAY });
  await renewXWikiToken(ctx.deps, sid);
  assert.equal(ctx.calls.createToken.length, 1);
  const [call] = ctx.calls.createToken;
  assert.deepEqual(call.auth, { bearer: bearerOf(1) });
  assert.deepEqual(call.args, { xwikiUser: USER, appName: "xwiki-mcp – Claude – 2026-11-18", days: 90 });
  const st = ctx.store.read();
  const s = st.sessions[sid];
  assert.equal(s.tokenVersion, 2);
  assert.equal(s.consentId, consent(101));
  assert.equal(s.tokenExpiresAt, T0 + 90 * DAY);
  assert.equal(ctx.store.openField(s.xwikiTokenSealed, `session:${sid}:xwikiToken`), bearerOf(101));
  const cl = Object.values(st.cleanups);
  assert.equal(cl.length, 1, JSON.stringify(cl));
  assert.equal(cl[0].reason, "renewed");
  assert.equal(cl[0].consentId, consent(1));
  assert.equal(ctx.store.openField(cl[0].xwikiTokenSealed, `cleanup:${cl[0].id}:xwikiToken`), bearerOf(1));
  await runCleanups(ctx.deps);
  assert.deepEqual(ctx.calls.deleteToken.at(-1).auth, { bearer: bearerOf(1) }, "old token deleted with its own bearer");
});

test("renewXWikiToken: Anlegen scheitert (unavailable) -> Sitzung unveraendert, pending-create bleibt, kein Throw", async () => {
  const ctx = makeDeps({ createToken: async () => { throw new XWikiTokenError("unavailable"); } });
  const { sid } = await newSession(ctx, { n: 1, tokenExpiresAt: T0 + 10 * DAY });
  const before = ctx.store.read().sessions[sid];
  const out = captureConsole();
  try {
    await renewXWikiToken(ctx.deps, sid);
  } finally {
    out.restore();
  }
  assert.deepEqual(ctx.store.read().sessions[sid], before);
  const cl = cleanupsOf(ctx);
  assert.equal(cl.length, 1);
  assert.equal(cl[0].reason, "pending-create");
  assert.ok(out.lines.some((l) => l.includes("unavailable")));
  assert.ok(!out.lines.join("\n").includes("secret1"));
});

test("renewXWikiToken: login_required -> pending-create entfernt (nichts angelegt)", async () => {
  const ctx = makeDeps({ createToken: async () => { throw new XWikiTokenError("login_required"); } });
  const { sid } = await newSession(ctx, { n: 1, tokenExpiresAt: T0 + 10 * DAY });
  const out = captureConsole();
  try {
    await renewXWikiToken(ctx.deps, sid);
  } finally {
    out.restore();
  }
  assert.deepEqual(ctx.store.read().cleanups, {});
  assert.equal(ctx.store.read().sessions[sid].tokenVersion, 1);
});

// --- dailyReconcile ---------------------------------------------------------------------

test("dailyReconcile mit AuthentikRejected -> Sitzung beendet (authentik-rejected)", async () => {
  const ctx = makeDeps({
    refresh: async () => { throw new AuthentikRejected(); },
    deleteToken: async () => { throw new XWikiTokenError("unavailable"); },
  });
  const { sid } = await newSession(ctx);
  await dailyReconcile(ctx.deps);
  assert.equal(ctx.store.read().sessions[sid], undefined);
  assert.equal(cleanupsOf(ctx)[0].reason, "authentik-rejected");
});

test("dailyReconcile: checkUser abgelehnt -> Sitzung beendet", async () => {
  const ctx = makeDeps({ checkUser: async () => { throw new AuthentikRejected(); } });
  const { sid } = await newSession(ctx);
  await dailyReconcile(ctx.deps);
  assert.equal(ctx.store.read().sessions[sid], undefined);
});

test("dailyReconcile mit Erfolg: neues Authentik-RT gespeichert, lastClientRefreshAt unveraendert", async () => {
  const ctx = makeDeps();
  const { sid } = await newSession(ctx);
  ctx.clock.now += 3 * DAY;
  await dailyReconcile(ctx.deps);
  const s = ctx.store.read().sessions[sid];
  assert.equal(s.lastClientRefreshAt, T0);
  assert.deepEqual(ctx.calls.refresh, ["AK-RT-0"]);
  assert.deepEqual(ctx.calls.checkUser, ["AK-AT-1"]);
  assert.equal(ctx.store.openField(s.authentikRefreshSealed, `session:${sid}:authentikRefresh`), "AK-RT-1");
});

test("dailyReconcile mit AuthentikUnavailable -> Sitzung unveraendert", async () => {
  const ctx = makeDeps({ refresh: async () => { throw new AuthentikUnavailable(); } });
  const { sid } = await newSession(ctx);
  const before = ctx.store.read().sessions[sid];
  await dailyReconcile(ctx.deps);
  assert.deepEqual(ctx.store.read().sessions[sid], before);
});

test("dailyReconcile: 30 Tage ohne Client-Refresh -> idle, kein Authentik-Aufruf; Abgleich verlaengert die Frist nicht", async () => {
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("unavailable"); } });
  const { sid } = await newSession(ctx);
  for (let d = 1; d <= 30; d++) {
    ctx.clock.now = T0 + d * DAY;
    await dailyReconcile(ctx.deps);
    assert.ok(ctx.store.read().sessions[sid], `alive on day ${d}`);
  }
  ctx.clock.now = T0 + 30 * DAY + 1;
  const n = ctx.calls.refresh.length;
  await dailyReconcile(ctx.deps);
  assert.equal(ctx.store.read().sessions[sid], undefined);
  assert.equal(ctx.calls.refresh.length, n);
  assert.ok(cleanupsOf(ctx).some((c) => c.reason === "idle"));
});

test("dailyReconcile: Sitzung ohne ausgegebenes Refresh-Token aelter als 10 min -> orphan", async () => {
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("unavailable"); } });
  const young = await newSession(ctx, { n: 1, issue: false });
  ctx.clock.now += 11 * MIN;
  const fresh = await newSession(ctx, { n: 2, issue: false });
  await dailyReconcile(ctx.deps);
  const st = ctx.store.read();
  assert.equal(st.sessions[young.sid], undefined);
  assert.ok(st.sessions[fresh.sid], "younger than 10 min stays");
  assert.ok(cleanupsOf(ctx).some((c) => c.reason === "orphan"));
});

test("dailyReconcile raeumt Cleanups, Upload-Nonces und alte Clients ohne Sitzung auf", async () => {
  const ctx = makeDeps();
  await seedClient(ctx.store, "old-unused", { lastUsedAt: T0 - 31 * DAY });
  await seedClient(ctx.store, "recent", { lastUsedAt: T0 - 5 * DAY });
  await seedClient(ctx.store, "old-with-session", { lastUsedAt: T0 - 31 * DAY });
  await ctx.store.mutate((s) => {
    s.grants["sub-1|old-unused"] = { at: 1 };
    s.grants["sub-1|recent"] = { at: 1 };
    s.uploadNonces.expired = T0 - 1;
    s.uploadNonces.valid = T0 + MIN;
  });
  const keep = await newSession(ctx, { n: 1, clientId: "old-with-session" });
  // createSession bumps lastUsedAt; make it old again.
  await ctx.store.mutate((s) => { s.clients["old-with-session"].lastUsedAt = T0 - 31 * DAY; });
  const gone = await newSession(ctx, { n: 2 });
  await endSession(ctx.deps, gone.sid, "revoked");
  await dailyReconcile(ctx.deps);
  const st = ctx.store.read();
  assert.ok(st.sessions[keep.sid]);
  assert.deepEqual(st.cleanups, {}, "cleanups ran");
  assert.deepEqual(Object.keys(st.uploadNonces), ["valid"]);
  assert.equal(st.clients["old-unused"], undefined);
  assert.equal(st.grants["sub-1|old-unused"], undefined);
  assert.ok(st.clients.recent);
  assert.ok(st.grants["sub-1|recent"]);
  assert.ok(st.clients["old-with-session"]);
});

test("dailyReconcile ist single-flight", async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const ctx = makeDeps({ refresh: async () => { await gate; return { refreshToken: "AK-RT-x", accessToken: "AK-AT-x" }; } });
  await newSession(ctx);
  const p1 = dailyReconcile(ctx.deps);
  const p2 = dailyReconcile(ctx.deps);
  release();
  await Promise.all([p1, p2]);
  assert.equal(ctx.calls.refresh.length, 1);
});

// --- startBackground ----------------------------------------------------------------------

test("startBackground: erster Abgleich nach 5 min, dann alle 24 h; Cleanups stuendlich", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("unavailable"); } });
  await newSession(ctx, { n: 1 });
  const s2 = await newSession(ctx, { n: 2 });
  await endSession(ctx.deps, s2.sid, "revoked", { awaitCleanup: true });
  const flush = async () => { for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r)); };
  const stop = startBackground(ctx.deps);
  try {
    t.mock.timers.tick(5 * MIN - 1);
    await flush();
    assert.equal(ctx.calls.refresh.length, 0);
    t.mock.timers.tick(1);
    await flush();
    assert.equal(ctx.calls.refresh.length, 1, "first reconcile after 5 min");
    const deletesAfterFirst = ctx.calls.deleteToken.length;
    t.mock.timers.tick(55 * MIN);
    await flush();
    assert.equal(ctx.calls.deleteToken.length, deletesAfterFirst + 1, "hourly cleanup");
    t.mock.timers.tick(24 * 60 * MIN - 55 * MIN);
    await flush();
    assert.equal(ctx.calls.refresh.length, 2, "second reconcile 24 h after the first");
  } finally {
    stop();
  }
  t.mock.timers.tick(48 * 60 * MIN);
  await new Promise((r) => setImmediate(r));
  assert.equal(ctx.calls.refresh.length, 2, "stopped");
});

// --- revoke (RFC 7009) --------------------------------------------------------------------

async function revokeSetup(opts = {}) {
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("unavailable"); }, ...opts });
  const app = createApp({
    sessionSecret: SECRET, mcpBaseUrl: BASE, store: ctx.store, authentik: ctx.deps.authentik,
    xwikiTokens: ctx.deps.xwikiTokens, now: ctx.deps.now, extraRedirectUris: [], authDebug: false,
  });
  return { ...ctx, app };
}

test("createApp legt die deps auf app.locals.deps", async () => {
  const ctx = await revokeSetup();
  const d = ctx.app.locals.deps;
  assert.equal(d.store, ctx.store);
  assert.equal(d.authentik, ctx.deps.authentik);
  assert.equal(d.xwikiTokens, ctx.deps.xwikiTokens);
  assert.equal(d.now(), T0);
  assert.equal(d.cfg.mcpBaseUrl, BASE);
});

test("/revoke mit unbekanntem Token -> 200 {} mit no-store", async () => {
  const ctx = await revokeSetup();
  const { sid } = await newSession(ctx);
  for (const url of ["/revoke", "/oauth/revoke", "/mcp/oauth/revoke"]) {
    const res = await request(ctx.app).post(url).type("form").send({ token: "garbage" });
    assert.equal(res.status, 200, url);
    assert.deepEqual(res.body, {});
    assert.equal(res.headers["cache-control"], "no-store");
  }
  assert.ok(ctx.store.read().sessions[sid]);
});

test("/revoke ohne token -> 400 invalid_request", async () => {
  const ctx = await revokeSetup();
  const res = await request(ctx.app).post("/revoke").type("form").send({ token_type_hint: "refresh_token" });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "invalid_request" });
});

test("/revoke mit Refresh-Token -> 200 und Sitzung weg (revoked)", async () => {
  for (const url of ["/revoke", "/oauth/revoke", "/mcp/oauth/revoke"]) {
    const ctx = await revokeSetup();
    const { sid, familyId, tokens } = await newSession(ctx);
    const res = await request(ctx.app).post(url).type("form").send({ token: tokens.refresh_token, token_type_hint: "refresh_token" });
    assert.equal(res.status, 200, url);
    assert.deepEqual(res.body, {});
    const st = ctx.store.read();
    assert.equal(st.sessions[sid], undefined);
    assert.equal(st.families[familyId], undefined);
    assert.equal(cleanupsOf(ctx)[0].reason, "revoked");
  }
});

test("/revoke als JSON mit Access-Token -> Sitzung weg; auch abgelaufen", async () => {
  const ctx = await revokeSetup();
  const a = await newSession(ctx, { n: 1 });
  const res = await request(ctx.app).post("/mcp/oauth/revoke").send({ token: a.tokens.access_token });
  assert.equal(res.status, 200);
  assert.equal(ctx.store.read().sessions[a.sid], undefined);

  const b = await newSession(ctx, { n: 2 });
  ctx.clock.now += 2 * 3600 * 1000; // exp is T0-based: the access token is expired now
  const res2 = await request(ctx.app).post("/revoke").type("form").send({ token: b.tokens.access_token, token_type_hint: "access_token" });
  assert.equal(res2.status, 200);
  assert.equal(ctx.store.read().sessions[b.sid], undefined, "expired but genuine access token still revokes");
});

test("/revoke mit falsch signiertem oder fremdem Access-Token -> 200, Sitzung bleibt", async () => {
  const ctx = await revokeSetup();
  const { sid } = await newSession(ctx);
  const iat = Math.floor(T0 / 1000);
  const forge = (secret, iss) => new SignJWT({ sid, client_id: CID, ver: 1 })
    .setProtectedHeader({ alg: "HS256" }).setIssuer(iss).setAudience(iss).setSubject("sub-1")
    .setIssuedAt(iat).setExpirationTime(iat + 3600).sign(new TextEncoder().encode(secret));
  for (const tok of [await forge("another-secret-32-chars-minimum!!", BASE), await forge(SECRET, "https://evil.example.com")]) {
    const res = await request(ctx.app).post("/revoke").type("form").send({ token: tok });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, {});
  }
  assert.ok(ctx.store.read().sessions[sid]);
});

test("/revoke mit bereits rotiertem Refresh-Token beendet die Sitzung ebenfalls", async () => {
  const ctx = await revokeSetup();
  const { sid, familyId, tokens } = await newSession(ctx);
  // A second issueTokens moves the first token into spentHashes.
  await issueTokens(ctx.deps, { sid, familyId, clientId: CID });
  assert.equal(ctx.store.read().families[familyId].spentHashes.length, 1);
  const res = await request(ctx.app).post("/revoke").type("form").send({ token: tokens.refresh_token });
  assert.equal(res.status, 200);
  assert.equal(ctx.store.read().sessions[sid], undefined);
});

// --- server.js ----------------------------------------------------------------------------

test("server.js mit kaputter Speicherdatei -> Exit-Code 1, Ausgabe nennt STORE_FILE", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "server-"));
  const file = path.join(dir, "store.json");
  fs.writeFileSync(file, "this is not a store");
  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const r = spawnSync(process.execPath, ["server.js"], {
    cwd: root,
    timeout: 10000,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      SYSTEMROOT: process.env.SYSTEMROOT,
      SESSION_SECRET: SECRET,
      TOKEN_ENC_KEY: KEY.toString("base64"),
      STORE_FILE: file,
      MCP_BASE_URL: BASE,
      XWIKI_URL: "http://xwiki.invalid",
      PORT: "0",
    },
  });
  assert.equal(r.status, 1, `stdout=${r.stdout} stderr=${r.stderr}`);
  assert.match(`${r.stdout}${r.stderr}`, /STORE_FILE/);
});

// --- Review fixes (Codex review of 1a71c25) ---

test("Warnung fuer Eintraege aelter als 7 Tage hoechstens einmal je 24 h und Eintrag", async () => {
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("unavailable"); } });
  const { sid } = await newSession(ctx);
  const id = await endSession(ctx.deps, sid, "idle", { awaitCleanup: true });
  const warnings = async () => {
    const out = captureConsole();
    try {
      await runCleanups(ctx.deps);
    } finally {
      out.restore();
    }
    return out.lines.filter((l) => l.includes(id)).length;
  };
  ctx.clock.now += 8 * DAY;
  assert.equal(await warnings(), 1);
  ctx.clock.now += 1 * 3600 * 1000;
  assert.equal(await warnings(), 0, "hourly run within 24 h stays quiet");
  ctx.clock.now += 23 * 3600 * 1000;
  assert.equal(await warnings(), 1, "again after 24 h");
  assert.equal(ctx.store.read().cleanups[id].attempts, 4);
});

test("Warnung wird auch fuer uebersprungene pending-create-Eintraege gedrosselt", async () => {
  const ctx = makeDeps();
  await seedPending(ctx);
  ctx.clock.now = T0;
  const count = async () => {
    const out = captureConsole();
    try {
      await runCleanups(ctx.deps);
    } finally {
      out.restore();
    }
    return out.lines.filter((l) => l.includes("p-old")).length;
  };
  assert.equal(await count(), 1);
  assert.equal(await count(), 0);
  assert.equal(ctx.store.read().cleanups["p-old"].attempts, 0, "still no attempts without a live session");
});

test("/revoke: Speichern scheitert -> 503 temporarily_unavailable mit no-store, Sitzung bleibt", async () => {
  const ctx = makeDeps({ deleteToken: async () => { throw new XWikiTokenError("unavailable"); } });
  const { sid, tokens } = await newSession(ctx);
  const failing = { ...ctx.store, mutate: async () => { throw new Error("disk full"); } };
  const app = createApp({
    sessionSecret: SECRET, mcpBaseUrl: BASE, store: failing, authentik: ctx.deps.authentik,
    xwikiTokens: ctx.deps.xwikiTokens, now: ctx.deps.now, extraRedirectUris: [], authDebug: false,
  });
  const out = captureConsole();
  let res;
  try {
    res = await request(app).post("/revoke").type("form").send({ token: tokens.refresh_token });
  } finally {
    out.restore();
  }
  assert.equal(res.status, 503);
  assert.deepEqual(res.body, { error: "temporarily_unavailable" });
  assert.equal(res.headers["cache-control"], "no-store");
  assert.ok(ctx.store.read().sessions[sid], "not revoked");
  assert.ok(!out.lines.join("\n").includes(tokens.refresh_token));
});
