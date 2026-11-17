// MCP sessions in the persistent store. Part 1: creating a session at login and
// recovering leftovers of interrupted token creations (pending-create cleanups).
// Part 2: issuing and rotating client tokens (access JWT + refresh token families).
//
// deps = { store, cfg, authentik, xwikiTokens, now } where now() returns ms.
// Secrets rule: tokens, cookies and refresh tokens are only ever stored sealed and
// never logged; log lines carry error codes only.
import { randomUUID, randomBytes, createHash } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { AuthentikRejected, AuthentikUnavailable } from "./authentik.js";

export const sealAad = (sid, field) => `session:${sid}:${field}`;

// Writes session + refresh family in ONE mutate and drops the pending-create entry of
// this login in the same write, so the token is either owned by a session or still
// tracked as pending — never neither.
// userId is the Authentik preferred_username (readable in logs and tool context);
// sub is kept separately for grants.
export async function createSession(deps, {
  sub, userId, xwikiUser, clientId, authentikRefresh, xwikiToken, consentId, tokenExpiresAt, pendingCleanupId,
}) {
  const { store } = deps;
  const now = deps.now();
  const sid = randomUUID();
  const familyId = randomUUID();
  const xwikiTokenSealed = store.sealField(xwikiToken, sealAad(sid, "xwikiToken"));
  const authentikRefreshSealed = store.sealField(authentikRefresh, sealAad(sid, "authentikRefresh"));
  await store.mutate((state) => {
    state.sessions[sid] = {
      sid, sub, userId, xwikiUser, clientId, familyId,
      xwikiTokenSealed, consentId, tokenVersion: 1, tokenExpiresAt,
      authentikRefreshSealed, createdAt: now, lastClientRefreshAt: now,
    };
    state.families[familyId] = { familyId, sid, clientId, currentHash: null, spentHashes: [], replay: null };
    if (pendingCleanupId) delete state.cleanups[pendingCleanupId];
    if (state.clients[clientId]) state.clients[clientId].lastUsedAt = now;
  });
  return { sid, familyId };
}

// Adds the pending-create marker before a token is created in XWiki.
export async function addPendingCreate(deps, { xwikiUser, appName }) {
  const id = randomUUID();
  await deps.store.mutate((state) => {
    state.cleanups[id] = {
      id, reason: "pending-create", xwikiUser, appName, consentId: null, xwikiTokenSealed: null,
      createdAt: deps.now(), attempts: 0, lastError: null,
    };
  });
  return id;
}

export async function removeCleanup(deps, id) {
  await deps.store.mutate((state) => { delete state.cleanups[id]; });
}

// R16: while the user's browser cookie is at hand, delete tokens left behind by earlier
// interrupted logins of this user (pending-create entries). A token is only deleted if no
// session or other cleanup references its consentId. Failures are logged and never block
// the login; the entry then stays for a later attempt.
// Callers must serialize this with their own token creation for the same xwikiUser
// (same appName prefixes), otherwise an in-flight token could be taken for a leftover.
export async function recoverPendingCreates(deps, { cookie, xwikiUser }) {
  const state = deps.store.read();
  const entries = Object.values(state.cleanups)
    .filter((c) => c && c.reason === "pending-create" && c.xwikiUser === xwikiUser && typeof c.appName === "string" && c.appName);
  for (const entry of entries) {
    try {
      // A token renewal of this user may be creating a token of this name right now
      // (renewals do not take the login's per-user lock).
      if (creationInFlight(deps.store.read(), entry, deps.now())) continue;
      const found = await deps.xwikiTokens.findTokensByPrefix({ cookie }, xwikiUser, entry.appName);
      const fresh = deps.store.read();
      if (creationInFlight(fresh, entry, deps.now())) continue;
      const referenced = referencedConsents(fresh, entry.id);
      for (const t of found) {
        if (t.name !== entry.appName || referenced.has(t.consentId)) continue;
        await deps.xwikiTokens.deleteToken({ cookie }, { xwikiUser, consentId: t.consentId });
      }
      await removeCleanup(deps, entry.id);
    } catch (e) {
      console.warn(`[login] pending-create recovery failed: ${e?.code || e?.name || "error"}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Part 2: client tokens.
//
// Refresh tokens are 32 random bytes (base64url) and are stored only as SHA-256 hex in the
// family: currentHash (valid), replay (the token rotated last, answered with the stored
// response for 30 s) and spentHashes (rotated tokens; presenting one ends the session).
// spentHashes keeps the last MAX_SPENT entries: an older token is then simply unknown
// (invalid_grant without ending the session), which bounds the store size per session.

const DAY_MS = 86400000;
const ACCESS_TTL_S = 3600;
const IDLE_MS = 30 * DAY_MS; // refresh token lifetime, sliding from lastClientRefreshAt
const REPLAY_MS = 30 * 1000;
const RENEW_BEFORE_MS = 14 * DAY_MS;
const MAX_SPENT = 50;

// RFC 6749 error of the token endpoint; status is the HTTP status to answer with.
export class TokenError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.name = "TokenError";
    this.code = code;
    this.status = status;
  }
}

const invalidGrant = () => new TokenError("invalid_grant");
const lockKey = (sid) => `session:${sid}`;
const replayAad = (familyId) => `family:${familyId}:replay`;
export const hashRefreshToken = (rt) => createHash("sha256").update(rt).digest("hex");
const newRefreshToken = () => randomBytes(32).toString("base64url");

async function signAccessToken(deps, session, nowMs) {
  const { cfg } = deps;
  const iat = Math.floor(nowMs / 1000);
  return new SignJWT({ sid: session.sid, client_id: session.clientId, ver: session.tokenVersion })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(cfg.mcpBaseUrl)
    .setAudience(cfg.mcpBaseUrl)
    .setSubject(session.sub)
    .setIssuedAt(iat)
    .setExpirationTime(iat + ACCESS_TTL_S)
    .sign(new TextEncoder().encode(cfg.sessionSecret));
}

async function buildResponse(deps, session, refreshToken, nowMs) {
  return {
    access_token: await signAccessToken(deps, session, nowMs),
    token_type: "Bearer",
    expires_in: ACCESS_TTL_S,
    refresh_token: refreshToken,
    scope: "xwiki",
  };
}

// Ends a session: ONE mutate records a cleanup entry for the XWiki token and removes session
// and family (no-op if the session is already gone). The XWiki token is re-sealed under the
// cleanup's own AAD `cleanup:<id>:xwikiToken`, so the entry can be opened without the
// (deleted) session id. Afterwards runCleanups is triggered.
//
// Locking: endSession never takes the session lock; callers that touch a session hold
// `session:<sid>` (withLock is not reentrant).
// Cleanup: by default runCleanups runs in the background (request paths must not wait for
// XWiki); errors are logged with their code only. `{ awaitCleanup: true }` waits for it
// (tests, background jobs). Returns the cleanup id, or null if the session was already gone.
export async function endSession(deps, sid, reason, { awaitCleanup = false } = {}) {
  const { store } = deps;
  const id = randomUUID();
  const now = deps.now();
  let ended = false;
  await store.mutate((state) => {
    const s = state.sessions[sid];
    if (!s) return;
    const xwikiTokenSealed = s.xwikiTokenSealed
      ? store.sealField(store.openField(s.xwikiTokenSealed, sealAad(sid, "xwikiToken")), cleanupAad(id))
      : null;
    state.cleanups[id] = {
      id, xwikiTokenSealed, consentId: s.consentId ?? null, xwikiUser: s.xwikiUser,
      reason, createdAt: now, attempts: 0, lastError: null,
    };
    delete state.sessions[sid];
    for (const [fid, f] of Object.entries(state.families)) {
      if (fid === s.familyId || f?.sid === sid) delete state.families[fid];
    }
    ended = true;
  });
  if (!ended) return null;
  console.warn(`[session] ended: ${reason}`);
  if (awaitCleanup) await runCleanups(deps);
  else triggerCleanups(deps);
  return id;
}

// Only short lower-case error codes reach logs and the store, never messages.
const errCode = (e) => (typeof e?.code === "string" && /^[a-z_]{1,40}$/.test(e.code) ? e.code : e?.name || "error");

// Background run of runCleanups; never rejects.
function triggerCleanups(deps) {
  runCleanups(deps).catch((e) => console.warn(`[cleanup] run failed: ${errCode(e)}`));
}

// ---------------------------------------------------------------------------
// Part 3: cleanups, XWiki token renewal, daily reconcile, background timers, revocation.

const cleanupAad = (id) => `cleanup:${id}:xwikiToken`;
const CLEANUP_WARN_AGE_MS = 7 * DAY_MS;
const CLEANUP_WARN_EVERY_MS = DAY_MS;
// A pending-create entry this young may belong to a token creation still in flight (login
// or renewal); tokens of that name are then left alone in this run.
const IN_FLIGHT_MS = 10 * 60 * 1000;
const ORPHAN_MS = 10 * 60 * 1000;
const CLIENT_IDLE_MS = 30 * DAY_MS;
const TOKEN_DAYS = 90;

// Single-flight state per store (deps objects differ between callers, the store does not).
const cleanupRuns = new WeakMap();
const reconcileRuns = new WeakMap();

// Deletes the XWiki tokens of cleanup entries. Single-flight: a call while a run is active
// returns that run's promise and makes it do one more pass for entries added meanwhile.
// Every entry is attempted at most once per run (no retry loops); failures count attempts
// and keep the entry for the next run (hourly, daily, next endSession).
export function runCleanups(deps) {
  let run = cleanupRuns.get(deps.store);
  if (run) {
    run.again = true;
    return run.promise;
  }
  run = { again: false, tried: new Set() };
  cleanupRuns.set(deps.store, run);
  run.promise = (async () => {
    try {
      do {
        run.again = false;
        await cleanupPass(deps, run.tried);
      } while (run.again);
    } finally {
      cleanupRuns.delete(deps.store);
    }
  })();
  return run.promise;
}

async function cleanupPass(deps, tried) {
  const now = deps.now();
  const entries = Object.values(deps.store.read().cleanups).filter((c) => c && typeof c.id === "string");
  for (const entry of entries) {
    if (tried.has(entry.id)) continue;
    tried.add(entry.id);
    await warnIfStale(deps, entry, now);
    try {
      if (entry.reason === "pending-create") await cleanupPending(deps, entry);
      else await cleanupToken(deps, entry);
    } catch (e) {
      await recordFailure(deps, entry.id, errCode(e));
    }
  }
}

// Entries older than 7 days are reported at most once per 24 h each; lastWarnedAt is
// persisted so restarts and hourly runs do not repeat the warning.
async function warnIfStale(deps, entry, now) {
  if (now - (entry.createdAt || 0) <= CLEANUP_WARN_AGE_MS) return;
  if (typeof entry.lastWarnedAt === "number" && now - entry.lastWarnedAt < CLEANUP_WARN_EVERY_MS) return;
  console.warn(`[cleanup] entry older than 7 days: id=${entry.id} xwikiUser=${entry.xwikiUser} reason=${entry.reason}`);
  try {
    await deps.store.mutate((state) => {
      if (state.cleanups[entry.id]) state.cleanups[entry.id].lastWarnedAt = now;
    });
  } catch (e) {
    console.warn(`[cleanup] store write failed: ${errCode(e)}`);
  }
}

async function recordFailure(deps, id, code) {
  try {
    await deps.store.mutate((state) => {
      const c = state.cleanups[id];
      if (!c) return;
      c.attempts = (c.attempts || 0) + 1;
      c.lastError = code;
    });
  } catch (e) {
    console.warn(`[cleanup] store write failed: ${errCode(e)}`);
  }
}

async function cleanupToken(deps, entry) {
  if (!entry.xwikiTokenSealed || !entry.consentId) throw Object.assign(new Error("no token"), { code: "no_token" });
  const bearer = deps.store.openField(entry.xwikiTokenSealed, cleanupAad(entry.id));
  // "deleted" and "gone" both mean done; every XWikiTokenError throws and is retried later.
  await deps.xwikiTokens.deleteToken({ bearer }, { xwikiUser: entry.xwikiUser, consentId: entry.consentId });
  await removeCleanup(deps, entry.id);
}

// consentIds owned by sessions or other cleanup entries: never deleted as leftovers.
function referencedConsents(state, exceptId) {
  const referenced = new Set();
  for (const s of Object.values(state.sessions)) if (s?.consentId) referenced.add(s.consentId);
  for (const c of Object.values(state.cleanups)) if (c && c.id !== exceptId && c.consentId) referenced.add(c.consentId);
  return referenced;
}

// True if a creation of a token named like `entry` may still be running: a young
// pending-create entry for the same user and name (the entry itself included).
function creationInFlight(state, entry, now) {
  return Object.values(state.cleanups).some((c) => c && c.reason === "pending-create"
    && c.xwikiUser === entry.xwikiUser && c.appName === entry.appName && now - (c.createdAt || 0) < IN_FLIGHT_MS);
}

// R16 outside the login: needs a credential of the same XWiki user, i.e. the bearer of one of
// the user's live sessions. Without one the entry stays untouched; the next login recovers it.
// Deleting another consent of the same user with a valid bearer works (fixture README 0.5).
async function cleanupPending(deps, entry) {
  const { store } = deps;
  const state = store.read();
  if (typeof entry.appName !== "string" || !entry.appName) return;
  if (creationInFlight(state, entry, deps.now())) return;
  const live = Object.values(state.sessions).find((s) => s?.xwikiUser === entry.xwikiUser && s.xwikiTokenSealed);
  if (!live) return;
  const bearer = store.openField(live.xwikiTokenSealed, sealAad(live.sid, "xwikiToken"));
  const found = await deps.xwikiTokens.findTokensByPrefix({ bearer }, entry.xwikiUser, entry.appName);
  // Re-read after the XWiki call: a creation that started meanwhile has its pending entry
  // (or, if finished, its session) in the store by now.
  const fresh = store.read();
  if (!fresh.cleanups[entry.id] || creationInFlight(fresh, entry, deps.now())) return;
  const referenced = referencedConsents(fresh, entry.id);
  for (const t of found) {
    if (t.name !== entry.appName || referenced.has(t.consentId)) continue;
    await deps.xwikiTokens.deleteToken({ bearer }, { xwikiUser: entry.xwikiUser, consentId: t.consentId });
  }
  await removeCleanup(deps, entry.id);
}

// Renews the XWiki token (called by refreshSession under `session:<sid>` when less than 14
// days are left). The new token is created with the current one as bearer and replaces it in
// ONE mutate (tokenVersion + 1); the old token becomes a "renewed" cleanup entry. A
// pending-create entry covers the window in which the token exists only in XWiki.
// Never throws: on failure the session continues with its current token.
export async function renewXWikiToken(deps, sid) {
  const { store } = deps;
  try {
    const state = store.read();
    const session = state.sessions[sid];
    if (!session) return;
    const clientName = state.clients[session.clientId]?.clientName || "unbenannter Client";
    const appName = `xwiki-mcp – ${clientName} – ${new Date(deps.now()).toISOString().slice(0, 10)}`;
    const xwikiUser = session.xwikiUser;
    const pendingId = await addPendingCreate(deps, { xwikiUser, appName });
    const current = store.openField(session.xwikiTokenSealed, sealAad(sid, "xwikiToken"));
    let created;
    try {
      created = await deps.xwikiTokens.createToken({ bearer: current }, { xwikiUser, appName, days: TOKEN_DAYS });
    } catch (e) {
      const code = errCode(e);
      console.warn(`[session] XWiki token renewal failed: ${code}`);
      // login_required: nothing was created. Otherwise the marker stays for recovery.
      if (code === "login_required") await removeCleanup(deps, pendingId);
      return;
    }
    const oldId = randomUUID();
    await store.mutate((draft) => {
      delete draft.cleanups[pendingId];
      const s = draft.sessions[sid];
      if (!s) {
        // Session vanished meanwhile: the new token must go, too.
        draft.cleanups[oldId] = {
          id: oldId, xwikiTokenSealed: store.sealField(created.token, cleanupAad(oldId)), consentId: created.consentId,
          xwikiUser, reason: "renewed", createdAt: deps.now(), attempts: 0, lastError: null,
        };
        return;
      }
      draft.cleanups[oldId] = {
        id: oldId,
        xwikiTokenSealed: store.sealField(store.openField(s.xwikiTokenSealed, sealAad(sid, "xwikiToken")), cleanupAad(oldId)),
        consentId: s.consentId ?? null, xwikiUser: s.xwikiUser, reason: "renewed",
        createdAt: deps.now(), attempts: 0, lastError: null,
      };
      s.xwikiTokenSealed = store.sealField(created.token, sealAad(sid, "xwikiToken"));
      s.consentId = created.consentId;
      s.tokenExpiresAt = created.expiresAt;
      s.tokenVersion = (s.tokenVersion || 1) + 1;
    });
    triggerCleanups(deps);
  } catch (e) {
    console.warn(`[session] XWiki token renewal failed: ${errCode(e)}`);
  }
}

// Daily reconcile with Authentik for every session (under its session lock): idle sessions
// and sessions whose code exchange never completed end; otherwise the stored Authentik refresh
// token is rotated and the user's group membership checked. lastClientRefreshAt is never
// touched, so this does not extend the 30-day idle limit. Afterwards cleanups, expired upload
// nonces and unused clients. Single-flight per store.
export function dailyReconcile(deps) {
  const running = reconcileRuns.get(deps.store);
  if (running) return running;
  const p = reconcile(deps).finally(() => reconcileRuns.delete(deps.store));
  reconcileRuns.set(deps.store, p);
  return p;
}

async function reconcile(deps) {
  const { store } = deps;
  for (const sid of Object.keys(store.read().sessions)) {
    try {
      await store.withLock(lockKey(sid), () => reconcileSession(deps, sid));
    } catch (e) {
      console.warn(`[reconcile] session check failed: ${errCode(e)}`);
    }
  }
  await runCleanups(deps);
  const now = deps.now();
  await store.mutate((state) => {
    for (const [nonce, exp] of Object.entries(state.uploadNonces)) {
      if (!(typeof exp === "number" && exp > now)) delete state.uploadNonces[nonce];
    }
    const used = new Set(Object.values(state.sessions).map((s) => s?.clientId));
    for (const [clientId, c] of Object.entries(state.clients)) {
      if (used.has(clientId) || now - (c?.lastUsedAt || 0) <= CLIENT_IDLE_MS) continue;
      delete state.clients[clientId];
      for (const key of Object.keys(state.grants)) {
        if (key.slice(key.lastIndexOf("|") + 1) === clientId) delete state.grants[key];
      }
    }
  });
}

async function reconcileSession(deps, sid) {
  const { store, authentik } = deps;
  const state = store.read();
  const session = state.sessions[sid];
  if (!session) return;
  const now = deps.now();
  if (now - session.lastClientRefreshAt > IDLE_MS) {
    await endSession(deps, sid, "idle");
    return;
  }
  const family = state.families[session.familyId];
  if ((!family || family.currentHash === null) && now - session.createdAt > ORPHAN_MS) {
    await endSession(deps, sid, "orphan");
    return;
  }
  // Returns normally if the session check is over (ended or skipped); rethrows the rest.
  const handle = async (e) => {
    if (e instanceof AuthentikRejected) await endSession(deps, sid, "authentik-rejected");
    else if (!(e instanceof AuthentikUnavailable)) throw e; // unavailable: try again tomorrow
  };
  let ak;
  try {
    ak = await authentik.refresh(store.openField(session.authentikRefreshSealed, sealAad(sid, "authentikRefresh")));
  } catch (e) {
    return handle(e);
  }
  const authentikRefreshSealed = store.sealField(ak.refreshToken, sealAad(sid, "authentikRefresh"));
  await store.mutate((draft) => {
    const s = draft.sessions[sid];
    if (s) s.authentikRefreshSealed = authentikRefreshSealed;
  });
  try {
    await authentik.checkUser(ak.accessToken);
  } catch (e) {
    return handle(e);
  }
}

// Background jobs: first reconcile 5 min after start, then every 24 h; cleanups hourly.
// Timers are unref'd; returns stop() (tests).
export function startBackground(deps, {
  firstDelayMs = 5 * 60 * 1000, reconcileEveryMs = DAY_MS, cleanupEveryMs = 60 * 60 * 1000,
} = {}) {
  const reconcileNow = () => dailyReconcile(deps).catch((e) => console.warn(`[reconcile] run failed: ${errCode(e)}`));
  let daily = null;
  const first = setTimeout(() => {
    reconcileNow();
    daily = setInterval(reconcileNow, reconcileEveryMs);
    daily.unref?.();
  }, firstDelayMs);
  first.unref?.();
  const hourly = setInterval(() => triggerCleanups(deps), cleanupEveryMs);
  hourly.unref?.();
  return () => {
    clearTimeout(first);
    if (daily) clearInterval(daily);
    clearInterval(hourly);
  };
}

// RFC 7009: maps a refresh token (current, replay or spent) or an access token of this
// server to its session and ends it with reason "revoked". An access token counts if its
// signature, issuer and audience are valid; expiry alone does not stop the revocation.
// Unknown tokens are ignored. The hint only changes the order of the lookups.
export async function revokeToken(deps, token, hint) {
  if (typeof token !== "string" || !token) return false;
  const byRefresh = () => findFamily(deps.store.read(), hashRefreshToken(token))?.sid ?? null;
  const byAccess = () => sidFromAccessToken(deps, token);
  const sid = hint === "access_token"
    ? (await byAccess()) ?? byRefresh()
    : byRefresh() ?? (await byAccess());
  if (!sid) return false;
  await deps.store.withLock(lockKey(sid), () => endSession(deps, sid, "revoked"));
  return true;
}

async function sidFromAccessToken(deps, token) {
  const { cfg } = deps;
  if (!token.includes(".")) return null;
  const opts = { issuer: cfg.mcpBaseUrl, audience: cfg.mcpBaseUrl, algorithms: ["HS256"], currentDate: new Date(deps.now()) };
  let payload;
  try {
    ({ payload } = await jwtVerify(token, new TextEncoder().encode(cfg.sessionSecret), opts));
  } catch (e) {
    // jose checks the signature before the claims, so an expired token got here genuine;
    // issuer and audience are checked by hand because claim validation may have stopped early.
    if (e?.code !== "ERR_JWT_EXPIRED" || !e.payload) return null;
    payload = e.payload;
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (payload.iss !== cfg.mcpBaseUrl || !aud.includes(cfg.mcpBaseUrl)) return null;
  }
  return typeof payload.sid === "string" && payload.sid ? payload.sid : null;
}

// After a successful code exchange: first refresh token of the family plus access token.
// lastClientRefreshAt stays as createSession set it.
export async function issueTokens(deps, { sid, familyId, clientId }) {
  const { store } = deps;
  return store.withLock(lockKey(sid), async () => {
    const state = store.read();
    const session = state.sessions[sid];
    const family = state.families[familyId];
    if (!session || !family || family.sid !== sid || family.clientId !== clientId || session.clientId !== clientId) {
      throw invalidGrant();
    }
    const refreshToken = newRefreshToken();
    const response = await buildResponse(deps, session, refreshToken, deps.now());
    await store.mutate((draft) => {
      const f = draft.families[familyId];
      if (!draft.sessions[sid] || !f) throw invalidGrant();
      if (f.currentHash) f.spentHashes = [...(f.spentHashes || []), f.currentHash].slice(-MAX_SPENT);
      f.currentHash = hashRefreshToken(refreshToken);
    });
    return response;
  });
}

function findFamily(state, hash) {
  for (const f of Object.values(state.families)) {
    if (!f) continue;
    if (f.currentHash === hash || f.replay?.hash === hash || (f.spentHashes || []).includes(hash)) return f;
  }
  return null;
}

// Maps Authentik errors: rejected → session ends; unavailable → 503 with nothing changed.
async function authentikStep(deps, sid, fn) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof AuthentikRejected) {
      await endSession(deps, sid, "authentik-rejected");
      throw invalidGrant();
    }
    if (e instanceof AuthentikUnavailable) throw new TokenError("temporarily_unavailable", 503);
    throw e;
  }
}

// Rotates a refresh token. The family is looked up outside the lock; inside the lock
// `session:<sid>` everything is re-read and re-validated, so a second concurrent call with
// the same token finds it as replay.hash and gets the stored response.
//
// The rotation counts only once the final mutate has written. If that write fails, the
// client gets an error and keeps the old token, which stays valid on the server too.
// Known limitation: Authentik may already have rotated its refresh token at that point; the
// server keeps the old Authentik token, and if Authentik invalidated it, the next refresh
// ends the session with "authentik-rejected".
export async function refreshSession(deps, { refreshToken, clientId }) {
  const { store, authentik } = deps;
  if (typeof refreshToken !== "string" || !refreshToken) throw invalidGrant();
  const hash = hashRefreshToken(refreshToken);
  const found = findFamily(store.read(), hash);
  if (!found) throw invalidGrant();
  const { familyId, sid } = found;

  return store.withLock(lockKey(sid), async () => {
    let state = store.read();
    const family = state.families[familyId];
    let session = state.sessions[sid];
    if (!family || !session || family.sid !== sid) throw invalidGrant();
    // Public client ids carry no security value; the binding is the refresh token itself.
    // Step 2 (checked wherever tokens would be handed out): client_id is optional for
    // public clients (RFC 6749 §6); if sent it must match the family.
    const clientOk = clientId === undefined || clientId === family.clientId;
    const start = deps.now();

    // Step 1: classify the presented token. Reuse of a spent token ends the session
    // whoever presents it.
    // There is a single replay slot: a second rotation within 30 s (A→B→C) overwrites it
    // with B, so A is then treated as reuse and ends the session. At now === until the
    // window is closed (reuse as well).
    if (family.currentHash !== hash) {
      if (family.replay?.hash === hash && start < family.replay.until) {
        if (!clientOk) throw invalidGrant();
        return JSON.parse(store.openField(family.replay.responseSealed, replayAad(familyId)));
      }
      if (family.replay?.hash === hash || (family.spentHashes || []).includes(hash)) {
        await endSession(deps, sid, "refresh-reuse");
      }
      throw invalidGrant();
    }
    if (!clientOk) throw invalidGrant();

    // Step 3: 30 days without a client refresh.
    if (start - session.lastClientRefreshAt > IDLE_MS) {
      await endSession(deps, sid, "idle");
      throw invalidGrant();
    }

    // Step 4: Authentik refresh and group check.
    const oldAkRefresh = store.openField(session.authentikRefreshSealed, sealAad(sid, "authentikRefresh"));
    const ak = await authentikStep(deps, sid, () => authentik.refresh(oldAkRefresh));
    await authentikStep(deps, sid, () => authentik.checkUser(ak.accessToken));

    // Step 5: XWiki token renewal (Task 10); never fails the refresh.
    if (session.tokenExpiresAt - start < RENEW_BEFORE_MS) {
      try {
        await renewXWikiToken(deps, sid);
      } catch (e) {
        console.warn(`[session] XWiki token renewal failed: ${e?.code || e?.name || "error"}`);
      }
      state = store.read();
      session = state.sessions[sid];
      if (!session || !state.families[familyId]) throw invalidGrant();
    }

    // Step 6: one write for the whole rotation; the answer leaves only after it.
    const now = deps.now();
    const newToken = newRefreshToken();
    const response = await buildResponse(deps, session, newToken, now);
    const responseSealed = store.sealField(JSON.stringify(response), replayAad(familyId));
    const authentikRefreshSealed = store.sealField(ak.refreshToken, sealAad(sid, "authentikRefresh"));
    await store.mutate((draft) => {
      const s = draft.sessions[sid];
      const f = draft.families[familyId];
      if (!s || !f || f.currentHash !== hash) throw invalidGrant();
      s.authentikRefreshSealed = authentikRefreshSealed;
      s.lastClientRefreshAt = now;
      f.spentHashes = [...(f.spentHashes || []), hash].slice(-MAX_SPENT);
      f.currentHash = hashRefreshToken(newToken);
      // Overwrites the previous slot; the token rotated before stays only in spentHashes.
      f.replay = { hash, responseSealed, until: now + REPLAY_MS };
      if (draft.clients[f.clientId]) draft.clients[f.clientId].lastUsedAt = now;
    });
    return response;
  });
}
