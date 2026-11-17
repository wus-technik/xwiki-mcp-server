// MCP sessions in the persistent store. Part 1: creating a session at login and
// recovering leftovers of interrupted token creations (pending-create cleanups).
// Part 2: issuing and rotating client tokens (access JWT + refresh token families).
//
// deps = { store, cfg, authentik, xwikiTokens, now } where now() returns ms.
// Secrets rule: tokens, cookies and refresh tokens are only ever stored sealed and
// never logged; log lines carry error codes only.
import { randomUUID, randomBytes, createHash } from "node:crypto";
import { SignJWT } from "jose";
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
      const fresh = deps.store.read();
      const referenced = new Set();
      for (const s of Object.values(fresh.sessions)) if (s?.consentId) referenced.add(s.consentId);
      for (const c of Object.values(fresh.cleanups)) if (c && c.id !== entry.id && c.consentId) referenced.add(c.consentId);
      const found = await deps.xwikiTokens.findTokensByPrefix({ cookie }, xwikiUser, entry.appName);
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

// Minimal end of a session (Task 10 adds runCleanups after it): ONE mutate that records a
// cleanup entry for the XWiki token and removes session and family. The XWiki token is
// re-sealed under the cleanup's own AAD `cleanup:<id>:xwikiToken`, so the entry can be
// opened without the (deleted) session id. No XWiki calls here.
export async function endSession(deps, sid, reason) {
  const { store } = deps;
  const id = randomUUID();
  const now = deps.now();
  let ended = false;
  await store.mutate((state) => {
    const s = state.sessions[sid];
    if (!s) return;
    const xwikiTokenSealed = s.xwikiTokenSealed
      ? store.sealField(store.openField(s.xwikiTokenSealed, sealAad(sid, "xwikiToken")), `cleanup:${id}:xwikiToken`)
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
  if (ended) console.warn(`[session] ended: ${reason}`);
  return ended ? id : null;
}

// Renews the XWiki token when it has less than 14 days left.
export async function renewXWikiToken(_deps, _sid) {
  // implemented in Task 10
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
