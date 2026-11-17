// MCP sessions in the persistent store. Part 1: creating a session at login and
// recovering leftovers of interrupted token creations (pending-create cleanups).
//
// deps = { store, cfg, authentik, xwikiTokens, now } where now() returns ms.
// Secrets rule: tokens, cookies and refresh tokens are only ever stored sealed and
// never logged; log lines carry error codes only.
import { randomUUID } from "node:crypto";

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
