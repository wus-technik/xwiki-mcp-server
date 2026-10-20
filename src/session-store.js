import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, renameSync } from "node:fs";

const authStates = new Map();
const authCodes  = new Map();
const sessions   = new Map();
const consumedUploadNonces = new Map(); // nonce -> expiresAt (mirrors the upload token's own expiry)

const AUTH_STATE_TTL = 10 * 60 * 1000;
const AUTH_CODE_TTL  = 5 * 60 * 1000;
const SESSION_TTL    = 7 * 24 * 60 * 60 * 1000;

// Sessions are written through to this file so a container recreate does not log everyone out.
// Auth states and codes stay in memory only: they live minutes and a lost one just means a retry.
let sessionFile = null;

export function configureSessionPersistence(filePath, { reset = false } = {}) {
  sessionFile = filePath || null;
  if (reset) sessions.clear();
  if (!sessionFile) return;

  let stored = {};
  try {
    stored = JSON.parse(readFileSync(sessionFile, "utf8"));
  } catch (e) {
    if (e.code !== "ENOENT") console.warn(`[session-store] ignoring unreadable ${sessionFile}: ${e.message}`);
  }
  const now = Date.now();
  for (const [id, session] of Object.entries(stored)) {
    if (session && session.expiresAt > now) sessions.set(id, session);
  }
  persistSessions();
}

function persistSessions() {
  if (!sessionFile) return;
  try {
    const tmp = `${sessionFile}.tmp`;
    // The file holds live XWiki session cookies: owner-only.
    writeFileSync(tmp, JSON.stringify(Object.fromEntries(sessions)), { mode: 0o600 });
    renameSync(tmp, sessionFile);
  } catch (e) {
    console.warn(`[session-store] could not persist sessions: ${e.message}`);
  }
}

export function storeAuthState(state, data) {
  authStates.set(state, { ...data, createdAt: Date.now() });
}

export function consumeAuthState(state) {
  const data = authStates.get(state);
  authStates.delete(state);
  if (!data || Date.now() - data.createdAt > AUTH_STATE_TTL) return undefined;
  return data;
}

export function storeAuthCode(code, sessionId, codeChallenge) {
  authCodes.set(code, { sessionId, codeChallenge, expiresAt: Date.now() + AUTH_CODE_TTL });
}

export function consumeAuthCode(code) {
  const data = authCodes.get(code);
  authCodes.delete(code);
  if (!data || Date.now() > data.expiresAt) return null;
  return data;
}

export function createSession(userId, xwikiCookie) {
  const sessionId = randomUUID();
  sessions.set(sessionId, { userId, xwikiCookie, expiresAt: Date.now() + SESSION_TTL });
  persistSessions();
  return sessionId;
}

export function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    persistSessions();
    return null;
  }
  return session;
}

export function deleteSession(sessionId) {
  if (sessions.delete(sessionId)) persistSessions();
}

export function listSessions() {
  const now = Date.now();
  return [...sessions]
    .filter(([, s]) => s.expiresAt > now)
    .map(([sessionId, s]) => ({ ...s, sessionId }));
}

// ponytail: sweeps the whole map on every check; upload tokens live 5 minutes so this
// stays tiny in practice — switch to a timer-based sweep if upload volume grows a lot.
function sweepConsumedUploadNonces() {
  const now = Date.now();
  for (const [nonce, expiresAt] of consumedUploadNonces) {
    if (now > expiresAt) consumedUploadNonces.delete(nonce);
  }
}

export function isUploadNonceConsumed(nonce) {
  sweepConsumedUploadNonces();
  return consumedUploadNonces.has(nonce);
}

export function markUploadNonceConsumed(nonce, expiresAt) {
  consumedUploadNonces.set(nonce, expiresAt);
}
