import { randomUUID } from "node:crypto";

const authStates = new Map();
const authCodes  = new Map();
const sessions   = new Map();
const consumedUploadNonces = new Map(); // nonce -> expiresAt (mirrors the upload token's own expiry)

const AUTH_STATE_TTL = 10 * 60 * 1000;
const AUTH_CODE_TTL  = 5 * 60 * 1000;
const SESSION_TTL    = 7 * 24 * 60 * 60 * 1000;

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
  return sessionId;
}

export function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

export function deleteSession(sessionId) {
  sessions.delete(sessionId);
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
