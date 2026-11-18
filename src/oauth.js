import { Router } from "express";
import { randomUUID, randomBytes, createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isAllowedRedirect, redirectMatches } from "./redirects.js";
import { AuthentikError, AuthentikRejected, AuthentikUnavailable } from "./authentik.js";
import {
  createSession, addPendingCreate, removeCleanup, recoverPendingCreates, issueTokens, refreshSession, revokeToken, TokenError,
} from "./sessions.js";
import { createAuthDebugLogger } from "./auth-debug.js";

// Login flow: /authorize → Authentik → XWiki login (same origin) → /oauth/complete
// → consent (once per user and client) → XWiki consent token → session → code.
// The user's XWiki browser cookie is used only inside one request to create the
// token and is never stored or logged.

const FLOW_COOKIE = "xmcp_flow";
// Routes are mounted under /mcp (see app.js); the cookie must reach callback/complete/consent.
const FLOW_PATH = "/mcp/oauth";
const STATE_TTL = 10 * 60 * 1000;
const PENDING_TTL = 10 * 60 * 1000;
const CODE_TTL = 5 * 60 * 1000;
const MAX_FLOWS = 10000; // /authorize is anonymous: cap the in-memory state
const SWEEP_INTERVAL = 60 * 1000;
const TOKEN_DAYS = 90;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43,128}$/;
const VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/; // RFC 7636 §4.1
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

class FlowFullError extends Error {}

function ttlMap(now, ttl, max = Infinity) {
  const m = new Map();
  const sweep = () => {
    const t = now();
    for (const [k, e] of m) if (t > e.expiresAt) m.delete(k);
  };
  const get = (key) => {
    if (typeof key !== "string") return null;
    const e = m.get(key);
    if (!e) return null;
    if (now() > e.expiresAt) {
      m.delete(key);
      return null;
    }
    return e.value;
  };
  return {
    put(key, value) {
      sweep();
      if (m.size >= max) throw new FlowFullError("too many pending flows");
      m.set(key, { value, expiresAt: now() + ttl });
    },
    get,
    take(key) {
      const v = get(key);
      if (v) m.delete(key);
      return v;
    },
    delete: (key) => m.delete(key),
    sweep,
    size: () => m.size,
  };
}

const rand = () => randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const own = (obj, key) => (obj && Object.hasOwn(obj, key) ? obj[key] : undefined);

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// Mapping Authentik → XWiki (test/fixtures/xwiki-18.7.0/README.md): preferred_username
// without dots, lower-cased, e.g. "max.mustermann" → "xwiki:XWiki.maxmustermann".
export function expectedXWikiUser(username) {
  return `xwiki:XWiki.${String(username).replace(/\./g, "").toLowerCase()}`;
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function redirectTargetLabel(uri) {
  try {
    const u = new URL(uri);
    return LOOPBACK_HOSTS.has(u.hostname) ? "lokales Programm auf diesem Rechner" : u.origin;
  } catch {
    return "unbekannt";
  }
}

function flowHeaders(res) {
  res.set("Referrer-Policy", "no-referrer");
  res.set("Cache-Control", "no-store");
  res.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
  res.set("X-Frame-Options", "DENY");
}

function htmlPage(title, body) {
  return `<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#222}
button{font-size:1rem;padding:.5rem 1.2rem;margin-right:.5rem}dt{font-weight:600}dd{margin:0 0 .6rem 0}</style>
</head><body><h1>${esc(title)}</h1>${body}</body></html>`;
}

export function sendError(res, status, message, code) {
  flowHeaders(res);
  const detail = code ? `<p><small>Fehlercode: ${esc(code)}</small></p>` : "";
  res.status(status).type("html").send(htmlPage("Anmeldung nicht möglich", `<p>${esc(message)}</p>${detail}`));
}

// Authorization response redirect; `iss` is the RFC 9207 issuer (= metadata issuer).
function redirectToClient(res, flow, params, issuer) {
  const u = new URL(flow.redirectUri);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  u.searchParams.set("state", flow.clientState);
  u.searchParams.set("iss", issuer);
  flowHeaders(res);
  res.redirect(302, u.toString());
}

// The XWiki session cookie of this request, without our own flow cookie.
function xwikiCookieOf(req) {
  return String(req.headers.cookie || "")
    .split(";")
    .map((c) => c.trim())
    .filter((c) => c && !c.startsWith(`${FLOW_COOKIE}=`))
    .join("; ");
}

export function createOAuthHandlers(cfg, deps = {}) {
  const {
    mcpBaseUrl,
    sessionSecret = "",
    store,
    extraRedirectUris = [],
  } = cfg;
  const { authentik, xwikiTokens } = deps;
  const now = deps.now || Date.now;
  const logger = deps.logger || createAuthDebugLogger(cfg.authDebug);
  const sessionDeps = { store, cfg, authentik, xwikiTokens, now };

  const flows = ttlMap(now, STATE_TTL, MAX_FLOWS); // serverState → flow
  const pendings = ttlMap(now, PENDING_TTL); // pendingId → { flow, sub, username, authentikRefresh }
  const codes = ttlMap(now, CODE_TTL); // code → { sid, familyId, clientId, redirectUri, codeChallenge, resource }
  // Expired entries are dropped even if never accessed again (pendings hold the Authentik
  // refresh token in memory until then).
  const sweep = () => {
    flows.sweep();
    pendings.sweep();
    codes.sweep();
  };
  setInterval(sweep, SWEEP_INTERVAL).unref();

  // AUTH_DEBUG: event name, short sid, user and client name only (no request data).
  const log = (event, extra = {}) => logger.info(event, undefined, extra);
  const csrfFor = (pendingId) => createHmac("sha256", sessionSecret).update(`consent:${pendingId}`).digest("base64url");
  const flowCookieMatches = (req, flow) => safeEqual(req.cookies?.[FLOW_COOKIE], flow.flowId);
  const clearFlowCookie = (res) => res.clearCookie(FLOW_COOKIE, { secure: true, httpOnly: true, sameSite: "lax", path: FLOW_PATH });

  const register = async (req, res) => {
    const body = req.body;
    const uris = body && typeof body === "object" ? body.redirect_uris : undefined;
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return res.status(400).json({ error: "invalid_client_metadata" });
    }
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > 20) {
      return res.status(400).json({ error: "invalid_redirect_uri" });
    }
    if (!uris.every((u) => typeof u === "string" && isAllowedRedirect(u, extraRedirectUris))) {
      return res.status(400).json({ error: "invalid_redirect_uri" });
    }
    if (body.client_name !== undefined && typeof body.client_name !== "string") {
      return res.status(400).json({ error: "invalid_client_metadata" });
    }
    if (!store) {
      console.error("[register] no store configured");
      return res.status(500).json({ error: "server_error" });
    }
    const clientName = (body.client_name || "").trim().slice(0, 200) || "unbenannter Client";
    const clientId = randomUUID();
    const ts = Date.now();
    try {
      await store.mutate((state) => {
        state.clients[clientId] = {
          clientId, clientName, redirectUris: [...uris], createdAt: ts, lastUsedAt: ts,
        };
      });
    } catch (e) {
      console.error("[register] store write failed:", e.message);
      return res.status(500).json({ error: "server_error" });
    }
    res.status(201).json({
      client_id: clientId,
      client_id_issued_at: Math.floor(ts / 1000),
      client_name: clientName,
      redirect_uris: uris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    });
  };

  const authorize = (req, res) => {
    flowHeaders(res);
    if (!store || !authentik) return sendError(res, 500, "Der Server ist nicht vollständig eingerichtet.", "server_error");
    const q = req.query;
    const clientId = str(q.client_id);
    const redirectUri = str(q.redirect_uri);
    const client = clientId ? own(store.read().clients, clientId) : undefined;
    if (!client) return sendError(res, 400, "Das Programm ist hier nicht registriert. Bitte die Verbindung im Programm neu einrichten.", "invalid_client");
    if (!redirectUri || !redirectMatches(client.redirectUris, redirectUri)) {
      return sendError(res, 400, "Die Rückleitungsadresse passt nicht zum registrierten Programm.", "invalid_request");
    }
    if (q.response_type !== "code") return sendError(res, 400, "Nicht unterstützte Anfrage.", "unsupported_response_type");
    const codeChallenge = str(q.code_challenge);
    if (q.code_challenge_method !== "S256" || !codeChallenge || !CHALLENGE_RE.test(codeChallenge)) {
      return sendError(res, 400, "Die Anfrage enthält keinen gültigen PKCE-Wert (S256).", "invalid_request");
    }
    const clientState = str(q.state);
    if (!clientState || clientState.length > 2048) return sendError(res, 400, "Die Anfrage enthält keinen gültigen state-Wert.", "invalid_request");
    // A trailing slash is tolerated: clients differ in whether they append one to the
    // resource URL; it names the same resource.
    let resource;
    if (q.resource !== undefined) {
      resource = str(q.resource);
      if (!resource || resource.replace(/\/$/, "") !== mcpBaseUrl) {
        return sendError(res, 400, "Die angefragte Ressource ist auf diesem Server nicht verfügbar.", "invalid_target");
      }
      resource = mcpBaseUrl;
    }

    const serverState = rand();
    const flowId = rand();
    const nonce = randomBytes(16).toString("hex");
    try {
      flows.put(serverState, { clientId, redirectUri, codeChallenge, clientState, resource, nonce, flowId });
    } catch (e) {
      if (e instanceof FlowFullError) return sendError(res, 503, "Zu viele offene Anmeldungen. Bitte später erneut versuchen.", "temporarily_unavailable");
      throw e;
    }
    res.cookie(FLOW_COOKIE, flowId, { secure: true, httpOnly: true, sameSite: "lax", path: FLOW_PATH, maxAge: STATE_TTL });
    log("authorize_start", { client: client.clientName });
    res.redirect(302, authentik.authorizeUrl({ state: serverState, nonce }));
  };

  function authentikFailure(res, e) {
    if (e instanceof AuthentikUnavailable) return sendError(res, 503, "Die Anmeldung (Authentik) ist gerade nicht erreichbar. Bitte später erneut versuchen.", "temporarily_unavailable");
    if (e instanceof AuthentikRejected) return sendError(res, 403, "Ihr Konto ist für den Zugriff auf XWiki über MCP nicht freigeschaltet.", "access_denied");
    if (e instanceof AuthentikError) return sendError(res, 400, "Die Anmeldung bei Authentik ist fehlgeschlagen. Bitte im Programm erneut verbinden.", "invalid_grant");
    console.error("[login] unexpected error during Authentik login");
    return sendError(res, 500, "Interner Fehler bei der Anmeldung.", "server_error");
  }

  const callback = async (req, res) => {
    flowHeaders(res);
    const state = str(req.query.state);
    const flow = state ? flows.take(state) : null;
    if (!flow) return sendError(res, 400, "Die Anmeldung ist abgelaufen oder ungültig. Bitte im Programm erneut verbinden.", "invalid_request");
    if (!flowCookieMatches(req, flow)) {
      return sendError(res, 400, "Die Anmeldung wurde in einem anderen Browser begonnen. Bitte im Programm erneut verbinden.", "invalid_request");
    }
    if (req.query.error !== undefined) return redirectToClient(res, flow, { error: "access_denied" }, mcpBaseUrl);
    const code = str(req.query.code);
    if (!code) return sendError(res, 400, "Authentik hat keinen Anmeldecode geliefert.", "invalid_request");

    let ak;
    try {
      ak = await authentik.exchangeCode(code, flow.nonce);
      await authentik.checkUser(ak.accessToken);
    } catch (e) {
      log("authentik_failed", { error: e?.code || "error" });
      return authentikFailure(res, e);
    }

    // XWiki's logincheck turns the Authentik SSO session into a XWiki session (cookie),
    // then follows xredirect same-origin to /oauth/complete, where that cookie arrives.
    const pendingId = rand();
    pendings.put(pendingId, { flow, sub: ak.sub, username: ak.username, authentikRefresh: ak.refreshToken });
    const xwikiOrigin = new URL(mcpBaseUrl).origin;
    const completeUrl = `${FLOW_PATH}/complete?t=${pendingId}`;
    res.redirect(302, `${xwikiOrigin}/bin/login/XWiki/XWikiLogin?xredirect=${encodeURIComponent(completeUrl)}`);
  };

  // Returns the XWiki user of the cookie if it is the expected one; otherwise answers with an
  // error page, drops the pending login and returns null.
  async function verifyIdentity(res, pendingId, pending, cookie) {
    const expected = expectedXWikiUser(pending.username);
    let actual;
    try {
      actual = cookie ? await xwikiTokens.whoami({ cookie }) : null;
    } catch (e) {
      pendings.delete(pendingId);
      if (e?.code === "unavailable") {
        sendError(res, 503, "XWiki ist gerade nicht erreichbar. Bitte später erneut versuchen.", "temporarily_unavailable");
      } else {
        sendError(res, 502, "XWiki hat unerwartet geantwortet. Bitte im Programm erneut verbinden.", "server_error");
      }
      return null;
    }
    if (actual !== expected) {
      pendings.delete(pendingId);
      log("identity_mismatch", { user: expected });
      sendError(res, 403, "Die XWiki-Anmeldung in diesem Browser gehört nicht zum angemeldeten Konto. Bitte in XWiki ab- und neu anmelden und dann erneut verbinden.", "access_denied");
      return null;
    }
    return actual;
  }

  function consentPage(res, pendingId, pending, xwikiUser, client) {
    flowHeaders(res);
    const body = `<p>Ein Programm möchte in Ihrem Namen auf XWiki zugreifen.</p>
<dl>
<dt>Angemeldet als</dt><dd>${esc(pending.username)} (${esc(xwikiUser)})</dd>
<dt>Programm</dt><dd>${esc(client.clientName)} (nicht geprüft)</dd>
<dt>Rückleitung an</dt><dd>${esc(redirectTargetLabel(pending.flow.redirectUri))}</dd>
</dl>
<p>Das Programm kann danach alles lesen und ändern, was Sie in XWiki lesen und ändern dürfen. Die Freigabe erscheint in XWiki in Ihrem Profil unter „Applications“ und kann dort widerrufen werden.</p>
<form method="post" action="${FLOW_PATH}/consent">
<input type="hidden" name="t" value="${esc(pendingId)}">
<input type="hidden" name="csrf" value="${esc(csrfFor(pendingId))}">
<button type="submit" name="action" value="allow">Zulassen</button>
<button type="submit" name="action" value="deny">Abbrechen</button>
</form>`;
    res.status(200).type("html").send(htmlPage("Zugriff auf XWiki erlauben?", body));
  }

  function sendBusy(res) {
    return sendError(res, 409, "Diese Anmeldung wird gerade in einem anderen Fenster abgeschlossen.", "invalid_request");
  }

  // Shared by both ways in (grant present / consent given). Serialized per XWiki user so the
  // pending-create recovery never mistakes an in-flight token of the same name for a leftover.
  async function finish(res, pending, xwikiUser, cookie, client) {
    const { flow } = pending;
    return store.withLock(`xwiki-user:${xwikiUser}`, async () => {
      await recoverPendingCreates(sessionDeps, { cookie, xwikiUser });
      const appName = `xwiki-mcp – ${client.clientName} – ${new Date(now()).toISOString().slice(0, 10)}`;
      let cleanupId;
      try {
        cleanupId = await addPendingCreate(sessionDeps, { xwikiUser, appName });
      } catch {
        console.error("[login] store write failed (pending-create)");
        return sendError(res, 500, "Interner Fehler beim Speichern. Bitte erneut verbinden.", "server_error");
      }
      let created;
      try {
        created = await xwikiTokens.createToken({ cookie }, { xwikiUser, appName, days: TOKEN_DAYS });
      } catch (e) {
        const code = e?.code || "error";
        console.warn(`[login] XWiki token creation failed: ${code}`);
        if (code === "login_required") {
          // Nothing was created: drop the marker.
          try {
            await removeCleanup(sessionDeps, cleanupId);
          } catch {
            console.error("[login] store write failed (drop pending-create)");
          }
          return sendError(res, 403, "Ihre XWiki-Anmeldung ist abgelaufen. Bitte im Programm erneut verbinden.", "login_required");
        }
        if (code === "unavailable") return sendError(res, 503, "XWiki ist gerade nicht erreichbar. Bitte später erneut verbinden.", "temporarily_unavailable");
        return sendError(res, 502, "XWiki konnte keinen Zugang anlegen. Bitte erneut verbinden.", "server_error");
      }
      let session;
      try {
        session = await createSession(sessionDeps, {
          sub: pending.sub,
          userId: pending.username,
          xwikiUser,
          clientId: flow.clientId,
          authentikRefresh: pending.authentikRefresh,
          xwikiToken: created.token,
          consentId: created.consentId,
          tokenExpiresAt: created.expiresAt,
          pendingCleanupId: cleanupId,
        });
      } catch {
        console.error("[login] store write failed (session)");
        return sendError(res, 500, "Interner Fehler beim Speichern. Bitte erneut verbinden.", "server_error");
      }
      const code = rand();
      codes.put(code, {
        sid: session.sid,
        familyId: session.familyId,
        clientId: flow.clientId,
        redirectUri: flow.redirectUri,
        codeChallenge: flow.codeChallenge,
        resource: flow.resource,
      });
      log("login_complete", { sid: session.sid.slice(0, 8), user: xwikiUser, client: client.clientName });
      clearFlowCookie(res);
      redirectToClient(res, flow, { code }, mcpBaseUrl);
    });
  }

  const complete = async (req, res) => {
    flowHeaders(res);
    const t = str(req.query.t);
    const pending = t ? pendings.get(t) : null;
    if (!pending) return sendError(res, 400, "Die Anmeldung ist abgelaufen oder ungültig. Bitte im Programm erneut verbinden.", "invalid_request");
    if (!flowCookieMatches(req, pending.flow)) {
      return sendError(res, 400, "Die Anmeldung wurde in einem anderen Browser begonnen. Bitte im Programm erneut verbinden.", "invalid_request");
    }
    // Claim before the first await: a parallel /complete or /consent for the same login
    // must not reach finish() a second time.
    if (pending.busy) return sendBusy(res);
    pending.busy = true;
    try {
      const cookie = xwikiCookieOf(req);
      const xwikiUser = await verifyIdentity(res, t, pending, cookie);
      if (!xwikiUser) return;
      const state = store.read();
      const client = own(state.clients, pending.flow.clientId);
      if (!client) {
        pendings.delete(t);
        return sendError(res, 400, "Das Programm ist nicht mehr registriert.", "invalid_client");
      }
      if (own(state.grants, `${pending.sub}|${pending.flow.clientId}`)) {
        pendings.delete(t);
        return await finish(res, pending, xwikiUser, cookie, client);
      }
      log("consent_shown", { user: xwikiUser, client: client.clientName });
      return consentPage(res, t, pending, xwikiUser, client);
    } finally {
      // Only matters on the consent-page path; every other path has removed the entry.
      pending.busy = false;
    }
  };

  const consent = async (req, res) => {
    flowHeaders(res);
    const t = str(req.body?.t);
    const pending = t ? pendings.get(t) : null;
    if (!pending) return sendError(res, 400, "Die Anmeldung ist abgelaufen oder ungültig. Bitte im Programm erneut verbinden.", "invalid_request");
    if (!flowCookieMatches(req, pending.flow) || !safeEqual(str(req.body?.csrf), csrfFor(t))) {
      return sendError(res, 403, "Die Bestätigung ist ungültig. Bitte im Programm erneut verbinden.", "access_denied");
    }
    const action = str(req.body?.action);
    if (action !== "allow" && action !== "deny") return sendError(res, 400, "Ungültige Auswahl.", "invalid_request");
    if (pending.busy) return sendBusy(res);
    // Taken synchronously, before any await: this login can be finished only once.
    pendings.delete(t);
    if (action === "deny") {
      log("consent_denied", {});
      clearFlowCookie(res);
      return redirectToClient(res, pending.flow, { error: "access_denied" }, mcpBaseUrl);
    }
    const cookie = xwikiCookieOf(req);
    const xwikiUser = await verifyIdentity(res, t, pending, cookie);
    if (!xwikiUser) return;
    const client = own(store.read().clients, pending.flow.clientId);
    if (!client) return sendError(res, 400, "Das Programm ist nicht mehr registriert.", "invalid_client");
    try {
      await store.mutate((state) => {
        state.grants[`${pending.sub}|${pending.flow.clientId}`] = { at: now() };
      });
    } catch {
      console.error("[login] store write failed (grant)");
      return sendError(res, 500, "Interner Fehler beim Speichern. Bitte erneut verbinden.", "server_error");
    }
    log("consent_granted", { user: xwikiUser, client: client.clientName });
    return finish(res, pending, xwikiUser, cookie, client);
  };

  // Single-use authorization codes (5 min), consumed by /token.
  const consumeCode = (code) => codes.take(code);

  // /token (RFC 6749): public clients only (token_endpoint_auth_method none), no secret.
  // Errors are JSON { error }; no request data or tokens are logged.
  const tokenError = (res, status, error) => res.status(status).json({ error });

  async function exchangeCode(req, res, body) {
    const code = str(own(body, "code"));
    const verifier = str(own(body, "code_verifier"));
    const clientId = str(own(body, "client_id"));
    const redirectUri = str(own(body, "redirect_uri"));
    const resourceRaw = own(body, "resource");
    if (!code || !verifier || !clientId || !redirectUri) return tokenError(res, 400, "invalid_request");
    if (resourceRaw !== undefined && !str(resourceRaw)) return tokenError(res, 400, "invalid_request");
    // Taken before any check: a failed attempt burns the code as well.
    const data = consumeCode(code);
    if (!data) return tokenError(res, 400, "invalid_grant");
    if (!VERIFIER_RE.test(verifier)) return tokenError(res, 400, "invalid_grant");
    const computed = createHash("sha256").update(verifier).digest("base64url");
    if (!safeEqual(computed, data.codeChallenge)) return tokenError(res, 400, "invalid_grant");
    if (clientId !== data.clientId || redirectUri !== data.redirectUri) return tokenError(res, 400, "invalid_grant");
    // RFC 8707: the resource may be omitted; if sent it must name this server (and the
    // one bound to the code, if any). Trailing slash tolerated as at /authorize.
    if (resourceRaw !== undefined) {
      const resource = resourceRaw.replace(/\/$/, "");
      if (resource !== (data.resource || mcpBaseUrl)) return tokenError(res, 400, "invalid_target");
    }
    const response = await issueTokens(sessionDeps, { sid: data.sid, familyId: data.familyId, clientId: data.clientId });
    log("token_issued", { sid: data.sid.slice(0, 8) });
    return res.json(response);
  }

  const token = async (req, res) => {
    res.set("Cache-Control", "no-store");
    res.set("Pragma", "no-cache");
    const body = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
    const grantType = str(own(body, "grant_type"));
    if (!grantType) return tokenError(res, 400, "invalid_request");
    if (grantType !== "authorization_code" && grantType !== "refresh_token") return tokenError(res, 400, "unsupported_grant_type");
    if (!store) {
      console.error("[token] no store configured");
      return tokenError(res, 500, "server_error");
    }
    try {
      if (grantType === "authorization_code") return await exchangeCode(req, res, body);
      const refreshToken = str(own(body, "refresh_token"));
      const clientIdRaw = own(body, "client_id");
      if (!refreshToken || (clientIdRaw !== undefined && !str(clientIdRaw))) return tokenError(res, 400, "invalid_request");
      const response = await refreshSession(sessionDeps, { refreshToken, clientId: clientIdRaw });
      return res.json(response);
    } catch (e) {
      if (e instanceof TokenError) {
        log("token_failed", { error: e.code });
        return tokenError(res, e.status, e.code);
      }
      console.error(`[token] failed: ${e?.code || e?.name || "error"}`);
      return tokenError(res, 500, "server_error");
    }
  };

  // RFC 7009 revocation: form or JSON, parameter token, optional token_type_hint. A refresh
  // token (current, replay or spent) or an access token of this server ends its session.
  // Unknown or invalid tokens are answered with 200 as well; only a missing token is 400.
  const revoke = async (req, res) => {
    res.set("Cache-Control", "no-store");
    res.set("Pragma", "no-cache");
    const body = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
    const tokenValue = str(own(body, "token"));
    if (!tokenValue) return tokenError(res, 400, "invalid_request");
    if (!store) {
      console.error("[revoke] no store configured");
      return tokenError(res, 500, "server_error");
    }
    try {
      if (await revokeToken(sessionDeps, tokenValue, str(own(body, "token_type_hint")))) log("token_revoked", {});
    } catch (e) {
      // The session could not be ended (store write failed): not revoked, so no 200.
      console.error(`[revoke] failed: ${e?.code || e?.name || "error"}`);
      return tokenError(res, 503, "temporarily_unavailable");
    }
    return res.status(200).json({});
  };

  const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

  return {
    register,
    authorize,
    callback: wrap(callback),
    complete: wrap(complete),
    consent: wrap(consent),
    token: wrap(token),
    revoke: wrap(revoke),
    consumeCode,
    sweep,
    stats: () => ({ flows: flows.size(), pendings: pendings.size(), codes: codes.size() }),
  };
}

export function createOAuthRouter(h) {
  const router = Router();
  router.post("/oauth/register", h.register);
  router.get("/oauth/authorize", h.authorize);
  router.get("/oauth/callback", h.callback);
  router.get("/oauth/complete", h.complete);
  router.post("/oauth/consent", h.consent);
  router.post("/oauth/token", h.token);
  router.post("/oauth/revoke", h.revoke);
  return router;
}
