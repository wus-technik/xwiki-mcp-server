import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT, createLocalJWKSet } from "jose";
import {
  createAuthentik,
  AuthentikError,
  AuthentikRejected,
  AuthentikUnavailable,
} from "../src/authentik.js";

const ISSUER = "https://auth.example";
const IDP_ISS = `${ISSUER}/application/o/xwiki-mcp/`;
const { publicKey, privateKey } = await generateKeyPair("RS256");
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
const jwks = createLocalJWKSet({ keys: [jwk] });

async function idToken(over = {}, { exp = "5m" } = {}) {
  const claims = { nonce: "n1", preferred_username: "alice", ...over.claims };
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(over.iss ?? IDP_ISS)
    .setAudience(over.aud ?? "cid")
    .setSubject("sub-1")
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(privateKey);
}

const json = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

function make(fetcher, extra = {}) {
  return createAuthentik({
    issuer: ISSUER,
    clientId: "cid",
    clientSecret: "csec",
    redirectUri: "https://x.example/mcp/oauth/callback",
    allowedGroups: ["AdminsIT", "xwiki_redaktion"],
    fetcher,
    jwks,
    ...extra,
  });
}

test("authorizeUrl enthaelt alle Parameter", () => {
  const u = new URL(make(async () => {}).authorizeUrl({ state: "s1", nonce: "n1" }));
  assert.equal(u.origin + u.pathname, `${ISSUER}/application/o/authorize/`);
  assert.equal(u.searchParams.get("response_type"), "code");
  assert.equal(u.searchParams.get("client_id"), "cid");
  assert.equal(u.searchParams.get("redirect_uri"), "https://x.example/mcp/oauth/callback");
  assert.equal(u.searchParams.get("scope"), "openid profile email offline_access");
  assert.equal(u.searchParams.get("state"), "s1");
  assert.equal(u.searchParams.get("nonce"), "n1");
});

test("exchangeCode: gueltiges ID-Token", async () => {
  let call;
  const a = make(async (url, init) => {
    call = { url, init };
    return json(200, { id_token: await idToken(), refresh_token: "rt1", access_token: "at" });
  });
  const r = await a.exchangeCode("code1", "n1");
  assert.deepEqual(r, { sub: "sub-1", username: "alice", refreshToken: "rt1" });
  assert.equal(call.url, `${ISSUER}/application/o/token/`);
  assert.equal(call.init.method, "POST");
  assert.match(call.init.headers["Content-Type"], /x-www-form-urlencoded/);
  const p = new URLSearchParams(call.init.body);
  assert.equal(p.get("grant_type"), "authorization_code");
  assert.equal(p.get("code"), "code1");
  assert.equal(p.get("client_id"), "cid");
  assert.equal(p.get("client_secret"), "csec");
  assert.equal(p.get("redirect_uri"), "https://x.example/mcp/oauth/callback");
});

test("exchangeCode: falsche nonce, aud, abgelaufen, falscher iss", async () => {
  const cases = [
    await idToken({ claims: { nonce: "other" } }),
    await idToken({ aud: "evil" }),
    await idToken({ iss: "https://evil.example/" }),
    await idToken({}, { exp: Math.floor(Date.now() / 1000) - 3600 }),
  ];
  for (const id_token of cases) {
    const a = make(async () => json(200, { id_token, refresh_token: "rt" }));
    await assert.rejects(a.exchangeCode("c", "n1"), (e) => e instanceof AuthentikError && e.code === "invalid_id_token");
  }
});

test("exchangeCode: fehlendes preferred_username -> invalid_id_token", async () => {
  const id_token = await idToken({ claims: { preferred_username: undefined } });
  const a = make(async () => json(200, { id_token, refresh_token: "rt" }));
  await assert.rejects(a.exchangeCode("c", "n1"), (e) => e.code === "invalid_id_token");
});

test("exchangeCode: ohne refresh_token -> no_refresh_token", async () => {
  const a = make(async () => json(200, { id_token: await idToken() }));
  await assert.rejects(a.exchangeCode("c", "n1"), (e) => e instanceof AuthentikError && e.code === "no_refresh_token");
});

test("exchangeCode: non-2xx -> exchange_failed, Netzfehler/Timeout -> Unavailable, ohne Geheimnisse", async () => {
  const a = make(async () => json(400, { error: "invalid_grant", refresh_token: "SECRETRT" }));
  await assert.rejects(a.exchangeCode("c", "n1"), (e) => e.code === "exchange_failed" && !e.message.includes("SECRETRT"));
  const b = make(async () => {
    throw new Error("ECONNREFUSED");
  });
  await assert.rejects(b.exchangeCode("c", "n1"), AuthentikUnavailable);
  const c = make((url, init) => new Promise((_, rej) => init.signal.addEventListener("abort", () => rej(init.signal.reason))), { timeoutMs: 20 });
  await assert.rejects(c.exchangeCode("c", "n1"), AuthentikUnavailable);
});

test("refresh: Erfolg, altes Refresh-Token bleibt, wenn kein neues kommt", async () => {
  let body;
  const a = make(async (url, init) => {
    body = new URLSearchParams(init.body);
    return json(200, { access_token: "at2" });
  });
  assert.deepEqual(await a.refresh("old"), { refreshToken: "old", accessToken: "at2" });
  assert.equal(body.get("grant_type"), "refresh_token");
  assert.equal(body.get("refresh_token"), "old");
  assert.equal(body.get("client_secret"), "csec");
  const b = make(async () => json(200, { access_token: "at3", refresh_token: "new" }));
  assert.deepEqual(await b.refresh("old"), { refreshToken: "new", accessToken: "at3" });
});

test("refresh: 400/401 -> Rejected, 503/Netz -> Unavailable", async () => {
  for (const s of [400, 401]) {
    await assert.rejects(make(async () => json(s, { error: "invalid_grant" })).refresh("rt"), AuthentikRejected);
  }
  await assert.rejects(make(async () => json(503, {})).refresh("rt"), AuthentikUnavailable);
  await assert.rejects(
    make(async () => {
      throw new Error("boom rt-secret");
    }).refresh("rt-secret"),
    (e) => e instanceof AuthentikUnavailable && !e.message.includes("rt-secret"),
  );
});

test("refresh: 2xx ohne access_token -> Rejected", async () => {
  await assert.rejects(make(async () => json(200, {})).refresh("rt"), AuthentikRejected);
});

test("checkUser: Gruppen und Fehlerabbildung", async () => {
  let call;
  const ok = make(async (url, init) => {
    call = { url, init };
    return json(200, { groups: ["xwiki_redaktion"] });
  });
  await ok.checkUser("at");
  assert.equal(call.url, `${ISSUER}/application/o/userinfo/`);
  assert.equal(call.init.headers.Authorization, "Bearer at");
  await assert.rejects(make(async () => json(200, { groups: ["Mitarbeiter"] })).checkUser("at"), AuthentikRejected);
  await assert.rejects(make(async () => json(200, {})).checkUser("at"), AuthentikRejected);
  await assert.rejects(make(async () => json(200, { groups: "AdminsIT" })).checkUser("at"), AuthentikRejected);
  await assert.rejects(make(async () => json(401, {})).checkUser("at"), AuthentikRejected);
  await assert.rejects(make(async () => json(502, {})).checkUser("at"), AuthentikUnavailable);
  await assert.rejects(make(async () => { throw new Error("x"); }).checkUser("at"), AuthentikUnavailable);
});
