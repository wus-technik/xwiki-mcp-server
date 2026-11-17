import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  createXWikiTokens,
  parseCreatedToken,
  parseConsentList,
  XWikiTokenError,
} from "../src/xwiki-tokens.js";

const FIX = new URL("./fixtures/xwiki-18.7.0/", import.meta.url);
const FORM_TOKEN = "TESTFORMTOKEN+abc/123==";
const COOKIE = "JSESSIONID=SECRETCOOKIE123";
const USER = "xwiki:XWiki.foellmann";
const BASE = "https://xwiki.example.com";
const PAGE_URL = `${BASE}/bin/view/XWiki/foellmann?category=userapplications`;

const rawCreated = readFileSync(new URL("created.html", FIX), "utf8");
const rawList = readFileSync(new URL("list.html", FIX), "utf8");
const withFT = (h) => h.replaceAll("REDACTED-FORM-TOKEN", FORM_TOKEN);
const LIST = withFT(rawList);
const CREATED = withFT(rawCreated);
const TOKEN = `${USER}/6/REDACTED-RANDOM`;
const BOX = '<div class="box">\n<div class="pull-left">';

function removeBox(html, idx) {
  return html
    .split(BOX)
    .filter((p) => !p.includes(`ConsentClass[${idx}]"`))
    .join(BOX);
}

const html = (body, status = 200, headers = {}) =>
  new Response(body, { status, headers: { "content-type": "text/html", ...headers } });

function mk(handler) {
  const calls = [];
  const fetcher = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    return handler(String(url), init, calls);
  };
  return { api: createXWikiTokens({ baseUrl: BASE, fetcher }), calls };
}

const rest = (user) =>
  new Response("{}", { status: 200, headers: user ? { "XWiki-User": user } : {} });

test("parseCreatedToken liest den Token aus dem Fixture", () => {
  assert.equal(parseCreatedToken(rawCreated), TOKEN);
  assert.equal(parseCreatedToken(rawList), null);
});

test("parseConsentList liest die Liste aus dem Fixture", () => {
  const list = parseConsentList(rawList);
  assert.equal(list.length, 5);
  assert.deepEqual(list.map((e) => e.name), ["local", "token", "token2", "lab", "lab2"]);
  list.forEach((e, i) => assert.equal(e.consentId, `${USER}^XWiki.OIDC.ConsentClass[${i}]`));
  assert.equal(list[0].expired, true);
  assert.equal(list[0].expiresAt, 0);
  assert.equal(list[3].expired, false);
  assert.equal(list[3].expiresAt, Date.UTC(2026, 11, 10, 23, 59, 59, 999));
  assert.equal(parseConsentList(rawCreated).length, 7);
  assert.equal(parseConsentList(rawCreated)[6].name, "mcp-vortest-2");
});

test("parseConsentList dekodiert Entities im Namen", () => {
  const h = rawList.replace(
    "<strong>lab2</strong>",
    "<strong>a &amp; b &lt;x&gt; &quot;q&quot; &#39;s&#39; &#65;</strong>",
  );
  assert.equal(parseConsentList(h)[4].name, `a & b <x> "q" 's' A`);
});

test("Parser werfen unexpected_page ohne Pane", () => {
  assert.throws(() => parseConsentList("<html>nix</html>"), (e) => e.code === "unexpected_page");
});

test("whoami: Header, Gast, fehlend", async () => {
  let user = USER;
  const { api, calls } = mk(() => rest(user));
  assert.equal(await api.whoami({ cookie: COOKIE }), USER);
  assert.equal(calls[0].url, `${BASE}/rest/`);
  assert.equal(calls[0].init.headers.Cookie, COOKIE);
  assert.equal(calls[0].init.redirect, "manual");
  for (user of ["XWiki.XWikiGuest", "xwiki:XWiki.XWikiGuest", "", null]) {
    assert.equal(await api.whoami({ bearer: "t" }), null);
  }
  assert.equal(calls.at(-1).init.headers.Authorization, "Bearer t");
});

function happyHandler({ whoamiUser = USER, created = CREATED } = {}) {
  return (url, init) => {
    if (url === `${BASE}/rest/`) return rest(whoamiUser);
    if (url === PAGE_URL && init.method === "POST") return html(created);
    if (url === PAGE_URL) return html(LIST);
    throw new Error("unexpected " + url);
  };
}

const req = { xwikiUser: USER, appName: "mcp-vortest-2", days: 7 };

test("createToken: Cookie, POST-Felder, Ergebnis", async () => {
  const { api, calls } = mk(happyHandler());
  const r = await api.createToken({ cookie: COOKIE }, { ...req, days: 90 });
  assert.equal(r.token, TOKEN);
  assert.equal(r.consentId, `${USER}^XWiki.OIDC.ConsentClass[6]`);
  assert.equal(r.expiresAt, Date.UTC(2026, 10, 24, 23, 59, 59, 999));
  const post = calls.find((c) => c.init.method === "POST");
  assert.equal(post.init.headers.Cookie, COOKIE);
  assert.equal(post.init.redirect, "manual");
  assert.match(post.init.headers["Content-Type"], /application\/x-www-form-urlencoded/);
  const p = new URLSearchParams(post.init.body);
  assert.equal(p.get("form_token"), FORM_TOKEN);
  assert.equal(p.get("application_name"), "mcp-vortest-2");
  assert.equal(p.get("expiration"), "90");
  assert.ok(p.has("oidc_consent_create"));
  assert.equal(p.get("oidc_consent_create"), "");
  assert.equal(calls.at(-1).init.headers.Authorization, `Bearer ${TOKEN}`);
});

test("createToken: ohne Datum im Eintrag now + days", async () => {
  const created = CREATED.replaceAll("Der Token läuft am 24.11.2026 ab.", "");
  const { api } = mk(happyHandler({ created }));
  const before = Date.now();
  const r = await api.createToken({ cookie: COOKIE }, req);
  assert.ok(Math.abs(r.expiresAt - (before + 7 * 86400000)) < 5000);
});

test("createToken: 302 auf POST -> login_required", async () => {
  const { api } = mk((url, init) =>
    init.method === "POST"
      ? new Response(null, { status: 302, headers: { Location: `${BASE}/bin/login/XWiki/XWikiLogin` } })
      : html(LIST),
  );
  await assert.rejects(
    api.createToken({ cookie: COOKIE }, req),
    (e) => e instanceof XWikiTokenError && e.code === "login_required",
  );
});

test("createToken: 302/401/403 auf GET -> login_required", async () => {
  for (const status of [302, 401, 403]) {
    const { api } = mk(() => new Response(null, { status, headers: { Location: "/bin/login" } }));
    await assert.rejects(
      api.createToken({ cookie: COOKIE }, req),
      (e) => e.code === "login_required",
      String(status),
    );
  }
});

test("createToken: Seite ohne Pane oder ohne form_token -> unexpected_page", async () => {
  const noFT = rawList.replace(/<input[^>]*form_token[^>]*>/g, "");
  for (const body of ["<html>login</html>", noFT]) {
    const { api } = mk(() => html(body));
    await assert.rejects(api.createToken({ cookie: COOKIE }, req), (e) => e.code === "unexpected_page");
  }
});

test("createToken: Antwort ohne Token oder falscher Titel -> unexpected_page", async () => {
  const wrongTitle = CREATED.replace('<div class="box-title">mcp-vortest-2</div><p>', '<div class="box-title">anders</div><p>');
  for (const created of [LIST, wrongTitle]) {
    const { api } = mk(happyHandler({ created }));
    await assert.rejects(api.createToken({ cookie: COOKIE }, req), (e) => e.code === "unexpected_page");
  }
});

test("createToken: Benutzer im Token weicht ab -> identity_mismatch", async () => {
  const created = CREATED.replace("Bearer xwiki:XWiki.foellmann/6/", "Bearer xwiki:XWiki.other/6/");
  const { api } = mk(happyHandler({ created }));
  await assert.rejects(api.createToken({ cookie: COOKIE }, req), (e) => e.code === "identity_mismatch");
});

test("createToken: consent_id fehlt in der Liste -> unexpected_page", async () => {
  const { api } = mk(happyHandler({ created: removeBox(CREATED, 6) }));
  await assert.rejects(api.createToken({ cookie: COOKIE }, req), (e) => e.code === "unexpected_page");
});

test("createToken: whoami liefert anderen Benutzer -> Token wird geloescht", async () => {
  const afterDelete = removeBox(CREATED, 6);
  let deleted = false;
  const { api } = mk((url, init) => {
    if (url === `${BASE}/rest/`) return rest("xwiki:XWiki.mallory");
    if (url === PAGE_URL && init.method === "POST") {
      const p = new URLSearchParams(init.body);
      if (p.has("oidc_consent_delete")) {
        deleted = true;
        assert.equal(p.get("consent_id"), `${USER}^XWiki.OIDC.ConsentClass[6]`);
        assert.equal(init.headers.Authorization, `Bearer ${TOKEN}`);
        return html(afterDelete);
      }
      return html(CREATED);
    }
    return html(deleted ? afterDelete : CREATED);
  });
  await assert.rejects(api.createToken({ cookie: COOKIE }, req), (e) => e.code === "identity_mismatch");
  assert.ok(deleted);
});

test("createToken: Aufraeumen faellt auf Original-Auth zurueck", async () => {
  let cookieDelete = false;
  const { api } = mk((url, init) => {
    if (url === `${BASE}/rest/`) return rest("xwiki:XWiki.mallory");
    if (url === PAGE_URL && init.method === "POST") {
      const p = new URLSearchParams(init.body);
      if (p.has("oidc_consent_delete")) {
        if (init.headers.Authorization) return new Response("boom", { status: 500 });
        cookieDelete = true;
        return html(removeBox(CREATED, 6));
      }
      return html(CREATED);
    }
    return html(CREATED);
  });
  await assert.rejects(api.createToken({ cookie: COOKIE }, req), (e) => e.code === "identity_mismatch");
  assert.ok(cookieDelete);
});

const CID = (i) => `${USER}^XWiki.OIDC.ConsentClass[${i}]`;

test("deleteToken: erfolgreich", async () => {
  const { api, calls } = mk((url, init) => {
    if (url === `${BASE}/rest/`) return rest(USER);
    if (init.method === "POST") {
      const p = new URLSearchParams(init.body);
      assert.equal(p.get("form_token"), FORM_TOKEN);
      assert.equal(p.get("consent_id"), CID(3));
      assert.ok(p.has("oidc_consent_delete"));
      assert.equal(p.get("oidc_consent_delete"), "");
      return html(removeBox(LIST, 3));
    }
    return html(LIST);
  });
  assert.equal(await api.deleteToken({ bearer: "b" }, { xwikiUser: USER, consentId: CID(3) }), "deleted");
  assert.ok(calls.some((c) => c.init.method === "POST"));
});

test("deleteToken: bereits widerrufener Bearer (whoami null) -> gone", async () => {
  const { api, calls } = mk(() => rest(null));
  assert.equal(await api.deleteToken({ bearer: "b" }, { xwikiUser: USER, consentId: CID(3) }), "gone");
  assert.equal(calls.length, 1);
});

test("deleteToken: 401 mit eigenem Bearer -> gone", async () => {
  const { api } = mk((url) => (url === `${BASE}/rest/` ? rest(USER) : new Response("no", { status: 401 })));
  assert.equal(await api.deleteToken({ bearer: "b" }, { xwikiUser: USER, consentId: CID(3) }), "gone");
});

test("deleteToken: 401 mit Cookie -> login_required", async () => {
  const { api } = mk(() => new Response("no", { status: 401 }));
  await assert.rejects(
    api.deleteToken({ cookie: COOKIE }, { xwikiUser: USER, consentId: CID(3) }),
    (e) => e.code === "login_required",
  );
});

test("deleteToken: consent_id nicht in der Liste -> gone ohne POST", async () => {
  const { api, calls } = mk(() => html(LIST));
  assert.equal(await api.deleteToken({ cookie: COOKIE }, { xwikiUser: USER, consentId: CID(9) }), "gone");
  assert.ok(!calls.some((c) => c.init.method === "POST"));
});

test("deleteToken: Eintrag bleibt -> delete_failed", async () => {
  const { api } = mk(() => html(LIST));
  await assert.rejects(
    api.deleteToken({ cookie: COOKIE }, { xwikiUser: USER, consentId: CID(3) }),
    (e) => e.code === "delete_failed",
  );
});

test("findTokensByPrefix filtert nach Namenspraefix", async () => {
  const { api } = mk(() => html(LIST));
  const r = await api.findTokensByPrefix({ cookie: COOKIE }, USER, "lab");
  assert.deepEqual(r.map((e) => e.name), ["lab", "lab2"]);
  assert.equal(r[0].consentId, CID(3));
});

test("Fehler enthalten nie Token, Cookie oder form_token", async () => {
  const handlers = [
    happyHandler({ created: CREATED.replace("Bearer xwiki:XWiki.foellmann/6/", "Bearer xwiki:XWiki.other/6/") }),
    (url, init) =>
      init.method === "POST"
        ? new Response(null, { status: 302, headers: { Location: `/login?c=${COOKIE}` } })
        : html(LIST),
    () => html(LIST),
    happyHandler({ created: CREATED.replace(">mcp-vortest-2</div><p>", ">zz</div><p>") }),
  ];
  for (const handler of handlers) {
    const { api } = mk(handler);
    const errs = [];
    await api.createToken({ cookie: COOKIE }, req).catch((e) => errs.push(e));
    await api.deleteToken({ cookie: COOKIE }, { xwikiUser: USER, consentId: CID(3) }).catch((e) => errs.push(e));
    assert.ok(errs.length > 0);
    for (const e of errs) {
      const s = `${e.message}\n${e.stack}`;
      for (const secret of [TOKEN, "REDACTED-RANDOM", COOKIE, "SECRETCOOKIE123", FORM_TOKEN]) {
        assert.ok(!s.includes(secret), `leak ${secret}`);
      }
    }
  }
});
