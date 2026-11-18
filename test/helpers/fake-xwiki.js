// In-process fake of XWiki 18.7.0 for the end-to-end test. Behaviour follows
// test/fixtures/xwiki-18.7.0/README.md:
//  - GET /rest/ answers 200; the XWiki-User header is present only for a valid cookie or
//    bearer (an invalid or revoked bearer falls back to guest: 200 WITHOUT the header).
//  - protected REST resources (search, pages) answer 401 for guests.
//  - profile page "Anwendungen" at /bin/view/XWiki/<name>?category=userapplications with
//    forms posting to the same URL; markup mirrors created.html / list.html.
//  - consent ids `<user>^XWiki.OIDC.ConsentClass[<index>]`, tokens `<user>/<index>/<random>`,
//    deleted indices are never reused.
//  - restart() drops every browser session (cookies); bearer tokens survive.
import express from "express";
import { randomBytes } from "node:crypto";

const DAY_MS = 86400000;
const COOKIE = "JSESSIONID";
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const rand = () => randomBytes(32).toString("base64url"); // 43 chars, like XWiki's random part

function germanDate(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}.${p(d.getUTCMonth() + 1)}.${d.getUTCFullYear()}`;
}

export async function fakeXWiki({ pages = [] } = {}) {
  const sessions = new Map(); // cookie value → xwikiUser
  const formTokens = new Map(); // xwikiUser → form_token (session bound: reset by restart)
  const consents = new Map(); // xwikiUser → { next, entries: Map(index → { name, expiresAt, random }) }
  const requests = []; // { method, path, auth: "bearer" | "cookie" | "none" }
  let ssoUser = null; // the user the browser is logged in as at the SSO (for /bin/login)

  const userBook = (user) => {
    if (!consents.has(user)) consents.set(user, { next: 0, entries: new Map() });
    return consents.get(user);
  };
  const formTokenOf = (user) => {
    if (!formTokens.has(user)) formTokens.set(user, rand());
    return formTokens.get(user);
  };

  function bearerUser(token) {
    const m = /^(.+)\/(\d+)\/([A-Za-z0-9_-]+)$/.exec(token);
    if (!m) return null;
    const entry = consents.get(m[1])?.entries.get(Number(m[2]));
    if (!entry || entry.random !== m[3] || entry.expiresAt < Date.now()) return null;
    return m[1];
  }

  // Resolves the request's user (or null for guest) and records how it authenticated.
  function userOf(req) {
    const auth = req.headers.authorization || "";
    const m = /^Bearer (\S+)$/.exec(auth);
    const cookie = /(?:^|;\s*)JSESSIONID=([^;]+)/.exec(req.headers.cookie || "");
    requests.push({ method: req.method, path: req.path, auth: m ? "bearer" : cookie ? "cookie" : "none" });
    if (m) return bearerUser(m[1]);
    if (cookie) return sessions.get(cookie[1]) || null;
    return null;
  }

  function entriesHtml(user, formToken) {
    return [...userBook(user).entries].map(([index, e]) => `
<div class="box">
<div class="pull-left">
<strong>${esc(e.name)}</strong>
<br>
<span class="date xHint">
${e.expiresAt < Date.now() ? "Der Token ist abgelaufen!" : `Der Token läuft am ${germanDate(e.expiresAt)} ab.`}
</span>
</div>

<form class="xform pull-right" method="post">
<input name="form_token" type="hidden" value="${esc(formToken)}">
<input name="consent_id" type="hidden" value="${esc(`${user}^XWiki.OIDC.ConsentClass[${index}]`)}">
<button class="btn btn-sm btn-danger" name="oidc_consent_delete">Löschen</button>
</form>
</div>`).join("");
  }

  function profilePage(user, created) {
    const formToken = formTokenOf(user);
    const success = created ? `<div class="box successmessage"><span class="icon-block"><span aria-hidden="true" class="fa fa-check"></span></span><span class="sr-only">Erfolg</span><div><div class="box-title">${esc(created.name)}</div><p>Es wurde ein neuer Token erstellt, um als Benutzer mit der Kennung „${esc(user)}“ auf XWiki zuzugreifen.</p><div>Es handelt sich um ein OAuth2-Token.</div><div class="box"><div class="box-title">Authorization</div><div class="code">Bearer ${esc(created.token)}</div></div></div></div>` : '<div class="wikimodel-emptyline"></div>';
    const pane = `<div id="userapplicationsPane" class="user-page-pane"><div>Auf dieser Seite können alle Token verwaltet werden.</div>${success}<form class="xform" method="post">
<input name="form_token" type="hidden" value="${esc(formToken)}">
<label id="label_application_name">Anwendung:<input id="input_application_name" name="application_name" type="text"></label>
<label id="label_expiration">Ablauf:<select id="select_expiration" name="expiration"><option value="7">7 Tage</option><option selected="selected" value="30">30 Tage</option><option value="60">60 Tage</option><option value="90">90 Tage</option><option value="date">Benutzerdefiniert...</option><option value="never">Niemals</option></select></label>
<button class="btn btn-primary" name="oidc_consent_create">Erstellen</button>
</form>
${entriesHtml(user, formToken)}</div>`;
    return `<!DOCTYPE html><html><head><title>Profil</title></head><body><div id="mainContentArea">${pane}</div></body></html>`;
  }

  const app = express();
  app.use(express.urlencoded({ extended: false }));

  // XWiki's login action: the SSO (Authentik) session turns into a XWiki session cookie,
  // then the browser follows xredirect (same origin).
  app.get("/bin/login/XWiki/XWikiLogin", (req, res) => {
    if (!ssoUser) return res.status(401).send("not logged in at the SSO");
    const value = rand();
    sessions.set(value, ssoUser);
    res.cookie(COOKIE, value, { path: "/", httpOnly: true });
    res.redirect(302, String(req.query.xredirect || "/"));
  });

  app.get("/rest/", (req, res) => {
    const user = userOf(req);
    if (user) {
      res.set("XWiki-User", user);
      res.set("XWiki-Form-Token", formTokenOf(user));
    }
    res.type("application/xml").send("<xwiki/>");
  });

  app.get("/rest/wikis/:wiki/search", (req, res) => {
    if (!userOf(req)) return res.status(401).send("unauthorized");
    const q = String(req.query.q || "").toLowerCase();
    const number = Number(req.query.number) || 10;
    const searchResults = pages
      .filter((p) => `${p.title} ${p.content}`.toLowerCase().includes(q))
      .slice(0, number)
      .map((p) => ({ title: p.title, space: p.space, pageName: p.pageName, pageFullName: `${p.space}.${p.pageName}` }));
    res.json({ searchResults });
  });

  app.get("/rest/wikis/:wiki/spaces/:space/pages/:page", (req, res) => {
    if (!userOf(req)) return res.status(401).send("unauthorized");
    const p = pages.find((x) => x.space === req.params.space && x.pageName === req.params.page);
    if (!p) return res.status(404).send("not found");
    res.json({ title: p.title, content: p.content, syntax: "markdown/1.2", author: "XWiki.Admin", modified: 0 });
  });

  const profile = (req, res) => {
    if (req.query.category !== "userapplications") return res.status(404).send("not found");
    const user = userOf(req);
    if (!user) return res.redirect(302, `/bin/login/XWiki/XWikiLogin?xredirect=${encodeURIComponent(req.originalUrl)}`);
    if (user !== `xwiki:XWiki.${req.params.name}`) return res.status(403).send("forbidden");
    if (req.method === "GET") return res.type("html").send(profilePage(user));
    const body = req.body || {};
    if (body.form_token !== formTokenOf(user)) return res.status(403).send("invalid form token");
    const book = userBook(user);
    if (Object.hasOwn(body, "oidc_consent_create")) {
      const days = Number(body.expiration);
      if (![7, 30, 60, 90].includes(days) || !body.application_name) return res.status(400).send("bad request");
      const index = book.next++;
      const random = rand();
      book.entries.set(index, { name: body.application_name, expiresAt: Date.now() + days * DAY_MS, random });
      return res.type("html").send(profilePage(user, { name: body.application_name, token: `${user}/${index}/${random}` }));
    }
    if (Object.hasOwn(body, "oidc_consent_delete")) {
      const m = /^(.+)\^XWiki\.OIDC\.ConsentClass\[(\d+)\]$/.exec(String(body.consent_id || ""));
      if (m && m[1] === user) book.entries.delete(Number(m[2]));
      return res.type("html").send(profilePage(user));
    }
    return res.status(400).send("bad request");
  };
  app.get("/bin/view/XWiki/:name", profile);
  app.post("/bin/view/XWiki/:name", profile);

  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const url = `http://127.0.0.1:${server.address().port}`;

  return {
    url,
    requests,
    // The browser is logged in at the SSO as this XWiki user (e.g. "xwiki:XWiki.zurmano").
    ssoLogin(user) {
      ssoUser = user;
    },
    // Tomcat restart: every session cookie (and its form token) is gone; consents persist.
    restart() {
      sessions.clear();
      formTokens.clear();
    },
    // The consents of a user, as the profile page lists them.
    consents(user) {
      return [...(consents.get(user)?.entries || [])].map(([index, e]) => ({
        consentId: `${user}^XWiki.OIDC.ConsentClass[${index}]`,
        name: e.name,
        expiresAt: e.expiresAt,
      }));
    },
    close() {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}
