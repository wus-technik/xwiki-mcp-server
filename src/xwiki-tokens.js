// XWiki consent tokens (OAuth2 bearer) managed via the user's "Applications"
// profile page. Behaviour measured against XWiki 18.7.0, see
// test/fixtures/xwiki-18.7.0/README.md.
//
// Secrets rule: error messages and logs never contain tokens, cookies or
// form_token values. Messages are fixed strings; only `code` and `status`
// (an HTTP status number) are attached.

export class XWikiTokenError extends Error {
  constructor(code, status) {
    super(`XWiki token operation failed: ${code}`);
    this.name = "XWikiTokenError";
    this.code = code;
    if (status !== undefined) this.status = status;
  }
}

const DAY_MS = 86400000;

function decodeEntities(s) {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

// Returns the balanced `div#userapplicationsPane` subtree, or null.
function extractPane(html) {
  if (typeof html !== "string") return null;
  const start = /<div\s[^>]*id="userapplicationsPane"[^>]*>/.exec(html);
  if (!start) return null;
  const re = /<(\/?)div\b[^>]*>/g;
  re.lastIndex = start.index + start[0].length;
  let depth = 1;
  let m;
  while ((m = re.exec(html))) {
    depth += m[1] ? -1 : 1;
    if (depth === 0) return html.slice(start.index, m.index + m[0].length);
  }
  return null;
}

function requirePane(html) {
  const pane = extractPane(html);
  if (!pane) throw new XWikiTokenError("unexpected_page");
  return pane;
}

function inputValue(segment, name) {
  const tag = new RegExp(`<input\\b[^>]*\\bname="${name}"[^>]*>`).exec(segment);
  if (!tag) return null;
  const v = /\bvalue="([^"]*)"/.exec(tag[0]);
  return v ? decodeEntities(v[1]) : null;
}

function parseDate(text) {
  const m = /(\d{2})\.(\d{2})\.(\d{4})/.exec(text);
  if (!m) return null;
  return Date.UTC(+m[3], +m[2] - 1, +m[1], 23, 59, 59, 999);
}

// Entries: { consentId, name, expiresAt, expired }.
// expiresAt: epoch ms (end of the stated day, UTC); for "Der Token ist
// abgelaufen!" it is 0 and expired is true; null when no date is shown.
export function parseConsentList(html) {
  const pane = requirePane(html);
  const starts = [];
  const re = /<div class="box">\s*<div class="pull-left">/g;
  let m;
  while ((m = re.exec(pane))) starts.push(m.index);
  return starts.map((from, i) => {
    const seg = pane.slice(from, i + 1 < starts.length ? starts[i + 1] : pane.length);
    const name = /<strong>([\s\S]*?)<\/strong>/.exec(seg);
    const consentId = inputValue(seg, "consent_id");
    if (!name || !consentId) throw new XWikiTokenError("unexpected_page");
    const dateM = /<span class="date xHint">([\s\S]*?)<\/span>/.exec(seg);
    const dateText = dateM ? decodeEntities(dateM[1]).trim() : "";
    const expired = /abgelaufen/.test(dateText);
    return {
      consentId,
      name: decodeEntities(name[1].trim()),
      expiresAt: expired ? 0 : parseDate(dateText),
      expired,
    };
  });
}

function parseCreated(html) {
  const pane = extractPane(html);
  if (!pane) return null;
  const box = /<div class="box successmessage">([\s\S]*?)<div class="box warningmessage">|<div class="box successmessage">([\s\S]*)$/.exec(pane);
  if (!box) return null;
  const seg = box[1] ?? box[2];
  const title = /<div class="box-title">([\s\S]*?)<\/div>/.exec(seg);
  const code = /<div class="code">\s*Bearer ([^<\s]+)\s*<\/div>/.exec(seg);
  if (!title || !code) return null;
  return { title: decodeEntities(title[1].trim()), token: decodeEntities(code[1]) };
}

export function parseCreatedToken(html) {
  return parseCreated(html)?.token ?? null;
}

function authHeaders(auth) {
  if (auth && typeof auth.cookie === "string" && auth.cookie && !auth.bearer) {
    return { Cookie: auth.cookie };
  }
  if (auth && typeof auth.bearer === "string" && auth.bearer && !auth.cookie) {
    return { Authorization: `Bearer ${auth.bearer}` };
  }
  throw new TypeError("auth must be { cookie } or { bearer }");
}

function profilePageName(xwikiUser) {
  const i = xwikiUser.indexOf("XWiki.");
  const page = i >= 0 ? xwikiUser.slice(i + "XWiki.".length) : "";
  if (!page) throw new TypeError("xwikiUser must be a full user reference");
  return page;
}

export function createXWikiTokens({ baseUrl, fetcher = fetch }) {
  const base = baseUrl.replace(/\/+$/, "");

  async function whoami(auth) {
    const res = await fetcher(`${base}/rest/`, {
      method: "GET",
      headers: authHeaders(auth),
      redirect: "manual",
    });
    const user = res.headers.get("XWiki-User");
    if (!user || /(^|[:.])XWikiGuest$/.test(user)) return null;
    return user;
  }

  function pageUrl(xwikiUser) {
    return `${base}/bin/view/XWiki/${encodeURIComponent(profilePageName(xwikiUser))}?category=userapplications`;
  }

  async function pageRequest(auth, xwikiUser, params) {
    const headers = authHeaders(auth);
    const init = { method: "GET", headers, redirect: "manual" };
    if (params) {
      init.method = "POST";
      init.headers = { ...headers, "Content-Type": "application/x-www-form-urlencoded" };
      init.body = new URLSearchParams(params).toString();
    }
    const res = await fetcher(pageUrl(xwikiUser), init);
    const s = res.status;
    if ((s >= 300 && s < 400) || s === 401 || s === 403) throw new XWikiTokenError("login_required", s);
    if (s !== 200) throw new XWikiTokenError("unexpected_page", s);
    const body = await res.text();
    const pane = extractPane(body);
    if (!pane) throw new XWikiTokenError("unexpected_page", s);
    return { html: body, pane };
  }

  async function loadPage(auth, xwikiUser) {
    const page = await pageRequest(auth, xwikiUser);
    const formToken = inputValue(page.pane, "form_token");
    if (!formToken) throw new XWikiTokenError("unexpected_page", 200);
    return { ...page, formToken };
  }

  async function deleteToken(auth, { xwikiUser, consentId }) {
    if (auth && auth.bearer && (await whoami(auth)) === null) return "gone";
    try {
      const page = await loadPage(auth, xwikiUser);
      if (!parseConsentList(page.html).some((e) => e.consentId === consentId)) return "gone";
      const after = await pageRequest(auth, xwikiUser, {
        form_token: page.formToken,
        consent_id: consentId,
        oidc_consent_delete: "",
      });
      if (parseConsentList(after.html).some((e) => e.consentId === consentId)) {
        throw new XWikiTokenError("delete_failed");
      }
      return "deleted";
    } catch (err) {
      if (err instanceof XWikiTokenError && err.code === "login_required" && err.status === 401 && auth.bearer) {
        return "gone";
      }
      throw err;
    }
  }

  async function cleanup(auth, token, target) {
    try {
      await deleteToken({ bearer: token }, target);
    } catch {
      try {
        await deleteToken(auth, target);
      } catch {
        // best effort
      }
    }
  }

  async function createToken(auth, { xwikiUser, appName, days }) {
    const page = await loadPage(auth, xwikiUser);
    const res = await pageRequest(auth, xwikiUser, {
      form_token: page.formToken,
      application_name: appName,
      expiration: String(days),
      oidc_consent_create: "",
    });
    const created = parseCreated(res.html);
    if (!created || created.title !== appName) throw new XWikiTokenError("unexpected_page");
    const { token } = created;
    const parts = /^(.+)\/(\d+)\/[A-Za-z0-9_-]+$/.exec(token);
    if (!parts) throw new XWikiTokenError("unexpected_page");
    const [, tokenUser, index] = parts;
    const consentId = `${tokenUser}^XWiki.OIDC.ConsentClass[${index}]`;
    if (tokenUser !== xwikiUser) {
      await cleanup(auth, token, { xwikiUser: tokenUser, consentId });
      throw new XWikiTokenError("identity_mismatch");
    }
    const entry = parseConsentList(res.html).find((e) => e.consentId === consentId);
    if (!entry) throw new XWikiTokenError("unexpected_page");
    const expiresAt = entry.expiresAt || Date.now() + Number(days) * DAY_MS;
    if ((await whoami({ bearer: token })) !== xwikiUser) {
      await cleanup(auth, token, { xwikiUser, consentId });
      throw new XWikiTokenError("identity_mismatch");
    }
    return { token, consentId, expiresAt };
  }

  async function findTokensByPrefix(auth, xwikiUser, prefix) {
    const page = await loadPage(auth, xwikiUser);
    return parseConsentList(page.html).filter((e) => e.name.startsWith(prefix));
  }

  return { whoami, createToken, deleteToken, findTokensByPrefix, parseCreatedToken, parseConsentList };
}
