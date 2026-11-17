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

function fromCode(raw, n) {
  // Out-of-range or surrogate code points stay as raw text instead of throwing.
  if (!Number.isInteger(n) || n < 0 || n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return raw;
  return String.fromCodePoint(n);
}

function decodeEntities(s) {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (m, h) => fromCode(m, parseInt(h, 16)))
    .replace(/&#(\d+);/g, (m, d) => fromCode(m, parseInt(d, 10)))
    .replace(/&ndash;/g, "–")
    .replace(/&mdash;/g, "—")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

// Returns the balanced subtree starting at the first match of startRe, or null.
function extractBalanced(html, startRe) {
  if (typeof html !== "string") return null;
  const start = startRe.exec(html);
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

function extractPane(html) {
  return extractBalanced(html, /<div\s[^>]*id="userapplicationsPane"[^>]*>/);
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
  // Fail closed: every consent_id input in the pane must belong to a parsed entry.
  const idInputs = (pane.match(/<input\b[^>]*\bname="consent_id"/g) || []).length;
  if (idInputs !== starts.length) throw new XWikiTokenError("unexpected_page");
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
  const seg = extractBalanced(pane, /<div class="box successmessage">/);
  if (!seg) return null;
  const title = /<div class="box-title">([\s\S]*?)<\/div>/.exec(seg);
  const code = /<div class="code">\s*Bearer ([^<\s]+)\s*<\/div>/.exec(seg);
  if (!code) return null;
  // A missing title is reported as null so the caller can still clean the token up.
  return { title: title ? decodeEntities(title[1].trim()) : null, token: decodeEntities(code[1]) };
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

  // Network errors and unreadable bodies become a fixed "unavailable" error
  // (never "gone"), so callers retry instead of treating the token as deleted.
  async function send(url, init) {
    try {
      const res = await fetcher(url, init);
      const text = init.wantText ? await res.text() : null;
      return { res, text };
    } catch {
      throw new XWikiTokenError("unavailable");
    }
  }

  // Returns the XWiki user, or null only for a 200 answer without a (non-guest)
  // user header. Any other status is an error, never "no user".
  async function whoami(auth) {
    const { res } = await send(`${base}/rest/`, {
      method: "GET",
      headers: authHeaders(auth),
      redirect: "manual",
    });
    if (res.status !== 200) {
      throw new XWikiTokenError(res.status >= 500 ? "unavailable" : "unexpected_page", res.status);
    }
    const user = res.headers.get("XWiki-User");
    if (!user || /(^|[:.])XWikiGuest$/.test(user)) return null;
    return user;
  }

  function pageUrl(xwikiUser) {
    return `${base}/bin/view/XWiki/${encodeURIComponent(profilePageName(xwikiUser))}?category=userapplications`;
  }

  async function pageRequest(auth, xwikiUser, params, { requireFormToken = true } = {}) {
    const headers = authHeaders(auth);
    const init = { method: "GET", headers, redirect: "manual", wantText: true };
    if (params) {
      init.method = "POST";
      init.headers = { ...headers, "Content-Type": "application/x-www-form-urlencoded" };
      init.body = new URLSearchParams(params).toString();
    }
    const { res, text } = await send(pageUrl(xwikiUser), init);
    const s = res.status;
    if ((s >= 300 && s < 400) || s === 401 || s === 403) throw new XWikiTokenError("login_required", s);
    if (s >= 500) throw new XWikiTokenError("unavailable", s);
    if (s !== 200) throw new XWikiTokenError("unexpected_page", s);
    const pane = extractPane(text);
    if (!pane) throw new XWikiTokenError("unexpected_page", s);
    const formToken = inputValue(pane, "form_token");
    if (!formToken && requireFormToken) throw new XWikiTokenError("unexpected_page", s);
    return { html: text, pane, formToken };
  }

  const loadPage = (auth, xwikiUser) => pageRequest(auth, xwikiUser);

  // Contract: "gone" means the consent is really not valid any more. A revoked
  // bearer (whoami null) or a 401 on the own bearer counts as gone only when
  // the bearer belongs to consentId (same user and index segment); otherwise we
  // cannot tell and throw. This assumes the bearer is exactly the token that was
  // issued for this consent. Transient failures (5xx, network) always throw.
  function bearerOwns(auth, consentId) {
    const m = /^(.+)\/(\d+)\/[^/]+$/.exec(auth.bearer || "");
    return !!m && consentId === `${m[1]}^XWiki.OIDC.ConsentClass[${m[2]}]`;
  }

  async function deleteToken(auth, { xwikiUser, consentId }) {
    const own = !!auth.bearer && bearerOwns(auth, consentId);
    if (auth.bearer && (await whoami(auth)) === null) {
      if (own) return "gone";
      throw new XWikiTokenError("login_required");
    }
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
      if (own && err instanceof XWikiTokenError && err.code === "login_required" && err.status === 401) {
        return "gone";
      }
      throw err;
    }
  }

  // Best effort: delete with the new bearer; if that fails or reports "gone"
  // (bearer already invalid), retry with the original auth.
  async function cleanup(auth, token, target) {
    try {
      if ((await deleteToken({ bearer: token }, target)) === "deleted") return;
    } catch {
      // fall through
    }
    try {
      await deleteToken(auth, target);
    } catch {
      // best effort
    }
  }

  async function createToken(auth, { xwikiUser, appName, days }) {
    const page = await loadPage(auth, xwikiUser);
    // The form_token check is deferred: once the token is in the response, every
    // later failure must go through cleanup so no live token is left behind.
    const res = await pageRequest(
      auth,
      xwikiUser,
      {
        form_token: page.formToken,
        application_name: appName,
        expiration: String(days),
        oidc_consent_create: "",
      },
      { requireFormToken: false },
    );
    const created = parseCreated(res.html);
    const parts = created && /^(.+)\/(\d+)\/[A-Za-z0-9_-]+$/.exec(created.token);
    if (!parts) throw new XWikiTokenError("unexpected_page");
    const { token } = created;
    const [, tokenUser, index] = parts;
    const consentId = `${tokenUser}^XWiki.OIDC.ConsentClass[${index}]`;
    try {
      if (created.title !== appName || !res.formToken) throw new XWikiTokenError("unexpected_page");
      if (tokenUser !== xwikiUser) throw new XWikiTokenError("identity_mismatch");
      const entry = parseConsentList(res.html).find((e) => e.consentId === consentId);
      if (!entry) throw new XWikiTokenError("unexpected_page");
      const expiresAt = entry.expiresAt || Date.now() + Number(days) * DAY_MS;
      if ((await whoami({ bearer: token })) !== xwikiUser) throw new XWikiTokenError("identity_mismatch");
      return { token, consentId, expiresAt };
    } catch (err) {
      await cleanup(auth, token, { xwikiUser: tokenUser, consentId });
      throw err;
    }
  }

  async function findTokensByPrefix(auth, xwikiUser, prefix) {
    const page = await loadPage(auth, xwikiUser);
    return parseConsentList(page.html).filter((e) => e.name.startsWith(prefix));
  }

  return { whoami, createToken, deleteToken, findTokensByPrefix, parseCreatedToken, parseConsentList };
}
