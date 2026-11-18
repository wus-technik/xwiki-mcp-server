import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";

export class XWikiAuthError extends Error {
  constructor(message) {
    super(message);
    this.name = "XWikiAuthError";
  }
}

const DEFAULT_SYNTAX = "markdown/1.2";
// XWiki REST search scopes (/rest/wikis/{wiki}/search?scope=...); the default is content only.
const SEARCH_SCOPES = ["name", "title", "content"];
export const MAX_SOURCE_URL_BYTES = 50 * 1024 * 1024;
const SOURCE_URL_TIMEOUT_MS = 30_000;
const MAX_SOURCE_URL_REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const DISALLOWED_ADDRESS = "source_url resolves to a disallowed internal/private address";
const TOO_LARGE = `source_url content exceeds maximum allowed size (${MAX_SOURCE_URL_BYTES} bytes)`;

// [network, prefix length] — loopback, private, CGNAT, link-local (incl. cloud metadata),
// "this network", IETF protocol assignments, benchmarking, multicast, reserved/broadcast.
const IPV4_BLOCKED = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
];

function ipv4ToInt(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part) || Number(part) > 255) return null;
    n = n * 256 + Number(part);
  }
  return n;
}

function isDisallowedIpv4Int(n) {
  return IPV4_BLOCKED.some(([net, bits]) => {
    const size = 2 ** (32 - bits);
    return Math.floor(n / size) === Math.floor(ipv4ToInt(net) / size);
  });
}

// Eight 16-bit groups, or null if the text is not an IPv6 address.
function ipv6Groups(ip) {
  let s = String(ip).toLowerCase();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  const lastColon = s.lastIndexOf(":");
  if (lastColon < 0) return null;
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const n = ipv4ToInt(tail);
    if (n === null) return null;
    s = `${s.slice(0, lastColon + 1)}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = 8 - head.length - rest.length;
  if (halves.length === 1 ? fill !== 0 : fill < 1) return null;
  const groups = [...head, ...Array(fill).fill("0"), ...rest];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

export function isDisallowedIp(ip) {
  const kind = isIP(String(ip));
  if (kind === 4) return isDisallowedIpv4Int(ipv4ToInt(ip));
  if (kind !== 6) return true; // not an IP address: refuse
  const g = ipv6Groups(ip);
  if (!g) return true;
  const embedded = () => isDisallowedIpv4Int(g[6] * 65536 + g[7]);
  const zeroUpTo = (n) => g.slice(0, n).every((x) => x === 0);
  if (zeroUpTo(5) && g[5] === 0xffff) return true; // IPv4-mapped ::ffff:0:0/96, whole prefix
  if (zeroUpTo(6)) return true; // ::, ::1 and the deprecated IPv4-compatible ::/96
  if (g[0] === 0x64 && g[1] === 0xff9b) { // NAT64: well-known /96 embeds IPv4, the rest is local-use
    return g.slice(2, 6).every((x) => x === 0) ? embedded() : true;
  }
  if (g[0] === 0x2002) return isDisallowedIpv4Int(g[1] * 65536 + g[2]); // 6to4
  if (g[0] === 0x2001 && g[1] === 0) return true; // Teredo
  if ((g[0] & 0xffc0) === 0xfe80) return true; // link-local
  if ((g[0] & 0xffc0) === 0xfec0) return true; // site-local (deprecated)
  if ((g[0] & 0xfe00) === 0xfc00) return true; // unique local
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast
  return false;
}

// "scheme//host:effective-port" — URL.port is empty for the scheme's default port.
function originKey(url) {
  const port = url.port || (url.protocol === "https:" ? "443" : "80");
  return `${url.protocol}//${url.hostname.toLowerCase()}:${port}`;
}

export function createXWikiClient({ baseUrl, publicUrl, wiki, fetcher = fetch, sourceLookup }) {
  const linkBase = (publicUrl || baseUrl || "").replace(/\/$/, "");
  // Resolver for source_url hosts: (hostname) -> [{ address, family }]. Injectable for tests.
  const resolveSourceHost = sourceLookup || ((hostname) => dnsLookup(hostname, { all: true, verbatim: true }));

  // The configured XWiki origin (scheme, host, effective port) is the only source_url target
  // whose resolved address is not IP-checked; other ports on that host are checked normally.
  let trustedOrigin = "";
  try {
    const base = new URL(baseUrl);
    if (base.protocol === "http:" || base.protocol === "https:") trustedOrigin = originKey(base);
  } catch {
    // no configured baseUrl to trust; every source_url host is IP-checked
  }

  function viewUrl(pageFullName) {
    const segments = String(pageFullName || "").split(".").map(encodeURIComponent);
    return `${linkBase}/bin/view/${segments.join("/")}`;
  }

  function downloadUrl(pagePath, filename) {
    const segments = normalizePagePath(pagePath).split(".").map(encodeURIComponent);
    return `${linkBase}/bin/download/${segments.join("/")}/${encodeURIComponent(filename)}`;
  }

  // Checks scheme and host of one hop. IP literals are checked here (Node does not call
  // `lookup` for them); names are checked by the lookup at connect time.
  function checkSourceTarget(url) {
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("source_url must use http or https");
    }
    // Node would turn userinfo into an Authorization: Basic header.
    if (url.username || url.password) throw new Error("source_url must not contain credentials");
    const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (!host) throw new Error("source_url has no host");
    const trusted = trustedOrigin !== "" && originKey(url) === trustedOrigin;
    if (!trusted && isIP(host) && isDisallowedIp(host)) throw new Error(DISALLOWED_ADDRESS);
    return trusted;
  }

  // A net/dns-compatible lookup: resolves the name, refuses the connection if any address is
  // disallowed, and hands exactly the checked addresses to the socket. The configured XWiki
  // host (trusted) may resolve to a private address.
  function checkingLookup(trusted) {
    return (hostname, options, callback) => {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      const opts = typeof options === "number" ? { family: options } : options || {};
      Promise.resolve()
        .then(() => resolveSourceHost(hostname, { family: opts.family }))
        .catch(() => {
          throw new Error(`Could not resolve source_url host: ${hostname}`);
        })
        .then((resolved) => {
          const addresses = (Array.isArray(resolved) ? resolved : [])
            .map((a) => ({ address: a.address, family: a.family === 6 || isIP(a.address) === 6 ? 6 : 4 }));
          if (addresses.length === 0) throw new Error(`Could not resolve source_url host: ${hostname}`);
          if (!trusted && addresses.some((a) => isDisallowedIp(a.address))) throw new Error(DISALLOWED_ADDRESS);
          const wanted = opts.family === 4 || opts.family === 6
            ? addresses.filter((a) => a.family === opts.family)
            : addresses;
          if (wanted.length === 0) throw new Error(`Could not resolve source_url host: ${hostname}`);
          return wanted;
        })
        .then(
          (wanted) => process.nextTick(() => (opts.all
            ? callback(null, wanted)
            : callback(null, wanted[0].address, wanted[0].family))),
          (err) => process.nextTick(() => callback(err)),
        );
    };
  }

  // One GET without redirect following and without any XWiki credentials.
  function requestSourceOnce(url, trusted, signal) {
    const mod = url.protocol === "https:" ? https : http;
    return new Promise((resolve, reject) => {
      const req = mod.request(url, {
        method: "GET",
        headers: { Accept: "*/*" },
        lookup: checkingLookup(trusted),
        agent: false,
        signal,
      }, resolve);
      req.on("error", reject);
      req.end();
    });
  }

  async function readLimited(res) {
    const declaredLength = Number(res.headers["content-length"]);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_SOURCE_URL_BYTES) {
      res.destroy();
      throw new Error(TOO_LARGE);
    }
    const chunks = [];
    let total = 0;
    for await (const chunk of res) {
      total += chunk.length;
      if (total > MAX_SOURCE_URL_BYTES) {
        res.destroy();
        throw new Error(TOO_LARGE);
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }

  async function fetchFromSourceUrl(sourceUrl) {
    let current;
    try {
      current = new URL(sourceUrl);
    } catch {
      throw new Error("source_url is not a valid URL");
    }
    const signal = AbortSignal.timeout(SOURCE_URL_TIMEOUT_MS);
    try {
      for (let redirects = 0; ; redirects += 1) {
        const trusted = checkSourceTarget(current);
        const res = await requestSourceOnce(current, trusted, signal);
        const status = res.statusCode;
        if (REDIRECT_STATUSES.has(status) && res.headers.location) {
          res.destroy();
          if (redirects >= MAX_SOURCE_URL_REDIRECTS) throw new Error("source_url: too many redirects");
          try {
            current = new URL(res.headers.location, current);
          } catch {
            throw new Error("source_url redirect target is not a valid URL");
          }
          continue;
        }
        if (status < 200 || status >= 300) {
          res.destroy();
          throw new Error(`Failed to fetch source_url: ${status}`);
        }
        return await readLimited(res);
      }
    } catch (err) {
      if (signal.aborted) throw new Error("source_url request timed out");
      throw err;
    }
  }

  function normalizeHeadingName(value) {
    return String(value || "").trim().replace(/\s+/g, " ").toLowerCase();
  }

  function normalizePagePath(pagePath) {
    return String(pagePath || "").replace(/\//g, ".");
  }

  function getPageEndpoint(pagePath) {
    const parts = normalizePagePath(pagePath).split(".");
    const spacePath = parts.slice(0, -1).join("/spaces/");
    const pageName = parts[parts.length - 1] || "WebHome";
    return `${baseUrl}/rest/wikis/${wiki}/spaces/${spacePath}/pages/${pageName}`;
  }

  function parseHeadingLine(line) {
    const xwikiMatch = line.match(/^(=+)\s*(.*?)\s*\1\s*$/);
    if (xwikiMatch) {
      return {
        level: xwikiMatch[1].length,
        title: xwikiMatch[2].trim(),
      };
    }

    const markdownMatch = line.match(/^(#{1,6})\s+(.+?)$/);
    if (markdownMatch) {
      return {
        level: markdownMatch[1].length,
        title: markdownMatch[2].replace(/\s+#+$/, "").trim(),
      };
    }

    return null;
  }

  // Per line: true if it belongs to a code block, where "# comment" or "= x =" lines are code,
  // not headings. Which block kinds apply depends on the page syntax:
  //  - fenced blocks (``` / ~~~) only in Markdown (and unknown syntax). A backtick fence's
  //    info string must not contain a backtick (CommonMark), so ```x``` is inline code.
  //    Closed by a bare fence of the same character, at least as long.
  //  - XWiki code macros {{code ...}} ... {{/code}} in every syntax (XWiki Markdown 1.2
  //    supports macros too); an opener may follow prose, {{/code}} may sit mid-line, and a
  //    self-closing {{code .../}} opens nothing.
  //  - verbatim {{{ ... }}} in XWiki syntax (and unknown syntax), not in Markdown.
  function codeLineMask(lines, syntax) {
    const s = typeof syntax === "string" ? syntax.toLowerCase() : "";
    const markdown = s.startsWith("markdown");
    const xwiki = s.startsWith("xwiki");
    const fences = !xwiki;
    const verbatim = !markdown;
    const MACRO_TOKENS = /\{\{\{|\}\}\}|\{\{code(?:\s[^}]*?)?(\/)?\}\}|\{\{\/code\}\}/g;
    const mask = [];
    let fence = null; // { char, len } while inside a fenced block
    let block = null; // "macro" | "verbatim" while inside an XWiki block
    for (const line of lines) {
      if (fence) {
        mask.push(true);
        const close = line.match(/^ {0,3}(`{3,}|~{3,})\s*$/);
        if (close && close[1][0] === fence.char && close[1].length >= fence.len) fence = null;
        continue;
      }
      if (!block && fences) {
        const open = line.match(/^ {0,3}(?:(`{3,})[^`]*|(~{3,}).*)$/);
        if (open) {
          const run = open[1] || open[2];
          fence = { char: run[0], len: run.length };
          mask.push(true);
          continue;
        }
      }
      let inCode = block !== null;
      for (const m of line.matchAll(MACRO_TOKENS)) {
        const token = m[0];
        if (block === "macro") {
          if (token === "{{/code}}") block = null;
        } else if (block === "verbatim") {
          if (token === "}}}") block = null;
        } else if (token.startsWith("{{code") && !m[1]) {
          block = "macro";
          inCode = true;
        } else if (token === "{{{" && verbatim) {
          block = "verbatim";
          inCode = true;
        }
      }
      mask.push(inCode);
    }
    return mask;
  }

  function extractHeadings(content, syntax) {
    const lines = String(content || "").split("\n");
    const inCode = codeLineMask(lines, syntax);
    const occurrences = new Map();
    const headings = [];

    for (const [i, line] of lines.entries()) {
      if (inCode[i]) continue;
      const parsedHeading = parseHeadingLine(line);
      if (!parsedHeading) continue;
      const normalizedTitle = normalizeHeadingName(parsedHeading.title);
      const occurrence = (occurrences.get(normalizedTitle) || 0) + 1;
      occurrences.set(normalizedTitle, occurrence);
      headings.push({
        title: parsedHeading.title,
        level: parsedHeading.level,
        occurrence,
      });
    }

    return headings;
  }

  function extractSectionByHeading(content, options = {}) {
    const requestedHeading = typeof options.heading === "string" ? options.heading.trim() : "";
    if (!requestedHeading) {
      return {
        content,
        headingMatched: null,
        headingOccurrence: null,
        headingLevel: null,
        sourceContentLength: String(content || "").length,
        headingTruncated: false,
      };
    }

    const requestedOccurrence = Number.isFinite(options.headingOccurrence)
      ? Math.max(1, Math.trunc(options.headingOccurrence))
      : 1;
    const normalizedRequestedHeading = normalizeHeadingName(requestedHeading);
    const lines = String(content || "").split("\n");
    const inCode = codeLineMask(lines, options.syntax);
    const headings = [];
    let cursor = 0;

    for (const [i, line] of lines.entries()) {
      const parsedHeading = inCode[i] ? null : parseHeadingLine(line);
      if (parsedHeading) {
        headings.push({
          ...parsedHeading,
          start: cursor,
          line,
        });
      }
      cursor += line.length + 1;
    }

    const matches = headings.filter((heading) => normalizeHeadingName(heading.title) === normalizedRequestedHeading);
    const matchedHeading = matches[requestedOccurrence - 1];
    if (!matchedHeading) {
      throw new Error(`Heading not found: ${requestedHeading}`);
    }

    const nextHeading = headings.find(
      (heading) => heading.start > matchedHeading.start && heading.level <= matchedHeading.level,
    );
    const end = nextHeading ? nextHeading.start : String(content || "").length;

    return {
      content: String(content || "").slice(matchedHeading.start, end).trimEnd(),
      headingMatched: matchedHeading.title,
      headingOccurrence: requestedOccurrence,
      headingLevel: matchedHeading.level,
      sourceContentLength: String(content || "").length,
      headingTruncated: true,
    };
  }

  function resolveGetPageArgs(optionsOrSessionCtx = {}, sessionCtx = {}) {
    if (
      optionsOrSessionCtx &&
      typeof optionsOrSessionCtx === "object" &&
      ("xwikiToken" in optionsOrSessionCtx || "userId" in optionsOrSessionCtx) &&
      (!sessionCtx || Object.keys(sessionCtx).length === 0)
    ) {
      return { options: {}, sessionCtx: optionsOrSessionCtx };
    }

    return { options: optionsOrSessionCtx || {}, sessionCtx: sessionCtx || {} };
  }

  function resolveSearchArgs(limitOrOptions = 10, optionsOrSessionCtx = {}, maybeSessionCtx = {}) {
    if (
      optionsOrSessionCtx &&
      typeof optionsOrSessionCtx === "object" &&
      ("xwikiToken" in optionsOrSessionCtx || "userId" in optionsOrSessionCtx) &&
      (!maybeSessionCtx || Object.keys(maybeSessionCtx).length === 0)
    ) {
      return {
        limit: Number.isFinite(limitOrOptions) ? limitOrOptions : 10,
        options: {},
        sessionCtx: optionsOrSessionCtx,
      };
    }

    return {
      limit: Number.isFinite(limitOrOptions) ? limitOrOptions : 10,
      options: optionsOrSessionCtx || {},
      sessionCtx: maybeSessionCtx || {},
    };
  }

  function sliceContent(content, options = {}) {
    const includeContent = options.includeContent !== false;
    const normalizedContent = typeof content === "string" ? content : "";
    const totalLength = Number.isFinite(options.totalLengthOverride)
      ? Math.max(0, Math.trunc(options.totalLengthOverride))
      : normalizedContent.length;
    const offset = Number.isFinite(options.contentOffset) ? Math.max(0, Math.trunc(options.contentOffset)) : 0;
    const hasLength = Number.isFinite(options.contentLength);
    const length = hasLength ? Math.max(0, Math.trunc(options.contentLength)) : undefined;
    const baseTruncated = options.baseTruncated === true;

    if (!includeContent) {
      return {
        content: undefined,
        contentOffset: 0,
        contentLength: 0,
        totalContentLength: totalLength,
        contentTruncated: totalLength > 0 || baseTruncated,
      };
    }

    const slicedContent = hasLength
      ? normalizedContent.slice(offset, offset + length)
      : normalizedContent.slice(offset);

    return {
      content: slicedContent,
      contentOffset: offset,
      contentLength: slicedContent.length,
      totalContentLength: totalLength,
      contentTruncated: baseTruncated || offset > 0 || slicedContent.length < totalLength,
    };
  }

  // Every XWiki request carries the user's bearer token. A missing token is a programming
  // error, not an expired login: a plain Error, so the caller does not end the session.
  function authHeaders(sessionCtx) {
    const token = sessionCtx?.xwikiToken;
    if (typeof token !== "string" || token === "") throw new Error("missing XWiki token");
    return { Authorization: `Bearer ${token}`, Accept: "application/json" };
  }

  async function getFormToken(sessionCtx) {
    const res = await fetcher(`${baseUrl}/rest/`, { headers: authHeaders(sessionCtx) });
    if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
    return res.headers.get("XWiki-Form-Token") || "";
  }

  async function fetchPageRecord(pagePath, sessionCtx) {
    const res = await fetcher(getPageEndpoint(pagePath), { headers: authHeaders(sessionCtx) });
    if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
    if (res.status === 403) throw new Error("Access denied. Insufficient XWiki permissions.");
    if (!res.ok) throw new Error(`XWiki page fetch failed: ${res.status}`);
    return res.json();
  }

  // Shared by uploadAttachment (source_url) and the /uploads/:token presigned-URL route:
  // fetch the XWiki form token, then PUT the already-fetched bytes as an attachment.
  async function putAttachmentBytes(pagePath, filename, bytes, contentType, sessionCtx) {
    const formToken = await getFormToken(sessionCtx);
    const url = `${getPageEndpoint(pagePath)}/attachments/${encodeURIComponent(filename)}`;
    const headers = {
      ...authHeaders(sessionCtx),
      "Content-Type": contentType || "application/octet-stream",
      ...(formToken ? { "XWiki-Form-Token": formToken } : {}),
    };
    const res = await fetcher(url, { method: "PUT", headers, body: bytes });
    if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
    if (res.status === 403) throw new Error("Access denied. Insufficient XWiki permissions.");
    if (!res.ok) throw new Error(`XWiki attachment upload failed: ${res.status}`);
    return downloadUrl(pagePath, filename);
  }

  return {
    async search(query, limitOrOptions = 10, optionsOrSessionCtx = {}, maybeSessionCtx = {}) {
      const { limit, options, sessionCtx } = resolveSearchArgs(limitOrOptions, optionsOrSessionCtx, maybeSessionCtx);
      // Page name and title as well as content: a search for "EdooboxMCP" must find
      // IT.LLM.MCP.EdooboxMCP even if the word is not in the page body.
      const scopes = SEARCH_SCOPES.map((s) => `&scope=${s}`).join("");
      const url = `${baseUrl}/rest/wikis/${wiki}/search?q=${encodeURIComponent(query)}${scopes}&number=${limit}`;
      const res = await fetcher(url, { headers: authHeaders(sessionCtx) });
      if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
      if (!res.ok) throw new Error(`XWiki search failed: ${res.status}`);
      const data = await res.json();
      // One page can match in several scopes: keep its first hit only, then cap at limit.
      const seen = new Set();
      const unique = (data.searchResults || []).filter((r) => {
        const key = r.id || r.pageFullName || [r.space, r.pageName].filter(Boolean).join(".");
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      }).slice(0, Math.max(0, limit));
      const results = unique.map((r) => ({
        title: r.title || r.pageName,
        space: r.space,
        pagePath: r.pageFullName || [r.space, r.pageName].filter(Boolean).join("."),
        url: viewUrl(r.pageFullName),
      }));

      if (options.includeHeadings !== true) {
        return results.map(({ pagePath, ...result }) => result);
      }

      return Promise.all(results.map(async ({ pagePath, ...result }) => {
        const page = await fetchPageRecord(pagePath, sessionCtx);
        return {
          ...result,
          headings: extractHeadings(page.content, page.syntax),
        };
      }));
    },

    async getPage(pagePath, optionsOrSessionCtx = {}, maybeSessionCtx = {}) {
      const { options, sessionCtx } = resolveGetPageArgs(optionsOrSessionCtx, maybeSessionCtx);
      const page = await fetchPageRecord(pagePath, sessionCtx);
      const section = extractSectionByHeading(page.content, { ...options, syntax: page.syntax });
      return {
        title: page.title,
        author: page.author,
        modified: page.modified,
        syntax: page.syntax,
        ...sliceContent(section.content, {
          ...options,
          totalLengthOverride: section.content.length,
          baseTruncated: section.headingTruncated,
        }),
        sourceContentLength: section.sourceContentLength,
        headingMatched: section.headingMatched,
        headingOccurrence: section.headingOccurrence,
        headingLevel: section.headingLevel,
      };
    },

    async createPage(pagePath, title, content, sessionCtx = {}) {
      const formToken = await getFormToken(sessionCtx);
      const url = getPageEndpoint(pagePath);
      const xml = `<?xml version="1.0" encoding="UTF-8"?><page xmlns="http://www.xwiki.org"><title>${title}</title><syntax>${DEFAULT_SYNTAX}</syntax><content><![CDATA[${content}]]></content></page>`;
      const headers = {
        ...authHeaders(sessionCtx),
        "Content-Type": "application/xml",
        ...(formToken ? { "XWiki-Form-Token": formToken } : {}),
      };
      const res = await fetcher(url, { method: "PUT", headers, body: xml });
      if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
      if (res.status === 403) throw new Error("Access denied. Insufficient XWiki permissions.");
      if (!res.ok) throw new Error(`XWiki page create failed: ${res.status}`);
      return viewUrl(normalizePagePath(pagePath));
    },

    async uploadAttachment(pagePath, filename, { sourceUrl, contentType } = {}, sessionCtx = {}) {
      if (!filename) throw new Error("filename is required");
      if (!sourceUrl) throw new Error("source_url is required");
      const bytes = await fetchFromSourceUrl(sourceUrl);
      return putAttachmentBytes(pagePath, filename, bytes, contentType, sessionCtx);
    },

    putAttachmentBytes,
  };
}
