import { lookup } from "node:dns/promises";

export class XWikiAuthError extends Error {
  constructor(message) {
    super(message);
    this.name = "XWikiAuthError";
  }
}

const DEFAULT_SYNTAX = "markdown/1.2";
export const MAX_SOURCE_URL_BYTES = 50 * 1024 * 1024;
const SOURCE_URL_TIMEOUT_MS = 30_000;

// ponytail: covers the common private/loopback/link-local ranges (including the
// 169.254.169.254 cloud metadata address); exotic ranges (e.g. 100.64.0.0/10 CGNAT)
// are not covered, add if a real target needs it.
function isDisallowedIp(ip) {
  if (ip.includes(":")) {
    const lower = ip.toLowerCase();
    if (lower === "::1") return true; // loopback
    if (lower.startsWith("::ffff:") && lower.slice(7).includes(".")) {
      return isDisallowedIp(lower.slice(7));
    }
    const firstGroup = parseInt(lower.split(":")[0] || "0", 16);
    if (firstGroup >= 0xfe80 && firstGroup <= 0xfebf) return true; // link-local
    if (firstGroup >= 0xfc00 && firstGroup <= 0xfdff) return true; // unique local (private)
    return false;
  }
  const octets = ip.split(".").map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n))) return true; // malformed, reject
  const [a, b] = octets;
  if (a === 127) return true; // loopback
  if (a === 10) return true; // private
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
  if (a === 0) return true; // unspecified/this-network
  return false;
}

export function createXWikiClient({ baseUrl, publicUrl, wiki, fetcher = fetch }) {
  const linkBase = (publicUrl || baseUrl || "").replace(/\/$/, "");

  function viewUrl(pageFullName) {
    const segments = String(pageFullName || "").split(".").map(encodeURIComponent);
    return `${linkBase}/bin/view/${segments.join("/")}`;
  }

  function downloadUrl(pagePath, filename) {
    const segments = normalizePagePath(pagePath).split(".").map(encodeURIComponent);
    return `${linkBase}/bin/download/${segments.join("/")}/${encodeURIComponent(filename)}`;
  }

  async function fetchFromSourceUrl(sourceUrl) {
    let parsed;
    try {
      parsed = new URL(sourceUrl);
    } catch {
      throw new Error("source_url is not a valid URL");
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("source_url must use http or https");
    }

    let trustedHost = "";
    try {
      trustedHost = new URL(baseUrl).hostname.toLowerCase();
    } catch {
      // no configured baseUrl to trust; fall through to the IP checks below
    }

    if (parsed.hostname.toLowerCase() !== trustedHost) {
      let addresses;
      try {
        addresses = await lookup(parsed.hostname, { all: true });
      } catch {
        throw new Error(`Could not resolve source_url host: ${parsed.hostname}`);
      }
      if (addresses.length === 0 || addresses.some((addr) => isDisallowedIp(addr.address))) {
        throw new Error("source_url resolves to a disallowed internal/private address");
      }
    }

    const res = await fetcher(sourceUrl, { signal: AbortSignal.timeout(SOURCE_URL_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`Failed to fetch source_url: ${res.status}`);

    const declaredLength = Number(res.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_SOURCE_URL_BYTES) {
      throw new Error(`source_url content exceeds maximum allowed size (${MAX_SOURCE_URL_BYTES} bytes)`);
    }

    if (res.body && typeof res.body.getReader === "function") {
      const reader = res.body.getReader();
      const chunks = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > MAX_SOURCE_URL_BYTES) {
          reader.cancel().catch(() => {});
          throw new Error(`source_url content exceeds maximum allowed size (${MAX_SOURCE_URL_BYTES} bytes)`);
        }
        chunks.push(value);
      }
      return Buffer.concat(chunks);
    }

    const bytes = Buffer.from(await res.arrayBuffer());
    if (bytes.length > MAX_SOURCE_URL_BYTES) {
      throw new Error(`source_url content exceeds maximum allowed size (${MAX_SOURCE_URL_BYTES} bytes)`);
    }
    return bytes;
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

  function extractHeadings(content) {
    const lines = String(content || "").split("\n");
    const occurrences = new Map();
    const headings = [];

    for (const line of lines) {
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
    const headings = [];
    let cursor = 0;

    for (const line of lines) {
      const parsedHeading = parseHeadingLine(line);
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
      ("xwikiCookie" in optionsOrSessionCtx || "userId" in optionsOrSessionCtx) &&
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
      ("xwikiCookie" in optionsOrSessionCtx || "userId" in optionsOrSessionCtx) &&
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

  function cookieHeaders(sessionCtx) {
    return sessionCtx?.xwikiCookie
      ? { Cookie: sessionCtx.xwikiCookie, Accept: "application/json" }
      : { Accept: "application/json" };
  }

  // Any authenticated request resets Tomcat's idle timer (30 min) for this session.
  async function touchSession(sessionCtx) {
    const res = await fetcher(`${baseUrl}/rest/`, { headers: cookieHeaders(sessionCtx) });
    return res.status;
  }

  async function getFormToken(sessionCtx) {
    const res = await fetcher(`${baseUrl}/rest/`, { headers: cookieHeaders(sessionCtx) });
    if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
    return res.headers.get("XWiki-Form-Token") || "";
  }

  async function fetchPageRecord(pagePath, sessionCtx) {
    const res = await fetcher(getPageEndpoint(pagePath), { headers: cookieHeaders(sessionCtx) });
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
      ...cookieHeaders(sessionCtx),
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
    touchSession,

    async search(query, limitOrOptions = 10, optionsOrSessionCtx = {}, maybeSessionCtx = {}) {
      const { limit, options, sessionCtx } = resolveSearchArgs(limitOrOptions, optionsOrSessionCtx, maybeSessionCtx);
      const url = `${baseUrl}/rest/wikis/${wiki}/search?q=${encodeURIComponent(query)}&number=${limit}`;
      const res = await fetcher(url, { headers: cookieHeaders(sessionCtx) });
      if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
      if (!res.ok) throw new Error(`XWiki search failed: ${res.status}`);
      const data = await res.json();
      const results = (data.searchResults || []).map((r) => ({
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
          headings: extractHeadings(page.content),
        };
      }));
    },

    async getPage(pagePath, optionsOrSessionCtx = {}, maybeSessionCtx = {}) {
      const { options, sessionCtx } = resolveGetPageArgs(optionsOrSessionCtx, maybeSessionCtx);
      const page = await fetchPageRecord(pagePath, sessionCtx);
      const section = extractSectionByHeading(page.content, options);
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
        ...cookieHeaders(sessionCtx),
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
