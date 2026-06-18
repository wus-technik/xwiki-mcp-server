export class XWikiAuthError extends Error {
  constructor(message) {
    super(message);
    this.name = "XWikiAuthError";
  }
}

export function createXWikiClient({ baseUrl, wiki, fetcher = fetch }) {
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
    const match = line.match(/^(=+)\s*(.*?)\s*\1\s*$/);
    if (!match) return null;
    return {
      level: match[1].length,
      title: match[2].trim(),
    };
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

  return {
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
        url: `${baseUrl}/bin/view/${(r.pageFullName || "").replace(/\./g, "/")}`,
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
      const xml = `<?xml version="1.0" encoding="UTF-8"?><page xmlns="http://www.xwiki.org"><title>${title}</title><content><![CDATA[${content}]]></content></page>`;
      const headers = {
        ...cookieHeaders(sessionCtx),
        "Content-Type": "application/xml",
        ...(formToken ? { "XWiki-Form-Token": formToken } : {}),
      };
      const res = await fetcher(url, { method: "PUT", headers, body: xml });
      if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
      if (res.status === 403) throw new Error("Access denied. Insufficient XWiki permissions.");
      if (!res.ok) throw new Error(`XWiki page create failed: ${res.status}`);
      return `${baseUrl}/bin/view/${pagePath.replace(/\./g, "/")}`;
    },
  };
}
