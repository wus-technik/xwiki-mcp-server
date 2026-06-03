export class XWikiAuthError extends Error {
  constructor(message) {
    super(message);
    this.name = "XWikiAuthError";
  }
}

export function createXWikiClient({ baseUrl, wiki, fetcher = fetch }) {
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

  return {
    async search(query, limit = 10, sessionCtx = {}) {
      const url = `${baseUrl}/rest/wikis/${wiki}/search?q=${encodeURIComponent(query)}&number=${limit}`;
      const res = await fetcher(url, { headers: cookieHeaders(sessionCtx) });
      if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
      if (!res.ok) throw new Error(`XWiki search failed: ${res.status}`);
      const data = await res.json();
      return (data.searchResults || []).map((r) => ({
        title: r.title || r.pageName,
        space: r.space,
        url: `${baseUrl}/bin/view/${(r.pageFullName || "").replace(/\./g, "/")}`,
      }));
    },

    async getPage(pagePath, sessionCtx = {}) {
      const parts = pagePath.replace(/\//g, ".").split(".");
      const spacePath = parts.slice(0, -1).join("/spaces/");
      const pageName = parts[parts.length - 1] || "WebHome";
      const url = `${baseUrl}/rest/wikis/${wiki}/spaces/${spacePath}/pages/${pageName}`;
      const res = await fetcher(url, { headers: cookieHeaders(sessionCtx) });
      if (res.status === 401) throw new XWikiAuthError("XWiki session expired. Please re-authenticate.");
      if (res.status === 403) throw new Error("Access denied. Insufficient XWiki permissions.");
      if (!res.ok) throw new Error(`XWiki page fetch failed: ${res.status}`);
      const page = await res.json();
      return { title: page.title, content: page.content, author: page.author, modified: page.modified };
    },

    async createPage(pagePath, title, content, sessionCtx = {}) {
      const formToken = await getFormToken(sessionCtx);
      const parts = pagePath.replace(/\//g, ".").split(".");
      const spacePath = parts.slice(0, -1).join("/spaces/");
      const pageName = parts[parts.length - 1] || "WebHome";
      const url = `${baseUrl}/rest/wikis/${wiki}/spaces/${spacePath}/pages/${pageName}`;
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
