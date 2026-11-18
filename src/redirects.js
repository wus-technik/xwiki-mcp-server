// Redirect-URI and Origin allowlists for dynamic client registration.

const FIXED_REDIRECTS = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
  "https://chatgpt.com/connector_platform_oauth_redirect",
];
const FIXED_ORIGINS = ["https://claude.ai", "https://claude.com", "https://chatgpt.com"];
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1"]);

// Parse a redirect URI strictly; returns a URL or null.
function parseRedirect(raw) {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) return null;
  if (/[\s\\\u0000-\u001f]/.test(raw)) return null;
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  if (u.hash || raw.includes("#")) return null;
  if (u.username || u.password) return null;
  const authority = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[/?#]/)[0];
  if (authority.includes("@")) return null;
  // new URL() resolves dot segments; reject them in the raw input instead.
  const afterAuthority = raw.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, "");
  const rawPath = afterAuthority.split("?")[0];
  if (rawPath.split("/").some((s) => /^(\.|%2e){1,2}$/i.test(s))) return null;
  return u;
}

// Loopback per RFC 8252: literal lowercase "http://localhost" or "http://127.0.0.1",
// optional numeric port; returns the raw parts, port excluded.
function loopbackParts(raw) {
  if (!parseRedirect(raw)) return null;
  const m = /^http:\/\/(localhost|127\.0\.0\.1)(?::(\d{1,5}))?(?=[/?]|$)(.*)$/s.exec(raw);
  return m ? { host: m[1], rest: m[3] } : null;
}

export function isAllowedRedirect(uri, extra = []) {
  if (!parseRedirect(uri)) return false;
  if (loopbackParts(uri)) return true;
  if (FIXED_REDIRECTS.includes(uri)) return true;
  return extra.includes(uri);
}

export function redirectMatches(registered, requested) {
  if (!parseRedirect(requested) || !Array.isArray(registered)) return false;
  const req = loopbackParts(requested);
  return registered.some((r) => {
    if (!parseRedirect(r)) return false;
    const reg = loopbackParts(r);
    if (reg) return !!req && reg.host === req.host && reg.rest === req.rest;
    return r === requested;
  });
}

export function isAllowedOrigin(origin, mcpBaseUrl, extra = []) {
  if (typeof origin !== "string" || origin.length === 0) return false;
  const allowed = new Set([...FIXED_ORIGINS, ...extra]);
  try { allowed.add(new URL(mcpBaseUrl).origin); } catch { /* ignore */ }
  return allowed.has(origin);
}
