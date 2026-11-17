import { jwtVerify, createRemoteJWKSet } from "jose";

// Error messages never carry tokens, cookies or response bodies.
export class AuthentikError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "AuthentikError";
    this.code = code;
  }
}
export class AuthentikRejected extends AuthentikError {
  constructor(message = "Authentik rejected the request") {
    super("rejected", message);
    this.name = "AuthentikRejected";
  }
}
export class AuthentikUnavailable extends AuthentikError {
  constructor(message = "Authentik unavailable") {
    super("unavailable", message);
    this.name = "AuthentikUnavailable";
  }
}

export function createAuthentik({
  issuer,
  appSlug = "xwiki-mcp",
  clientId,
  clientSecret,
  redirectUri,
  allowedGroups = [],
  fetcher = fetch,
  jwks,
  timeoutMs = 10000,
}) {
  const base = issuer.replace(/\/$/, "");
  const idpIssuer = `${base}/application/o/${appSlug}/`;
  let keySet = jwks;
  const getKeys = () => (keySet ||= createRemoteJWKSet(new URL(`${base}/application/o/${appSlug}/jwks/`)));

  // Network errors, timeouts and 5xx become AuthentikUnavailable; the caller maps other statuses.
  async function request(url, init) {
    let res;
    try {
      res = await fetcher(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    } catch {
      throw new AuthentikUnavailable();
    }
    if (res.status >= 500) throw new AuthentikUnavailable();
    return res;
  }

  function tokenRequest(params) {
    return request(`${base}/application/o/token/`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({ ...params, client_id: clientId, client_secret: clientSecret }).toString(),
    });
  }

  const readJson = async (res) => {
    try {
      return await res.json();
    } catch {
      // Unreadable body (parse error, abort/timeout while reading): not a verdict from Authentik.
      throw new AuthentikUnavailable();
    }
  };

  // Only genuine token/claim failures count as an invalid ID token; JWKS fetch problems
  // (timeout, network, non-200) are infrastructure errors.
  const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
  const INVALID_TOKEN_CODES = new Set([
    "ERR_JWT_CLAIM_VALIDATION_FAILED",
    "ERR_JWT_EXPIRED",
    "ERR_JWT_INVALID",
    "ERR_JWS_INVALID",
    "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
    "ERR_JOSE_ALG_NOT_ALLOWED",
    "ERR_JOSE_NOT_SUPPORTED",
    "ERR_JWKS_NO_MATCHING_KEY",
  ]);

  return {
    authorizeUrl({ state, nonce }) {
      const q = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: "openid profile email offline_access",
        state,
        nonce,
      });
      return `${base}/application/o/authorize/?${q}`;
    },

    async exchangeCode(code, expectedNonce) {
      const res = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: redirectUri });
      if (!res.ok) throw new AuthentikError("exchange_failed", `Token exchange failed (HTTP ${res.status})`);
      const body = await readJson(res);
      if (!body?.id_token) throw new AuthentikError("invalid_id_token", "Token response has no id_token");
      if (typeof body.id_token !== "string" || !COMPACT_JWS.test(body.id_token)) {
        throw new AuthentikError("invalid_id_token", "ID token is not a compact JWS");
      }
      let payload;
      try {
        ({ payload } = await jwtVerify(body.id_token, getKeys(), {
          issuer: idpIssuer,
          audience: clientId,
          algorithms: ["RS256"],
          requiredClaims: ["exp"],
        }));
      } catch (e) {
        if (INVALID_TOKEN_CODES.has(e?.code)) throw new AuthentikError("invalid_id_token", "ID token verification failed");
        throw new AuthentikUnavailable("JWKS unavailable");
      }
      if (!expectedNonce || payload.nonce !== expectedNonce) {
        throw new AuthentikError("invalid_id_token", "ID token nonce mismatch");
      }
      if (typeof payload.sub !== "string" || !payload.sub) {
        throw new AuthentikError("invalid_id_token", "ID token has no sub");
      }
      if (typeof payload.preferred_username !== "string" || !payload.preferred_username) {
        throw new AuthentikError("invalid_id_token", "ID token has no preferred_username");
      }
      if (!body.refresh_token) throw new AuthentikError("no_refresh_token", "Token response has no refresh_token");
      return { sub: payload.sub, username: payload.preferred_username, refreshToken: body.refresh_token };
    },

    async refresh(refreshToken) {
      const res = await tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
      if (res.status === 400 || res.status === 401) throw new AuthentikRejected(`Refresh rejected (HTTP ${res.status})`);
      if (!res.ok) throw new AuthentikUnavailable(`Refresh failed (HTTP ${res.status})`);
      const body = await readJson(res);
      if (!body?.access_token) throw new AuthentikRejected("Refresh response has no access_token");
      // Authentik may not rotate the refresh token; keep the old one then.
      return { refreshToken: body.refresh_token || refreshToken, accessToken: body.access_token };
    },

    async checkUser(accessToken) {
      const res = await request(`${base}/application/o/userinfo/`, {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      });
      if (res.status === 401) throw new AuthentikRejected("Userinfo rejected (HTTP 401)");
      if (!res.ok) throw new AuthentikUnavailable(`Userinfo failed (HTTP ${res.status})`);
      const body = await readJson(res);
      if (!Array.isArray(body?.groups)) throw new AuthentikRejected("Userinfo has no groups");
      if (!body.groups.some((g) => allowedGroups.includes(g))) throw new AuthentikRejected("User not in an allowed group");
    },
  };
}
