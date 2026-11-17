# xwiki-MCP: OAuth für alle Zugangswege – Umsetzungsplan (Code)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Der MCP-Server gibt rotierende Refresh-Tokens aus, arbeitet je Sitzung mit einem eigenen XWiki-Consent-Token statt mit dem Browser-Cookie und erfüllt die Discovery- und Transportregeln, die claude.ai, ChatGPT, Claude Code und Codex erwarten.

**Architecture:** Der Server bleibt sein eigener OAuth-Autorisierungsserver (DCR, PKCE) und meldet Nutzer über Authentik an (Provider 112, `offline_access`). Beim Login legt er mit dem einmal vorliegenden Browser-Cookie einen XWiki-Consent-Token an und verwirft das Cookie. Danach laufen alle XWiki-Aufrufe mit `Authorization: Bearer`. Der Zustand liegt in einer verschlüsselten JSON-Datei, die jeder Schreibvorgang vor der Antwort an den Client sichert.

**Tech Stack:** Node.js (ESM; Dockerfile `node:20-alpine`, lokal 26), Express 4, `jose` 6, `cookie-parser`, Tests mit `node --test` und `supertest`.

**Spec:** `~/projects/_operations/docs/superpowers/specs/2026-11-17-xwiki-mcp-global-oauth-design.md` (Abschnitte 5.x und 5.9). Review: `~/projects/_operations/docs/superpowers/reviews/2026-11-17-xwiki-mcp-global-oauth-design.md`. Betriebsplan (Vortest, Authentik, HAProxy, Deploy, Rollout): `~/projects/_operations/docs/superpowers/plans/2026-11-17-xwiki-mcp-global-oauth-betrieb.md`.

**Voraussetzung:** Phase 0 des Betriebsplans (Vortest XWiki) ist durch. Sie liefert die geschwärzten HTML-Antworten unter `test/fixtures/xwiki-18.7.0/` und die Werte in `test/fixtures/xwiki-18.7.0/README.md` (URL der Profilseite „Anwendungen“, Feldnamen, Zuordnung Authentik → XWiki-Benutzer). Ohne diese Dateien nicht mit Task 7 beginnen.

**Branch:** `feat/global-oauth` (von `hosted`). Kein Push auf `hosted`: Ein Push dort baut sofort das Produktions-Image. Merge nur per PR nach Codex-Review (Task 15).

## Global Constraints

- Issuer und Resource: `MCP_BASE_URL` = `https://xwiki.wus-technik.com/mcp`, auf allen Metadaten-Pfaden identisch.
- Access-Token: HS256-JWT, Laufzeit **3600 s**, Claims `iss`=`MCP_BASE_URL`, `aud`=`MCP_BASE_URL`, `sub`, `sid`, `client_id`, `ver`. Die Prüfung verlangt `alg=HS256`, `iss`, `aud`, `exp` und eine bekannte Sitzung.
- Refresh-Token: ≥ 256 Bit Zufall, base64url, gespeichert nur als SHA-256-Hash. **30 Tage gleitend** ab letzter Nutzung, Rotation bei jeder Nutzung, Wiederholungsfenster **30 s**.
- XWiki-Token: Laufzeit **90 Tage**, Erneuerung bei **< 14 Tagen** Restlaufzeit. Name `xwiki-mcp – <client_name> – <JJJJ-MM-TT>`.
- Sitzung endet nach **30 Tagen** ohne Client-Refresh. Der tägliche Abgleich verlängert diese Frist nicht.
- `SESSION_SECRET` ≥ 32 Byte, `TOKEN_ENC_KEY` = 32 Byte (base64). Fehlt eins oder ist es zu kurz, startet der Server nicht.
- Unlesbare oder nicht entschlüsselbare Speicherdatei → Start verweigert. Kein automatischer Neuanfang.
- Ein Token oder eine Rotation gilt erst als erledigt, wenn `store.mutate()` erfolgreich geschrieben hat.
- Redirect-Allowlist: `http://localhost:<port>/…`, `http://127.0.0.1:<port>/…` (Port frei), `https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`, `https://chatgpt.com/connector_platform_oauth_redirect`, plus Env `EXTRA_REDIRECT_URIS` (kommagetrennt, exakt).
- Origin-Allowlist (nur wenn ein `Origin`-Header kommt): `https://claude.ai`, `https://claude.com`, `https://chatgpt.com`, Origin von `MCP_BASE_URL`, plus Env `EXTRA_ORIGINS`.
- Berechtigte Gruppen: Env `ALLOWED_GROUPS` (Default `AdminsIT,xwiki_redaktion`).
- Unterstützte MCP-Protokollversionen: `2025-06-18`, `2025-03-26`, `2024-11-05`.
- Kein Klartext-Token, kein Cookie und kein Refresh-Token in Logs. `AUTH_DEBUG` loggt nur Ereignisnamen, Sitzungs-ID (gekürzt auf 8 Zeichen), Benutzer und Client-Name.
- Commit-Nachrichten auf Deutsch, Präfix wie bisher (`feat(auth): …`, `fix(…): …`). Kein Co-Author-Trailer.

## Review Focus

1. **Zwei Clients refreshen dieselbe Sitzung gleichzeitig** (z. B. Claude-App auf zwei Geräten mit derselben Sitzung kann nicht vorkommen, wohl aber ein Client, der nach Timeout wiederholt): beide bekommen eine gültige Antwort, die Sitzung überlebt. → Test in Task 9.
2. **XWiki antwortet auf das Anlegen des Tokens mit der Login-Seite** (Cookie schon abgelaufen, Redirect auf `/bin/login`): Login bricht mit Fehlerseite ab, kein Code, kein Sitzungsrest. → Test in Task 7.
3. **XWiki-Neustart während einer Sitzung:** Bearer-Token bleibt gültig, kein Re-Login. → E2E-Test in Task 14.
4. **Speicherdatei wird beim Schreiben voll/gesperrt:** Client bekommt einen Fehler, und nach einem Neustart sind Client und Server sich über das gültige Refresh-Token einig. → Test in Task 3 und Task 9.
5. **Nutzer löscht den Token im XWiki-Profil:** nächster Aufruf → 401 mit `resource_metadata`, Sitzung beendet, kein Absturz, kein Aufräumversuch in Schleife. → Test in Task 11.

---

## Dateistruktur

| Datei | Verantwortung | Status |
|---|---|---|
| `src/config.js` | Env lesen, `validateConfig()` | ändern |
| `src/crypto-box.js` | AES-256-GCM `seal`/`open` | neu |
| `src/store.js` | dauerhafter Zustand, `mutate()`, Sperre je Sitzung | neu, ersetzt `session-store.js` |
| `src/redirects.js` | Redirect- und Origin-Allowlist | neu |
| `src/metadata.js` | RFC 9728/8414/OIDC-Metadaten, 401-Challenge | neu |
| `src/authentik.js` | Code-Tausch, ID-Token-Prüfung, Refresh, Userinfo/Gruppen | neu |
| `src/xwiki-tokens.js` | XWiki-Consent-Token anlegen/löschen/prüfen, HTML-Parser | neu |
| `src/oauth.js` | `/register`, `/authorize`, `/oauth/callback`, `/oauth/complete`, `/oauth/consent`, `/token`, `/revoke` | umbauen |
| `src/sessions.js` | Sitzung anlegen/beenden, Refresh-Familien, Aufräumen, täglicher Abgleich | neu |
| `src/auth-middleware.js` | Access-Token prüfen | ändern |
| `src/mcp-handler.js` | Versionsaushandlung | ändern |
| `src/app.js` | Routing, 405, Origin, 401 mit Version | ändern |
| `src/xwiki-client.js` | Bearer statt Cookie, SSRF-Fix | ändern |
| `src/upload-route.js` | Bearer, Nonce dauerhaft und atomar | ändern |
| `src/sse-handler.js`, `src/keepalive.js`, `src/session-store.js` | entfallen | löschen |
| `server.js` | Start: `validateConfig`, `openStore`, Hintergrundläufe | ändern |
| `docker-compose.yml`, `README.md` | neue Env, Datenpfad | ändern |

Das Session-Objekt, das an Tools und `xwikiClient` geht (**`SessionCtx`**), ist ab Task 3 überall:
`{ sessionId: string, userId: string, xwikiUser: string, xwikiToken: string, tokenVersion: number }`.

---

### Task 1: Konfiguration härten

**Files:**
- Modify: `src/config.js`
- Test: `test/config.test.js` (neu)

**Interfaces:**
- Produces: `loadConfig(env = process.env) -> Config` und `validateConfig(cfg: Config) -> void` (wirft `Error` mit Klartext). `Config` hat die Felder `port, xwikiUrl, xwikiPublicUrl, xwikiWiki, oauthClientId, oauthClientSecret, oauthRedirectUri, authentikIssuer, mcpBaseUrl, sessionSecret, tokenEncKey (Buffer), storeFile, allowedGroups (string[]), extraRedirectUris (string[]), extraOrigins (string[]), authDebug (bool)`.

- [ ] **Step 1: Tests schreiben**

```js
test("validateConfig lehnt kurzes SESSION_SECRET ab", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, SESSION_SECRET: "kurz" })), /SESSION_SECRET/);
});
test("validateConfig lehnt fehlenden TOKEN_ENC_KEY ab", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, TOKEN_ENC_KEY: "" })), /TOKEN_ENC_KEY/);
});
test("validateConfig lehnt TOKEN_ENC_KEY ungleich 32 Byte ab", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, TOKEN_ENC_KEY: Buffer.alloc(16).toString("base64") })), /32/);
});
test("ALLOWED_GROUPS hat den Default AdminsIT,xwiki_redaktion", () => {
  assert.deepEqual(loadConfig(base).allowedGroups, ["AdminsIT", "xwiki_redaktion"]);
});
test("STORE_FILE ist Pflicht", () => {
  assert.throws(() => validateConfig(loadConfig({ ...base, STORE_FILE: "" })), /STORE_FILE/);
});
```
`base` enthält gültige Werte für alle Pflichtvariablen (`SESSION_SECRET` 32 Zeichen, `TOKEN_ENC_KEY` = `Buffer.alloc(32,1).toString("base64")`, `STORE_FILE=/tmp/x.json`, die OAuth-/XWiki-Variablen).

- [ ] **Step 2:** `node --test test/config.test.js` → FAIL (`loadConfig` fehlt).
- [ ] **Step 3:** `loadConfig`/`validateConfig` umsetzen. Die bisherigen benannten Exporte (`XWIKI_URL` …) entfallen. `SESSION_FILE` wird zu `STORE_FILE`. Der Default-Secret `dev-insecure-secret-change-me` entfällt überall (`grep -rn dev-insecure src` muss leer sein).
- [ ] **Step 4:** `node --test test/config.test.js` → PASS.
- [ ] **Step 5:** Commit `feat(config): Pflichtwerte pruefen, kein unsicherer Default-Secret`.

### Task 2: Verschlüsselung

**Files:**
- Create: `src/crypto-box.js`
- Test: `test/crypto-box.test.js`

**Interfaces:**
- Produces: `seal(plaintext: string, key: Buffer, aad: string) -> string` (Format `v1.<iv b64url>.<ct b64url>.<tag b64url>`), `open(sealed: string, key: Buffer, aad: string) -> string` (wirft bei falschem Schlüssel/AAD).

- [ ] **Step 1: Tests:** Rundreise ergibt den Klartext; zweimal `seal` desselben Texts ergibt verschiedene Werte; `open` mit anderem `aad` wirft; `open` mit anderem Schlüssel wirft.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** AES-256-GCM, 12-Byte-IV aus `randomBytes` je Aufruf, `setAAD(Buffer.from(aad))`.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(crypto): AES-256-GCM fuer gespeicherte Geheimnisse`.

### Task 3: Dauerhafter Speicher

**Files:**
- Create: `src/store.js`
- Delete: `src/session-store.js`, `test/session-store.test.js`, `test/session-persistence.test.js`
- Test: `test/store.test.js`

**Interfaces:**
- Consumes: `seal`/`open` (Task 2).
- Produces:
  - `openStore({ file: string, key: Buffer, fs? }) -> Store`. Datei fehlt → leerer Zustand und sofort geschrieben. Datei unlesbar, kein JSON oder `open` wirft → `throw new StoreCorruptError(file)`.
  - `Store.read() -> State` (tiefe Kopie, nur lesen).
  - `Store.mutate(fn: (draft: State) => T) -> Promise<T>`: wendet `fn` auf eine Kopie an, schreibt atomar (tmp + rename, Modus 0600). Erst danach wird die Kopie zum Zustand. Scheitert das Schreiben, bleibt der alte Zustand und der Fehler wird geworfen. Aufrufe laufen nacheinander (eine Promise-Kette).
  - `Store.withLock(key: string, fn: () => Promise<T>) -> Promise<T>`: Sperre je Schlüssel (z. B. Sitzungs-ID) im Prozess.
  - `Store.sealField(value: string, aad: string) -> string`, `Store.openField(sealed: string, aad: string) -> string`.
  - `State`: `{ version: 1, clients: {[clientId]: Client}, grants: {[`${sub}|${clientId}`]: { at: number }}, sessions: {[sid]: Session}, families: {[familyId]: Family}, cleanups: {[id]: Cleanup}, uploadNonces: {[nonce]: number /*exp*/} }`.
  - `Client`: `{ clientId, clientName, redirectUris: string[], createdAt, lastUsedAt }`.
  - `Session`: `{ sid, sub, userId, xwikiUser, clientId, familyId, xwikiTokenSealed, consentId, tokenVersion, tokenExpiresAt, authentikRefreshSealed, createdAt, lastClientRefreshAt }`.
  - `Family`: `{ familyId, sid, clientId, currentHash, spentHashes: string[], replay: { hash, responseSealed, until } | null }`.
  - `Cleanup`: `{ id, xwikiTokenSealed, consentId, xwikiUser, reason, createdAt, attempts, lastError }`.

- [ ] **Step 1: Tests:**
  - `mutate` schreibt, ein neues `openStore` auf dieselbe Datei liest denselben Zustand.
  - Mit einem `fs`-Stub, dessen `renameSync` wirft: `mutate` wirft, `read()` zeigt den alten Zustand.
  - Datei mit Müll → `openStore` wirft `StoreCorruptError`.
  - Falscher Schlüssel bei vorhandenem versiegeltem Feld → `openStore` wirft `StoreCorruptError` (beim Laden wird ein Prüffeld `check = seal("ok")` geöffnet).
  - Zwei `withLock("a", …)` laufen nacheinander, `withLock("b", …)` parallel dazu.
  - Geschriebene Datei hat Modus 0600 (nur auf POSIX prüfen, unter Windows `test.skip`).
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen. `fs` injizierbar (Default `node:fs`), damit Schreibfehler testbar sind.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(store): verschluesselter Zustand, Schreiben vor Bestaetigung`.

### Task 4: Redirect- und Origin-Allowlist, DCR

**Files:**
- Create: `src/redirects.js`
- Modify: `src/oauth.js` (Handler `register`)
- Test: `test/redirects.test.js`, `test/register.test.js`

**Interfaces:**
- Produces: `isAllowedRedirect(uri: string, extra: string[]) -> boolean`, `redirectMatches(registered: string[], requested: string) -> boolean` (exakt; bei Loopback darf nur der Port abweichen, RFC 8252), `isAllowedOrigin(origin: string, mcpBaseUrl: string, extra: string[]) -> boolean`.
- `POST /register` und `/mcp/oauth/register`: speichert `Client` per `store.mutate`, antwortet 201 mit `client_id`, `client_id_issued_at`, `client_name`, `redirect_uris`, `token_endpoint_auth_method: "none"`, `grant_types: ["authorization_code","refresh_token"]`, `response_types: ["code"]`.

- [ ] **Step 1: Tests:**
  - `isAllowedRedirect("http://localhost:3118/callback")` → true; `"http://127.0.0.1:50000/cb"` → true; `"https://claude.ai/api/mcp/auth_callback"` → true; `"https://evil.example/cb"` → false; `"http://localhost.evil.example/cb"` → false; `"https://claude.ai/api/mcp/auth_callback/../x"` → false.
  - `redirectMatches(["http://localhost:3118/callback"], "http://localhost:4000/callback")` → true; anderer Pfad → false.
  - `/register` mit `redirect_uris: ["https://evil.example/cb"]` → 400 `{"error":"invalid_redirect_uri"}`; mit erlaubter URI → 201, Felder wie oben, Client im Store.
  - `isAllowedOrigin("https://claude.ai")` → true; `"https://evil.example"` → false.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Mit `new URL()` vergleichen (Schema, Host, Port, Pfad), keine String-Präfixe.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(oauth): DCR speichert Clients, Redirect-Allowlist`.

### Task 5: Metadaten und 401-Challenge

**Files:**
- Create: `src/metadata.js`
- Modify: `src/app.js` (Routen einhängen)
- Test: `test/metadata.test.js`

**Interfaces:**
- Produces: `resourceMetadata(cfg) -> object`, `asMetadata(cfg) -> object`, `mountMetadata(app: Express, cfg)`, `sendUnauthorized(res, cfg, { error?: string, description?: string })` (setzt `WWW-Authenticate: Bearer realm="<base>", resource_metadata="<base>/.well-known/oauth-protected-resource"` plus `error`/`error_description`, Status 401, JSON-Body).
- AS-Metadaten: `issuer`, `authorization_endpoint` (`<base>/oauth/authorize`), `token_endpoint`, `registration_endpoint`, `revocation_endpoint` (`<base>/oauth/revoke`), `response_types_supported: ["code"]`, `grant_types_supported: ["authorization_code","refresh_token"]`, `code_challenge_methods_supported: ["S256"]`, `token_endpoint_auth_methods_supported: ["none"]`, `revocation_endpoint_auth_methods_supported: ["none"]`, `scopes_supported: ["xwiki"]`. OIDC-Aliasse liefern dasselbe Objekt.
- Resource-Metadaten: `resource`, `authorization_servers: [base]`, `bearer_methods_supported: ["header"]`, `scopes_supported: ["xwiki"]`.

- [ ] **Step 1: Tests:** Für jeden der Pfade `/.well-known/oauth-protected-resource`, `/.well-known/oauth-protected-resource/mcp`, `/mcp/.well-known/oauth-protected-resource` → 200, `resource === base`. Für `/.well-known/oauth-authorization-server`, `/.well-known/oauth-authorization-server/mcp`, `/mcp/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration/mcp`, `/mcp/.well-known/openid-configuration` → 200, `issuer === base`, `grant_types_supported` enthält `refresh_token`. `sendUnauthorized` mit `error:"invalid_token"` → Header enthält sowohl `resource_metadata=` als auch `error="invalid_token"`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen; die alten Handler `resourceMetadata`/`asMetadata` in `oauth.js` entfallen.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(oauth): Metadaten unter allen Discovery-Pfaden`.

### Task 6: Authentik-Anbindung

**Files:**
- Create: `src/authentik.js`
- Test: `test/authentik.test.js`

**Interfaces:**
- Produces: `createAuthentik({ issuer, clientId, clientSecret, redirectUri, allowedGroups, fetcher = fetch, jwks? })` mit
  - `authorizeUrl({ state, nonce }) -> string` (Scope `openid profile email offline_access`),
  - `exchangeCode(code, expectedNonce) -> Promise<{ sub, username, refreshToken }>`: Token-Endpunkt `<issuer>/application/o/token/`, prüft das ID-Token mit `jwtVerify` gegen `createRemoteJWKSet(<issuer>/application/o/xwiki-mcp/jwks/)`, `issuer = <issuer>/application/o/xwiki-mcp/`, `audience = clientId`, `nonce === expectedNonce`. Fehlt `refresh_token` → `AuthentikError("no_refresh_token")`. `username = preferred_username` (Pflicht).
  - `refresh(refreshToken) -> Promise<{ refreshToken, accessToken }>`: `grant_type=refresh_token`. 400/401 → `AuthentikRejected`. Netz/5xx/Timeout (10 s) → `AuthentikUnavailable`. Fehlt ein neues `refresh_token` in der Antwort → altes behalten (Lehre aus Provider 88).
  - `checkUser(accessToken) -> Promise<void>`: Userinfo `<issuer>/application/o/userinfo/`; wirft `AuthentikRejected`, wenn 401 oder `groups` keinen Eintrag aus `allowedGroups` enthält.
- Der Issuer-Pfad (`/application/o/xwiki-mcp/`) kommt aus Env `AUTHENTIK_APP_SLUG` (Default `xwiki-mcp`); Task 1 um dieses Feld ergänzen.

- [ ] **Step 1: Tests** mit `fetcher`-Stub und lokal erzeugtem Schlüsselpaar (`generateKeyPair("RS256")`, `jwks` injiziert):
  - gültiges ID-Token → `{ sub, username, refreshToken }`;
  - falsche `nonce`, falsches `aud`, abgelaufenes `exp` → wirft;
  - Antwort ohne `refresh_token` → `no_refresh_token`;
  - `refresh` mit 400 `invalid_grant` → `AuthentikRejected`; mit 503 → `AuthentikUnavailable`; Antwort ohne neues Refresh-Token → altes zurück;
  - `checkUser` mit `groups: ["Mitarbeiter"]` → `AuthentikRejected`; mit `["xwiki_redaktion"]` → ok.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(auth): Authentik-Login mit ID-Token-Pruefung, Refresh und Gruppen`.

### Task 7: XWiki-Consent-Tokens

**Files:**
- Create: `src/xwiki-tokens.js`
- Test: `test/xwiki-tokens.test.js`, Fixtures `test/fixtures/xwiki-18.7.0/*` (aus Phase 0 des Betriebsplans)

**Interfaces:**
- Produces: `createXWikiTokens({ baseUrl, fetcher = fetch })` mit
  - `whoami(auth: { cookie?: string, bearer?: string }) -> Promise<string|null>`: `GET /rest/`, Header `XWiki-User`; Gast oder fehlend → `null`.
  - `createToken(auth, { xwikiUser, appName, days }) -> Promise<{ token, consentId, expiresAt }>`: GET der Profilseite „Anwendungen“ (URL-Muster aus `test/fixtures/xwiki-18.7.0/README.md`), `form_token` lesen, POST mit `form_token`, `oidc_consent_create=1`, `application_name`, `expiration=<days>`. Token mit `parseCreatedToken(html)`, Consent-ID mit `parseConsentList(html)` über `appName`. Danach `whoami({ bearer: token }) === xwikiUser`, sonst Fehler. **Redirect-Antworten nicht folgen** (`redirect: "manual"`): 3xx oder eine Antwort ohne erkennbaren Token → `XWikiTokenError("login_required"|"unexpected_page")`.
  - `deleteToken(auth, { xwikiUser, consentId }) -> Promise<"deleted"|"gone">`: POST `oidc_consent_delete` + `consent_id`; 401 mit dem eigenen Bearer → `"gone"`.
  - `findTokensByPrefix(auth, xwikiUser, prefix) -> Promise<Array<{ consentId, name }>>` (für die Wiederfindung nach Absturz).
  - `parseCreatedToken(html) -> string|null`, `parseConsentList(html) -> Array<{ consentId, name, expiresAt|null }>`.

- [ ] **Step 1: Tests** gegen die Fixtures:
  - `parseCreatedToken(created.html)` liefert den geschwärzten Platzhalter `REDACTED-CONSENT/REDACTED-RANDOM`.
  - `parseConsentList(list.html)` liefert die Einträge aus `README.md` mit `consentId` und `name`.
  - `createToken` mit Stub, der auf den POST mit 302 nach `/bin/login/…` antwortet → `XWikiTokenError("login_required")`. **(Review Focus 2)**
  - `createToken`, bei dem `whoami` mit dem neuen Token einen anderen Benutzer liefert → wirft, und der neue Token wird per `deleteToken` wieder gelöscht.
  - `deleteToken` mit 401 → `"gone"`.
  - Die Fehlermeldungen enthalten nie den Token- oder Cookie-Wert.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen. Ein Parser auf Basis regulärer Ausdrücke gegen die Fixture-Struktur genügt. Bei unbekanntem Aufbau `unexpected_page` werfen, nie raten.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(xwiki): Consent-Tokens anlegen, pruefen und loeschen`.

### Task 8: Login-Ablauf (`/authorize` → Authentik → XWiki → Zustimmung → Code)

**Files:**
- Modify: `src/oauth.js`
- Create: `src/sessions.js` (Teil 1: `createSession`)
- Test: `test/login-flow.test.js`

**Interfaces:**
- Consumes: Tasks 3–7.
- Produces in `src/sessions.js`: `createSession(deps, { sub, userId, xwikiUser, clientId, authentikRefresh, xwikiToken, consentId, tokenExpiresAt }) -> Promise<{ sid, familyId }>`. `deps = { store, cfg, authentik, xwikiTokens, now }`.
- Ablauf und Regeln:
  - `GET /authorize`, `/mcp/oauth/authorize`: verlangt registrierte `client_id`, `redirectMatches`, `response_type=code`, `S256`, `state`; `resource` falls angegeben = `mcpBaseUrl`, sonst 400 `invalid_target`. Speichert im Speicher (10 min) `{ clientId, redirectUri, codeChallenge, clientState, resource, nonce, flowId }` unter `serverState`. Setzt Cookie `xmcp_flow=<flowId>` (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/mcp/oauth`, 10 min). Antwort 302 auf `authentik.authorizeUrl`.
  - `GET /mcp/oauth/callback`: `state` auflösen, `xmcp_flow` muss passen, sonst 400. `authentik.exchangeCode` → `{ sub, username, refreshToken }`. Weiter wie heute über `/bin/login/XWiki/XWikiLogin?xredirect=/mcp/oauth/complete?t=<pendingId>`.
  - `GET /mcp/oauth/complete`: `xmcp_flow` muss passen. `xwikiUser = whoami({ cookie })`. Erwarteter Benutzer gemäß Zuordnung aus dem Fixture-README (Default `xwiki:XWiki.<username>`). Abweichung oder `null` → Fehlerseite 403, kein Code. Ohne Zustimmung `grants[sub|clientId]` → Zustimmungsseite (Task-eigenes HTML): angemeldeter Benutzer, `client_name` mit „(nicht geprüft)“, Ziel der Rückleitung (Origin bzw. „lokales Programm auf diesem Rechner“), Formular `POST /mcp/oauth/consent` mit CSRF-Token (an `pendingId` gebunden), Buttons „Zulassen“/„Abbrechen“. Mit Zustimmung direkt weiter.
  - Fertigstellen (gemeinsam für beide Wege): zuerst `store.mutate` mit einem `Cleanup`-Eintrag `reason: "pending-create"` und dem geplanten `appName`, dann `xwikiTokens.createToken(cookie)`, dann `createSession` (entfernt den pending-Eintrag im selben `mutate`), dann Code (5 min, im Speicher) mit `{ sid, clientId, redirectUri, codeChallenge, resource }`. Rückleitung per `new URL(redirectUri)` + `searchParams.set("code"|"state")`. Das Cookie wird nirgends gespeichert.
  - Alle Seiten dieses Ablaufs: `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.

- [ ] **Step 1: Tests** (Stubs für `authentik` und `xwikiTokens`):
  - `/authorize` mit unregistrierter `client_id` → 400; mit nicht passender `redirect_uri` → 400; mit `resource=https://other` → 400 `invalid_target`.
  - Callback ohne `xmcp_flow`-Cookie → 400.
  - Complete mit `whoami` = anderer Benutzer → 403, keine Sitzung im Store, `createToken` nicht aufgerufen.
  - Complete ohne Zustimmung → 200 HTML mit „nicht geprüft“ und CSRF-Feld; POST `/mcp/oauth/consent` ohne gültiges CSRF → 403.
  - Zustimmung erteilt → 302 auf `redirect_uri?code=…&state=…`; eine `redirect_uri` mit vorhandener Query (`?a=1`) behält `a=1`; Grant gespeichert; zweiter Login desselben Clients zeigt keine Zustimmungsseite.
  - `createToken` wirft `login_required` → Fehlerseite, kein Code, `Cleanup` mit `pending-create` bleibt **nicht** stehen (es wurde kein Token angelegt).
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen. `src/sse-handler.js`, `test/sse.test.js` und der `logout`-Handler entfallen hier.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(oauth): Login mit Flow-Cookie, Identitaetsabgleich und Zustimmung je Client`.

### Task 9: Token-Endpunkt mit Rotation

**Files:**
- Modify: `src/oauth.js` (Handler `token`)
- Modify: `src/sessions.js` (Teil 2)
- Test: `test/token.test.js`

**Interfaces:**
- Produces in `src/sessions.js`:
  - `issueTokens(deps, { sid, familyId, clientId }) -> Promise<TokenResponse>`: neues Refresh-Token, `families[familyId].currentHash` setzen, Access-Token signieren (Claims laut Global Constraints, `ver = session.tokenVersion`). `TokenResponse = { access_token, token_type: "Bearer", expires_in: 3600, refresh_token, scope: "xwiki" }`.
  - `refreshSession(deps, { refreshToken, clientId }) -> Promise<TokenResponse>`: unter `store.withLock(sid)`:
    1. Familie über Hash finden. Hash = `currentHash` → weiter. Hash = `replay.hash` und `now < replay.until` → gespeicherte Antwort zurück. Hash in `spentHashes` → `endSession(..., "refresh-reuse")`, `invalid_grant`. Unbekannt → `invalid_grant`.
    2. `clientId` ≠ Familie → `invalid_grant`.
    3. `now - lastClientRefreshAt > 30 d` → `endSession(..., "idle")`, `invalid_grant`.
    4. `authentik.refresh` → bei `AuthentikRejected` `endSession(..., "authentik-rejected")`, `invalid_grant`; bei `AuthentikUnavailable` 503 `temporarily_unavailable`, nichts ändern. Danach `authentik.checkUser`.
    5. Falls `tokenExpiresAt - now < 14 d`: `renewXWikiToken` (Task 10).
    6. In **einem** `mutate`: neues Authentik-Refresh speichern, alten Hash nach `spentHashes`, neues `currentHash`, `replay = { hash: alt, responseSealed, until: now + 30 s }`, `lastClientRefreshAt = now`. Erst danach die Antwort senden.
- `/token` (`/token`, `/mcp/oauth/token`): `authorization_code` prüft PKCE, `client_id`, exakte `redirect_uri`, `resource` (falls im Code), Code einmalig. `refresh_token` → `refreshSession`. Alle Antworten `Cache-Control: no-store`, `Pragma: no-cache`. Fehler als `{ error }` nach RFC 6749.

- [ ] **Step 1: Tests:**
  - Code-Tausch mit falscher `client_id` oder anderer `redirect_uri` → 400 `invalid_grant`.
  - Refresh liefert neues Paar; altes Refresh-Token innerhalb 30 s erneut → **dieselbe** Antwort; nach 31 s (`now` injiziert) → `invalid_grant` und Sitzung beendet.
  - Zwei gleichzeitige Refreshs mit demselben Token (`Promise.all`) → beide 200, gleiche Antwort, Sitzung lebt. **(Review Focus 1)**
  - Refresh mit Token einer anderen `client_id` → `invalid_grant`.
  - `authentik.refresh` wirft `AuthentikRejected` → `invalid_grant`, Sitzung weg, `Cleanup` mit `authentik-rejected` vorhanden.
  - `AuthentikUnavailable` → 503 `temporarily_unavailable`, Refresh-Token weiter gültig.
  - `store.mutate` wirft in Schritt 6 → 500, und ein danach neu geöffneter Store akzeptiert weiter das **alte** Refresh-Token. **(Review Focus 4)**
  - Antwort-Header `Cache-Control: no-store`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(oauth): Refresh-Tokens mit Rotation, Wiederholungsfenster und Wiederverwendungsschutz`.

### Task 10: Sitzungsende, Aufräumen, Erneuerung, täglicher Abgleich, Revoke

**Files:**
- Modify: `src/sessions.js` (Teil 3), `src/oauth.js` (Handler `revoke`), `server.js`
- Delete: `src/keepalive.js`, `test/keepalive.test.js`
- Test: `test/sessions.test.js`

**Interfaces:**
- Produces:
  - `endSession(deps, sid, reason) -> Promise<void>`: in einem `mutate` `Cleanup` (Token versiegelt, `consentId`, `xwikiUser`, `reason`) anlegen und Sitzung, Familie löschen. Danach einmal `runCleanups`.
  - `runCleanups(deps) -> Promise<void>`: je Eintrag `xwikiTokens.deleteToken({ bearer }, …)`; `"deleted"`/`"gone"` → Eintrag weg; Fehler → `attempts++`, `lastError`. Einträge älter als 7 Tage → `console.warn` mit `id`, `xwikiUser`, `reason` (ohne Token). Einträge `pending-create` → `findTokensByPrefix` mit dem geplanten Namen, Fund löschen.
  - `renewXWikiToken(deps, sid) -> Promise<void>`: neuen Token per Bearer anlegen (`createToken({ bearer: alt })`), im `mutate` Token, `consentId`, `tokenExpiresAt` ersetzen und `tokenVersion++`, alten als `Cleanup` mit `reason: "renewed"` eintragen. Scheitert das Anlegen → `console.warn`, Sitzung läuft mit dem alten Token weiter.
  - `dailyReconcile(deps) -> Promise<void>`: je Sitzung unter `withLock(sid)` `authentik.refresh` + `checkUser`. `AuthentikRejected` → `endSession(…, "authentik-rejected")`. Sitzungen mit `now - lastClientRefreshAt > 30 d` → `endSession(…, "idle")`. Ändert `lastClientRefreshAt` **nicht**. Danach `runCleanups`. Abgelaufene Upload-Nonces entfernen, Clients ohne Sitzung und `lastUsedAt` > 30 d entfernen.
  - `startBackground(deps)`: `dailyReconcile` alle 24 h (erster Lauf 5 min nach Start), `runCleanups` stündlich; Timer mit `unref()`.
  - `POST /oauth/revoke`, `/mcp/oauth/revoke`, `/revoke`: Form-Parameter `token`, optional `token_type_hint`. Refresh-Token einer Familie oder Access-Token einer Sitzung → `endSession(…, "revoked")`. Immer 200, auch bei unbekanntem Token.
- `server.js`: `loadConfig` → `validateConfig` → `openStore` (bei Fehler `process.exit(1)` mit Klartext) → `createApp` → `startBackground` → `listen`.

- [ ] **Step 1: Tests:**
  - `endSession` → Sitzung weg, `Cleanup` da; `runCleanups` mit `deleteToken` = `"gone"` → Eintrag weg; mit Fehler → `attempts = 1`, Eintrag bleibt.
  - `renewXWikiToken`: `tokenVersion` steigt um 1, alter Token als `renewed`-Cleanup.
  - `dailyReconcile` mit `AuthentikRejected` → Sitzung beendet; mit Erfolg → `lastClientRefreshAt` unverändert.
  - `pending-create`-Eintrag wird über `findTokensByPrefix` gefunden und gelöscht.
  - `/revoke` mit unbekanntem Token → 200; mit Refresh-Token → 200 und Sitzung weg.
  - `server.js`-Start mit kaputter Speicherdatei: `node server.js` mit Env auf eine Mülldatei → Exit-Code 1, Ausgabe enthält `STORE_FILE`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(sessions): Aufraeumen, Erneuerung, taeglicher Abgleich mit Authentik, Revoke`.

### Task 11: `/mcp`-Endpunkt: Token-Prüfung, Transport, Versionen

**Files:**
- Modify: `src/auth-middleware.js`, `src/app.js`, `src/mcp-handler.js`
- Test: `test/auth.test.js` (umschreiben), `test/mcp-transport.test.js` (neu)

**Interfaces:**
- `createAuthMiddleware(deps)`: `jwtVerify(token, secret, { algorithms: ["HS256"], issuer: base, audience: base })`; Sitzung muss existieren; setzt `req.mcpSession: SessionCtx` (XWiki-Token entsiegelt, `tokenVersion` aus der Sitzung). Fehler → `sendUnauthorized(res, cfg, { error: "invalid_token" })`.
- `POST /mcp`: `Origin` vorhanden und nicht erlaubt → 403. Header `MCP-Protocol-Version` vorhanden und nicht unterstützt → 400. `XWikiAuthError` aus einem Tool: wenn `req.mcpSession.tokenVersion` < aktueller `tokenVersion` der Sitzung → einmal mit dem aktuellen Token wiederholen; sonst `endSession(…, "xwiki-401")` und `sendUnauthorized`.
- `GET /mcp`, `DELETE /mcp` → 405 mit `Allow: POST`.
- `handleMcpRequest("initialize", { protocolVersion })` antwortet mit der angefragten Version, falls in der Liste, sonst `2025-06-18`.

- [ ] **Step 1: Tests:**
  - Token mit falschem `aud`, falschem `iss`, `alg: none` oder abgelaufen → 401, `WWW-Authenticate` mit `resource_metadata`.
  - `initialize` mit `2025-03-26` → Antwort `2025-03-26`; mit `1999-01-01` → `2025-06-18`.
  - Header `MCP-Protocol-Version: 1999-01-01` → 400.
  - `Origin: https://evil.example` → 403; ohne `Origin` → 200; `Origin: https://claude.ai` → 200.
  - `GET /mcp` → 405, `Allow: POST`.
  - Tool wirft `XWikiAuthError` bei aktueller Version → 401 und Sitzung beendet, `Cleanup` vorhanden, kein zweiter Aufruf. **(Review Focus 5)**
  - Tool wirft `XWikiAuthError` bei veralteter Version → genau ein Wiederholungsaufruf mit neuem Token, Antwort 200.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(mcp): Token-Pruefung mit iss/aud, Versionsaushandlung, 405, Origin-Pruefung`.

### Task 12: XWiki-Client auf Bearer, SSRF-Fix

**Files:**
- Modify: `src/xwiki-client.js`, `src/tools.js`
- Test: `test/xwiki-client.test.js`, `test/tools.test.js` (anpassen)

**Interfaces:**
- `cookieHeaders(sessionCtx)` wird `authHeaders(sessionCtx) -> { Authorization: "Bearer <xwikiToken>", Accept: "application/json" }`. Die Erkennung in `resolveGetPageArgs`/`resolveSearchArgs` prüft `"xwikiToken" in …` statt `"xwikiCookie"`. `touchSession` entfällt.
- `fetchFromSourceUrl(sourceUrl)`: höchstens 5 Weiterleitungen, jede mit `redirect: "manual"` geholt und jedes Ziel neu geprüft (Schema, Host, IP). Die Verbindung nutzt eine `lookup`-Funktion, die die aufgelöste Adresse beim Verbindungsaufbau prüft (über `node:https`/`node:http` `request` mit Option `lookup`), damit Prüfung und Verbindung dieselbe IP sehen. Größenlimit und Timeout bleiben.

- [ ] **Step 1: Tests:**
  - Jeder REST-Aufruf schickt `Authorization: Bearer tok`, keinen `Cookie`-Header.
  - `source_url` → 302 auf `http://127.0.0.1/…` → Fehler „disallowed internal/private address“.
  - Hostname, der bei der Verbindung auf `10.0.0.1` auflöst (injizierte `lookup`) → Fehler.
  - Sechs Weiterleitungen in Folge → Fehler „too many redirects“.
  - Bestehende Tests für Suche, Seiten, Überschriften, Anhänge laufen mit `xwikiToken` statt `xwikiCookie`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen.
- [ ] **Step 4:** `npm test` → alle PASS.
- [ ] **Step 5:** Commit `fix(xwiki): Bearer statt Cookie; source_url prueft jede Weiterleitung und die verbundene IP`.

### Task 13: Upload-Route

**Files:**
- Modify: `src/upload-route.js`, `src/store.js` (nur Nutzung von `uploadNonces`)
- Test: `test/upload-route.test.js`

**Interfaces:**
- Ablauf: Token prüfen → in **einem** `mutate` Nonce reservieren (vorhanden → 409, sonst `uploadNonces[nonce] = exp`) → Sitzung prüfen → Body lesen → `putAttachmentBytes(…, sessionCtx)` mit dem Bearer der Sitzung. Bei Fehler nach der Reservierung bleibt die Nonce verbraucht (Einmal-URL).

- [ ] **Step 1: Tests:**
  - Zwei parallele PUTs mit derselben URL → genau einer 201, der andere 409.
  - Neuer Store auf derselben Datei (Neustart) → erneuter PUT mit derselben URL → 409.
  - Aufruf an XWiki trägt `Authorization: Bearer`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Umsetzen.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `fix(upload): Nonce atomar und dauerhaft, Bearer statt Cookie`.

### Task 14: Durchgehender Test und Deploy-Dateien

**Files:**
- Create: `test/e2e.test.js`, `test/helpers/fake-xwiki.js`, `test/helpers/fake-authentik.js`
- Modify: `docker-compose.yml`, `README.md`, `AGENTS.md` (falls dort Auth beschrieben ist)

**Interfaces:**
- `fakeXWiki()`: Express-App mit `/rest/` (`XWiki-User` aus Cookie oder Bearer), Profilseite „Anwendungen“ nach Fixture-Aufbau, Suche/Seiten-Endpunkten; `restart()` macht alle Cookies ungültig, Bearer-Tokens bleiben.
- `fakeAuthentik()`: Token-, JWKS-, Userinfo-Endpunkt; `deactivate(user)`, `removeFromGroups(user)`.

- [ ] **Step 1: Test** `full flow survives xwiki restart`: register → authorize → callback → complete → Zustimmung → token → `tools/call search_xwiki` → `fakeXWiki.restart()` → `tools/call` weiter 200 **(Review Focus 3)** → Refresh → neues Paar → `fakeAuthentik.removeFromGroups` → Refresh → `invalid_grant`, Consent in `fakeXWiki` gelöscht.
- [ ] **Step 2: Test** `revoke deletes xwiki token`: Login → `/revoke` → Consent in `fakeXWiki` weg.
- [ ] **Step 3:** `npm test` → alle PASS.
- [ ] **Step 4:** `docker-compose.yml`: `SESSION_FILE` → `STORE_FILE=/data/store.json`; neu `TOKEN_ENC_KEY=${TOKEN_ENC_KEY}`, `ALLOWED_GROUPS=${ALLOWED_GROUPS:-AdminsIT,xwiki_redaktion}`, `AUTHENTIK_APP_SLUG=${AUTHENTIK_APP_SLUG:-xwiki-mcp}`, `EXTRA_REDIRECT_URIS=${EXTRA_REDIRECT_URIS:-}`, `EXTRA_ORIGINS=${EXTRA_ORIGINS:-}`. Kein `env_file`. README: Env-Tabelle, Hinweis „Speicherdatei ohne Schlüssel unbrauchbar, Schlüssel im Passwortspeicher sichern“, Verbinden je Client (URL genügt).
- [ ] **Step 5:** `docker build -t xwiki-mcp-test .` → erfolgreich; `docker run --rm -e …(gültige Testwerte) xwiki-mcp-test` startet und loggt `MCP XWiki on http://0.0.0.0:3000`; ohne `TOKEN_ENC_KEY` → Exit 1.
- [ ] **Step 6:** Commit `test: durchgehender Ablauf mit XWiki-Neustart; Compose und README fuer neue Env`.

### Task 15: Review und PR

- [ ] **Step 1:** `npm test` → alle PASS; `grep -rn "xwikiCookie\|dev-insecure\|keepalive\|/sse" src test` → leer.
- [ ] **Step 2:** Codex-Review des Diffs `hosted...feat/global-oauth` über den Agenten `codex-reviewer`. Ergebnis als `~/projects/_operations/docs/superpowers/reviews/2026-11-XX-xwiki-mcp-global-oauth-code.md` ablegen (Format laut globaler CLAUDE.md). Befunde beheben oder begründet zurückweisen.
- [ ] **Step 3:** `git push -u origin feat/global-oauth`, PR gegen `hosted` mit `gh pr create --base hosted`. **Nicht mergen.** Der Merge ist der Deploy-Auslöser und gehört zu Phase 4 des Betriebsplans.
