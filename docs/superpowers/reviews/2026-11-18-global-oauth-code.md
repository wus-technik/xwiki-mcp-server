# Review: OAuth für alle Zugangswege (Code, Branch `feat/global-oauth`)

## Umfang

- Plan: `docs/superpowers/plans/2026-11-17-global-oauth.md`, Tasks 1–14, plus Abschluss-Review (Task 15).
- Diff: `hosted` (a7eb1d9) … `feat/global-oauth`.
- Vorgehen: je Task ein unabhängiges Codex-Review des Task-Diffs (Brief, Implementierer-Bericht, Diff), danach Fix-Runden mit
  erneutem Codex-Review des Fix-Diffs; kleine Fix-Runden (Test-Einzeiler, eindeutige Korrekturen) wurden vom Controller geprüft und im
  Abschluss-Review von Codex erneut gesehen. Zum Schluss ein Review des ganzen Branches.

## Modell und Aufruf

- Task-Reviews: `codex exec --sandbox read-only --model gpt-6.1-terra` (codex-cli 0.169.0), Prompt über stdin.
- Abschluss-Review: `codex exec --sandbox read-only --model gpt-6.1-sol -c model_reasoning_effort=high` über alle Dateien in `src/`,
  `server.js`, Compose, Dockerfile, README, AGENTS.md, die relevanten Tests und jeden nur vom Controller geprüften Fix-Commit.

## Befunde je Task

Schwere nach Codex; „Urteil“ = Entscheidung nach Prüfung; „Maßnahme“ = was geschah.

| Task | Schwere | Ort | Befund | Urteil | Maßnahme |
|---|---|---|---|---|---|
| 1 Config | Important | `src/config.js` | `TOKEN_ENC_KEY` lax als base64 dekodiert | gültig | strikte Prüfung + Tests (2178a20) |
| 1 | Important | `src/config.js` | `SESSION_SECRET` nur aus Leerzeichen akzeptiert | gültig | abgewiesen (2178a20) |
| 1 | Minor | `src/config.js` | Leerzeichen-`STORE_FILE`, `NODE_ENV` ungetrimmt (TLS-Schutz umgehbar) | gültig | getrimmt (2178a20, c02fac9) |
| 1 | Important | `docker-compose.yml` | `TOKEN_ENC_KEY` fehlt | gültig, Task 14 | in 178ea49 ergänzt |
| 2 Krypto | Important | `src/crypto-box.js` | `open` akzeptiert nicht-kanonisches base64url | gültig | strikte Dekodierung + Tests (565cddf) |
| 3 Store | Important | `src/store.js` | kurzer Schreibvorgang als Erfolg gewertet | gültig | Schreibschleife (e5ec699) |
| 3 | Important | `src/store.js` | Zustand per Referenz veränderbar | gültig | Zustand aus geschriebenem JSON (8ce2593) |
| 3 | Important | `src/store.js` | kein fsync des Verzeichnisses nach rename | gültig | fsync, Fehler danach nur Warnung (e5ec699) |
| 3 | Minor | `src/store.js` | tmp nicht exklusiv, Ladeprüfung zu schwach, Testlücken | gültig | `wx`, Typprüfung, Tests (e5ec699, f7f7082, 76b1f9f) |
| 3 | — | `src/store.js` | rename unter Windows sporadisch EPERM | gültig | begrenzte Wiederholung nur win32 (ef149b2) |
| 4 DCR | Important | `src/redirects.js` | leere Userinfo, Loopback-Vergleich zu locker | gültig | Rohvergleich außer Port (5b955e5) |
| 4 | Important | `src/oauth.js`, `src/app.js` | falscher Fehlercode, HTML-400 bei kaputtem JSON | gültig | `invalid_redirect_uri`, JSON-Fehler (5b955e5, deba505) |
| 4 | Important | `server.js` | alter Session-Store schreibt in dieselbe `STORE_FILE` | gültig | alter Store nur im Speicher (5b955e5) |
| 5 Metadaten | Minor | `src/metadata.js` | `error` im Header nicht bereinigt; kein Integrationstest | gültig | in Task 11 erledigt |
| 6 Authentik | Important | `src/authentik.js` | Lese-/Parsefehler, 403/429/3xx als „abgelehnt“ (würde Sitzungen beenden) | gültig | nur 400/401 bzw. 401 = abgelehnt (7fcb994) |
| 6 | Important | `src/authentik.js` | `exp` nicht Pflicht, JWKS-Ausfall als ungültiges Token, Redirects gefolgt | gültig | `requiredClaims`, `redirect: manual`, RS256 (7fcb994, 6e21f51) |
| 7 XWiki-Tokens | High | `src/xwiki-tokens.js` | `whoami` ignoriert Status → 5xx als „gelöscht“ | gültig | nur 200 ohne Header = null (952587f) |
| 7 | High | `src/xwiki-tokens.js` | Aufräumen nach Identitätsfehler ohne Fallback; Fehler nach dem Anlegen ohne Aufräumen | gültig | jeder Fehler nach dem Anlegen räumt auf (952587f, 8c2501d, c62d5ef) |
| 7 | Medium/Low | `src/xwiki-tokens.js` | Parser schloss offen, Entities, fremder Bearer als „gone“ | gültig | Zählprüfung, Dekodierung, Besitzprüfung (952587f) |
| 7 | — | `src/xwiki-tokens.js` | 90 Tage/Namensformat im Modul erzwingen | verworfen | Aufrufer liefern die Werte |
| 8 Login | Important | `src/oauth.js` | parallele Abschlüsse erzeugen doppelte Sitzungen | gültig | atomare Übernahme (d238f66) |
| 8 | Minor | `src/oauth.js`, `src/app.js` | Parserfehler ohne Fehlerseite, abgelaufene Einträge im Speicher | gültig | Fehlerseite, Sweep (d238f66) |
| 8 | — | `src/oauth.js` | `resource` mit Schrägstrich am Ende | bewusst toleriert | Kommentar + Test |
| 9 Rotation | Important | `src/sessions.js` | zweite Rotation schließt Wiederholungsfenster des ersten Tokens | Planvorgabe (ein Slot) | dokumentiert + Test (7af1a00) |
| 9 | Important | `src/sessions.js` | `client_id` beim Refresh optional | bewusst (RFC 6749 §6) | Kommentar + Test |
| 9 | Minor | `src/oauth.js` | PKCE-Verifier-Format ungeprüft | gültig | Prüfung (7af1a00) |
| 10 Lebenszyklus | Important | `src/xwiki-tokens.js` | keine Zeitgrenze → 10-Minuten-Schutz nicht wirksam | gültig | 60 s Timeout (5841323) |
| 10 | Minor | `src/sessions.js`, `src/oauth.js` | Warnungen ungedrosselt; Revoke bei Schreibfehler | gültig / bewusst | Drossel; 503 statt 200 (RFC 7009 §2.2.1) |
| 11 /mcp | Important | `src/xwiki-client.js` | echte XWiki-Aufrufe noch per Cookie | gültig, Task 12 | in acebff0 behoben |
| 11 | Important | `src/app.js`, `src/mcp-handler.js` | Parser vor Origin-Prüfung, Notifications/Batches falsch | gültig | Reihenfolge, 202, -32600 (717f460) |
| 11 | Important | `src/auth-debug.js` | Query-String im Debug-Log | gültig | nur Pfad (717f460) |
| 12 SSRF | Important | `src/xwiki-client.js` | gemappte IPv6 nur über eingebettete IPv4 geprüft | gültig (wörtlich) | ganzer Bereich gesperrt (5563295) |
| 12 | Minor | `src/xwiki-client.js` | Userinfo wird zu Basic-Auth; XWiki-Ausnahme gilt für alle Ports | gültig | abgewiesen, Port gebunden (5563295) |
| 13 Upload | Important | `src/upload-route.js` | 502/413 geben Fehlertext weiter (möglicher Token) | gültig | feste Texte (878258c) |
| 13 | Important | `src/app.js` | Body-Parser vor der Upload-Route | gültig | Parser übersprungen (878258c) |
| 13 | Minor | `src/upload-token.js` | Wiederverwendung genau bei `exp` | gültig | `>=` (878258c) |
| 14 Doku | Important | `README.md` | Env-Beispiel unbrauchbar, Refresh-Speicherung falsch beschrieben | gültig | `.env`-Block, Text korrigiert (81295ec) |

## Abschluss-Review des Branches

| Schwere | Ort | Befund | Urteil | Maßnahme |
|---|---|---|---|---|
| Important | `src/sessions.js` (`refreshSession`) | rotiertes Authentik-Refresh-Token geht verloren, wenn `checkUser` danach 503 liefert | gültig | wird vor `checkUser` gesichert (73a06ca) |
| Minor | `test/login-flow.test.js` | CSRF-Test verändert das Token in 1/64 der Läufe nicht (Flake) | gültig | korrigiert |
| Minor | `docker-compose.yml` | `AUTH_DEBUG` wird nicht durchgereicht | gültig | ergänzt |
| Minor | `README.md` | Beispiele ohne `id` werden als Notification behandelt | gültig | ergänzt |

Codex fand keine Deadlocks, keine Abweichungen bei Sperr-Schlüsseln, SessionCtx oder AAD, keine Geheimnisse in Logs und keine Reste
des alten Designs. Review-Schwerpunkte 1, 2, 3 und 5 gelten durchgehend; Schwerpunkt 4 nach dem Fix oben.

Re-Review des Fix-Commits 73a06ca (gpt-6.1-sol, high): alle vier Befunde behoben, keine neuen Fehler, Urteil APPROVE.
Codex prüfte dabei zusätzlich parallele Wiederholungen zwischen den beiden Schreibvorgängen, Ablehnung nach dem ersten Schreiben und
beide Reihenfolgen von täglichem Abgleich und Refresh.

Akzeptierte Restpunkte (bewusst nicht geändert): leerer JWT-Schlüssel nur ohne `validateConfig` (Server prüft vorher); JSON-Rundreise
verliert `Date`/`undefined` (gewollt); Pfadvergleich für Fehlerseiten exakt; Sweep-Intervall je `createApp` nicht gestoppt (unref);
gefälschter Bearer mit öffentlichem Benutzer/Index → „gone“ (Aufrufer nutzen eigenes Token); Anlege-Antwort ohne Seitenbereich →
kein Aufräumen (Token nicht lesbar, Wiederfindung über `pending-create`).

## Bekannte Grenzen

- Schlägt das Sichern des neuen Authentik-Refresh-Tokens fehl, nachdem Authentik rotiert hat, beendet der nächste Refresh die Sitzung
  (erneuter Login nötig). Client und Server bleiben sich über das MCP-Refresh-Token einig.
- Die README-Schritte für die Connector-Menüs von claude.ai/ChatGPT und die genaue `codex mcp add`-Syntax sind nicht gegen die
  jeweiligen Clients geprüft.
