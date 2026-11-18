# Review: Versionsprüfung, ChatGPT-Kompatibilität und Pfad-Härtung (Branch `fix/mcp-protocol-version`)

## Umfang

- Anlass: Der claude.ai-Connector scheiterte in Produktion mit 400 `unsupported_protocol_version`. claude.ai schickt beim ersten,
  unangemeldeten `POST /mcp` den Header `MCP-Protocol-Version: 2025-11-25`. Die Versionsprüfung lief vor der Anmeldung, deshalb sah
  der Client nie die 401 mit `resource_metadata` und fand den Login nicht.
- Zusätzlich geprüft: Anforderungen von ChatGPT-Connectoren laut OpenAI-Apps-SDK-Doku (https://developers.openai.com/apps-sdk/build/auth)
  und MCP-Spezifikation 2025-11-25.
- Commits auf `hosted` (b6c5a07): 7cb4773, 8938a25, fa88060, 604b290 und ein Einzeiler für die Upload-Route.

## Modell und Aufruf

- 7cb4773: `codex exec --sandbox read-only --model gpt-6.1-terra` (codex-cli 0.169.0), Prompt über stdin.
- 8938a25 + fa88060 und 604b290: `codex exec --sandbox read-only --model gpt-6.1-sol -c model_reasoning_effort=high`; Codex hat eigene
  HTTP-Proben gegen die App und die volle Testsuite gefahren.

## Befunde

| Commit | Schwere | Ort | Befund | Urteil | Maßnahme |
|---|---|---|---|---|---|
| Produktion | Critical | `src/app.js` transportGuard | Versionsprüfung vor der Anmeldung verhindert Discovery (claude.ai) | gültig | Prüfung hinter die Anmeldung; `initialize` nie wegen des Headers abgelehnt; 2025-11-25 ergänzt (7cb4773) |
| Produktion | High | `src/redirects.js` | neue ChatGPT-Connectoren nutzen `https://chatgpt.com/connector/oauth/{id}`, nicht erlaubt | gültig (Doku) | Muster zugelassen (8938a25) |
| Produktion | High | `src/oauth.js`, `src/metadata.js` | kein `iss` nach RFC 9207 in der Autorisierungsantwort | gültig (Doku) | `iss` in jeder Rückleitung, Metadaten-Flag (8938a25) |
| Produktion | Minor | `src/metadata.js` | `scope` fehlt in der 401-Challenge | gültig (Spec SHOULD) | ergänzt (8938a25) |
| 7cb4773 | Important | `src/app.js` | kaputter Body ohne Token → 400 statt 401 | gültig, vorbestehend | Anmeldung vor dem Parser (fa88060) |
| 7cb4773 | Important | `src/app.js` | Origin-Prüfung nur für POST | gültig, vorbestehend | alle Methoden (fa88060) |
| 7cb4773 | Minor | `src/app.js` | Versions-Header ungefiltert im Debug-Log | gültig | nur versionsartige Werte (fa88060) |
| fa88060 | Important | `src/app.js` | `/mcp//` umgeht die Origin-Prüfung; `/MCP` wird vor der Anmeldung geparst | gültig | nicht-kanonische `/mcp`-Pfade → 404 (604b290) |
| fa88060 | Minor | `src/redirects.js` | reservierte Parameter (`iss`, `code`, …) in registrierter Redirect-URI | gültig | bei Registrierung und Autorisierung abgewiesen (604b290) |
| 604b290 | Low | `src/app.js` | Upload-URL in Großschreibung: Body vom JSON-Parser verbraucht, Upload hängt | gültig, vorbestehend | Ausnahme ohne Groß-/Kleinschreibung (Einzeiler) |

Abschlussurteil des Re-Reviews von 604b290: APPROVE, bereit für Produktion.

## Nicht übernommen / Backlog

- Tool-Eingaben werden nicht gegen `inputSchema` validiert (Spec-MUST seit 2025-06-18, vorbestehend; Fehler landen heute als
  Text-Antwort des Tools).
- JSON-RPC-Antworten (mit `id`, ohne `method`) werden wie Anfragen behandelt (vorbestehend, praktisch irrelevant, da der Server keine
  Anfragen an Clients schickt).
- Fehlerbehandlung für Parserfehler vergleicht exakte Pfade (`/mcp/oauth/token/` bekommt kein `no-store` im Fehlerfall; kosmetisch).
- Die Route `/oauth/revoke` (Root) wird von der dokumentierten HAProxy-Regel nicht weitergeleitet; beworben wird `/mcp/oauth/revoke`.
- CIMD (Client-ID-Metadatendokumente) nicht unterstützt; ChatGPT fällt dann auf DCR zurück, das unterstützt wird.
