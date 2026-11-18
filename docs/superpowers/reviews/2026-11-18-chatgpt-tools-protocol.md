# Review: ChatGPT-Tool-Antworten, Protokoll 2026-07-28, Suche, Überschriften (Branch `fix/chatgpt-tools-protocol`)

## Umfang

- Anlass (Pilot in Produktion, `hosted` 4a71e87):
  - ChatGPT zeigt `get_xwiki_page` als `{}`, sobald Seiteninhalt zurückkommt.
  - claude.ai und `openai-mcp/1.0.0` senden `MCP-Protocol-Version: 2026-07-28` und bekommen auf Folgeanfragen 400.
  - Kleinere Befunde: Die Suche findet keine Seitennamen und Titel, `#`-Kommentare in Codeblöcken werden als Überschriften gewertet,
    und Refresh-Ereignisse fehlen im Log.
- Ursache für `{}` laut Community-Bericht mit Antwort des OpenAI-Supports
  (https://community.openai.com/t/chatgpt-mcp-file-reads-return-empty-objects-across-gitea-and-nextcloud-integrations/1406893):
  ein Schlüssel namens `content` im JSON der Tool-Antwort. Gegen einen echten ChatGPT-Connector ist das noch nicht geprüft.
- Commits auf 4a71e87:
  - 4f981e0: `structuredContent`, `outputSchema`, `annotations`, `isError`, `content` → `page_content`
  - b94e52d: Log-Ereignisse `tool_call`, `token_refreshed`, `refresh_rejected`
  - 420412d und 274bf09: Protokollversion
  - 304dca3: Suche über Name, Titel und Inhalt
  - 47f8cd1, d5f5f3a und c33ad08: Überschriften in Codeblöcken

## Modell und Aufruf

`codex exec --sandbox read-only --model gpt-6.1-sol -c model_reasoning_effort=high` (codex-cli 0.169.0), Prompt über stdin.
Das Review lief in drei Runden: Branch-Review, Re-Review der Fix-Runde und ein Vergleich gegen Produktion mit 89 Prüfseiten in drei
Syntaxen.

## Befunde

| Runde | Schwere | Ort | Befund | Urteil | Maßnahme |
|---|---|---|---|---|---|
| 1 | Important | `src/xwiki-client.js` codeLineMask | selbstschließendes `{{code …/}}` versteckt alle folgenden Überschriften | gültig | d5f5f3a |
| 1 | Important | `src/xwiki-client.js` | ```` ```x``` ```` als offener Fence gewertet | gültig | d5f5f3a |
| 1 | Minor | `src/xwiki-client.js` | Markdown-Fences auch auf xwiki/2.1-Seiten | gültig | Syntax berücksichtigt (d5f5f3a) |
| 1 | Minor | `src/mcp-handler.js` | jede spätere Datumsangabe akzeptiert (auch 2026-13-45, 2099-01-01) | gültig | echtes Datum, höchstens 2 Jahre voraus (274bf09) |
| 1 | Minor | `src/tools.js` | unbekanntes Tool als `isError` statt JSON-RPC -32602 | gültig | 274bf09 |
| 2 | Medium | `src/xwiki-client.js` | Inline-Code in Überschrift, escaptes `~{{code}}`, `}` in Parametern: Regressionen | gültig | nur Blockform ausblenden (c33ad08) |
| 3 | Low | `src/xwiki-client.js:316` | `~~~`-Fence bei gemischten Zeilenenden (CRLF/LF) | gültig, Randfall | Backlog |
| 3 | Low | `src/xwiki-client.js:306` | Fence-Ende akzeptiert NBSP/`\v`/`\f` | gültig, Randfall | Backlog |
| 3 | Low | `src/xwiki-client.js:293` | Makro-Parameter: einfache Anführungszeichen und `~`-Escape nicht berücksichtigt | gültig, wie Produktion | Backlog |
| 3 | Low | `src/xwiki-client.js:304-308` | ungeschlossener Fence in Listeneintrag läuft bis Seitenende | nach den Regeln zulässig | Backlog |

Ohne Befund: `structuredContent` passt in allen 13 Varianten zum `outputSchema` (geprüft mit AJV). Die Logs enthalten keine
Argumentwerte, Inhalte oder Tokens. Bei der Suche ist `scope` wiederholt richtig, und `number` ist eine Gesamtgrenze. Gegenüber
Produktion ändert sich der Text-Block nur durch `content` → `page_content`.

Abschlussurteil: bereit für Produktion.

## Backlog

- Die vier Low-Punkte oben.
- Bereits in Produktion (nicht neu): Markdown-Überschriften in CRLF-Inhalten werden nicht erkannt (`parseHeadingLine`).
- Ob ChatGPT nach dem Fix den Inhalt zeigt, muss gegen den echten Connector geprüft werden. Danach den Connector neu laden oder neu
  anlegen, damit die neue Tool-Liste übernommen wird.
