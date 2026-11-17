# XWiki 18.7.0 – Consent-Tokens (Vortest 17.11.2026)

Ermittelt gegen `https://xwiki.wus-technik.com` im angemeldeten Browser (Phase 0 des
Betriebsplans `_operations/docs/superpowers/plans/2026-11-17-xwiki-mcp-global-oauth-betrieb.md`).
Kein Token, kein Cookie und kein `form_token` steht in diesen Dateien.

## Dateien

| Datei | Inhalt |
|---|---|
| `created.html` | Antwort auf das Anlegen von `mcp-vortest-2` (POST mit Bearer, ohne Cookie) |
| `list.html` | Anwendungsliste nach dem Aufräumen (kein `mcp-vortest-*` mehr) |

Beide sind **nur der Ausschnitt** `div#userapplicationsPane.user-page-pane` der Seite, nicht die
ganze Seite (~168 KB). Der Parser muss also im Teilbaum suchen und darf sich nicht auf `<html>`,
`<head>` oder die Seitennavigation verlassen.

Schwärzung:

- Zufallsteil des Tokens → `REDACTED-RANDOM` (echt: 43 Zeichen `[A-Za-z0-9_-]`)
- jeder `form_token` → `REDACTED-FORM-TOKEN` (echt: sitzungsgebunden, Base64-artig)

## URL und Formulare

- Seite: `GET /bin/view/XWiki/<name>?category=userapplications` (`<name>` = Seitenname des
  Benutzers, z. B. `foellmann`).
- Alle Formulare haben **kein `action`** → POST an dieselbe URL,
  `application/x-www-form-urlencoded`. Antwort: **200 mit der Seite**, kein Redirect.
- **Anlegen** (Formular mit Button `oidc_consent_create`):
  `form_token`, `application_name`, `expiration` = `7|30|60|90|date|never` (Vorauswahl 30),
  `expiration_date` (nur bei `date`, Format `YYYY-MM-DD`), `oidc_consent_create=` (leer).
- **Löschen** (ein Formular je Eintrag, Button `oidc_consent_delete`):
  `form_token`, `consent_id`, `oidc_consent_delete=` (leer).
- `form_token` steht in jedem Formular; derselbe Wert gilt für alle Formulare einer Seite.

## Token und Consent-ID

- Neu angelegter Token: in `created.html` im Erfolgskasten
  `div.box.successmessage` → `div.box-title` = Anwendungsname, darunter
  `div.code` = `Bearer <xwiki-user>/<index>/<random>`.
  Der Token ist alles nach `Bearer ` (also `xwiki:XWiki.foellmann/6/…`).
  Er erscheint nur in dieser einen Antwort.
- `consent_id` = `<xwiki-user>^XWiki.OIDC.ConsentClass[<index>]`, z. B.
  `xwiki:XWiki.foellmann^XWiki.OIDC.ConsentClass[6]`. `<index>` ist derselbe wie das mittlere
  Segment des Tokens. Gelöschte Indizes werden nicht neu vergeben (nach dem Löschen von 5 und 6
  bleiben 0–4).
- Listeneintrag: `div.box` → `div.pull-left > strong` = Anwendungsname,
  `span.date.xHint` = `Der Token läuft am DD.MM.YYYY ab.` bzw. `Der Token ist abgelaufen!`
  (Seite ist deutsch lokalisiert), daneben das Löschformular mit `consent_id`.
- Anwendungsnamen sind **nicht eindeutig** – XWiki prüft das nicht. Beim Zuordnen über den Namen
  den Eintrag mit dem passenden Index nehmen (Index aus dem Token).

## Ergebnisse

| Schritt | Ergebnis |
|---|---|
| 0.3 Anlegen per Cookie, `GET /rest/` mit Bearer | 200, `XWiki-User: xwiki:XWiki.foellmann` |
| 0.4 Anlegen **nur mit Bearer** (`credentials: omit`) | **ja** – GET der Seite 200 mit Formular, POST 200 mit neuem Token |
| 0.5 Löschen per Bearer (fremder und eigener Token) | ja, beide verschwinden aus der Liste |
| Nach dem Löschen: `GET /rest/` mit dem Token | **200, aber ohne `XWiki-User`-Header** (anonym), nicht 401 |
| Nach dem Löschen: geschützte Ressource (`/rest/wikis/xwiki/spaces/XWiki/pages/foellmann`) | 401 |

**Folge für `whoami`:** Ein ungültiger oder widerrufener Bearer fällt in XWiki auf **Gast** zurück.
`GET /rest/` liefert dann 200 ohne `XWiki-User`. Gültigkeit also am Header erkennen
(fehlt → ungültig), nicht am Status. Ein zufällig erfundener Token verhält sich gleich.

## Zuordnung Authentik → XWiki-Benutzer

- XWiki-Benutzer entstehen über den OIDC-Login der Application `xwiki` (Provider 88).
- Seitenname = `preferred_username` **ohne Punkte**, klein geschrieben:
  `foellmann` → `xwiki:XWiki.foellmann`, `zurman.o` → `xwiki:XWiki.zurmano`
  (`XWiki.zurman.o` und `XWiki.zurman` existieren nicht). Kein Benutzer im Wiki hat einen Punkt
  im Seitennamen.
- Jeder dieser Benutzer trägt ein Objekt `XWiki.OIDC.UserClass` mit
  `issuer = https://sso.wus-technik.com/application/o/xwiki/` und `subject` = 64 Hex-Zeichen.
- Provider 88 (`xwiki`) und 112 (`xwiki-mcp`) stehen beide auf `sub_mode = hashed_user_id`.
  Das `sub` aus dem MCP-Login ist also dasselbe wie `subject` im XWiki-Profil.
- Regel: XWiki-Benutzer aus `preferred_username` ableiten (Punkte entfernen, klein), danach
  `whoami` mit dem neuen Token muss genau diesen Benutzer liefern (sonst Abbruch). Optional
  zusätzlich: `subject` aus `GET /rest/wikis/xwiki/spaces/XWiki/pages/<name>/objects/XWiki.OIDC.UserClass/0`
  mit dem `sub` vergleichen (per Cookie als Benutzer selbst lesbar; mit Bearer nicht getestet).
- Weitere Zeichen, die XWikis Formatter (`_clean`) entfernt (Leerzeichen, `@` usw.), wurden nicht
  getestet. Im Bestand kommt nur der Punkt vor.
