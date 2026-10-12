# Security notes

Scope: a **personal** analyst dashboard. (Where this document says "a test checks…", it refers to the automated tests this package was built and verified with; they are not included in the download.) Goals: opening it, installing it and feeding it hostile data can't hurt you, and nothing leaves your browser except
the requests you trigger.

## What the code defends against
| Risk | Defence |
|---|---|
| Script injection from feed text (CVE descriptions, headlines, ATT&CK text) | Every element is built with `createElement` + `textContent`, never from HTML strings. The element builder refuses `script/iframe/img/svg/style…` tags and `on*`/`style`/`src` attributes; links must be `http(s)`. The build-time tests checked that `innerHTML`, `eval`, inline handlers etc. do not appear. If you edit the code, keep it that way (see "Rules for future edits"). |
| Injection even if the above slipped | Strict Content-Security-Policy: `script-src 'self'`, `object-src 'none'`, `frame-src 'none'`, `form-action 'none'`, `base-uri 'self'`, and `connect-src` limited to `'self'` + five named hosts (identical to the allow-list in `js/net.js`; keep them in sync). |
| Talking to the wrong place | `fetchLimited` only accepts HTTPS URLs on the allow-list (no ports, no credentials in URLs); requests carry no cookies (`credentials: omit`) and no referrer. |
| Oversized / endless responses | Size is capped **while streaming** (8 MB default, 40 MB for NVD pages, 250 MB for the ATT&CK file), plus a time limit and cancel button. |
| Corrupt or tampered stored data | Everything read back from browser storage is validated and coerced (types, lengths, ID formats, URL schemes) before any page sees it. |
| Hostile text in the ATT&CK file | Parsed in a Web Worker; control/bidi characters stripped; regexes are bounded so 50,000 `[` characters can't stall it; output is validated (ID shapes, URLs, sanity thresholds) before it is stored. |
| Link spoofing (bidi / zero-width characters, `user@host` URLs, `javascript:` / `data:` URLs) | Stripped or rejected when records are built and again when they are loaded. |
| Prototype tricks (`{{constructor}}`, `__proto__` keys, `#/constructor`) | Null-prototype maps, `Object.hasOwn` routing and template filling, ID-shaped keys only. |
| Browser freeze on pasted text | Bounded regexes and input size caps. |
| Clickjacking | The app refuses to run inside a frame. |
| API-key leakage | No API keys are used or stored anywhere. |
| Third-party code | None: no npm packages, CDN scripts, fonts or analytics. |
| Service worker | Handles only same-origin GETs for the app's own files; never touches fetched data; cache is versioned by `BUILD` and installed bypassing the HTTP cache. |

## What code can't fix
* **The site is public** (free-plan GitHub Pages). It contains only generic content; keep anything internal out of the repository and out of templates.
* **`<username>.github.io` is one shared origin** for all your Pages sites, so browser storage (watchlist, templates, fetched data) is visible to any other page you host under that account. Don't host untrusted pages there, or use a separate account / custom domain.
* **Pages can't send security headers.** The CSP is a `<meta>` tag (it can't enforce `frame-ancestors`; the in-app frame guard covers that).
* **Lookups reveal what you look up** to the service you ask (NVD, CIRCL, FIRST) – your IP address and the CVE IDs. The reputation links (VirusTotal etc.) send the indicator to that site only when you select them.
* **Data you fetch is only as trustworthy as its source.** It is displayed as text and cannot run, but a wrong CVSS score is still wrong.

## Hardening checklist for your GitHub account (5 minutes)
1. Turn on two-factor authentication (passkey or authenticator app).
2. Enable **Secret scanning** and **Push protection** (Settings → Code security; free on public repos).
3. Optionally add a branch ruleset for `main` that blocks force-pushes and deletion.
4. Keep the repo free of private notes; review commits you didn't make.

## Rules for future edits
Build DOM with `h()` and `textContent`; no inline scripts or handlers; no new hosts without adding them to both `js/net.js` and the CSP; add every new file to `SHELL_FILES` in `sw.js` and bump `BUILD`.
