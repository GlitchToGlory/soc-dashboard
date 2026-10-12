# SOC Analyst Dashboard – static PWA (no Python, no server, nothing scheduled)

Everything runs in your browser. You host a folder of static files (free, on GitHub Pages) and install it from **Microsoft Edge** as an app.
Nothing is fetched until **you** press a button, so there is no background job, no schedule and nothing running on your laptop.

## Pages
| Page | What it does |
|---|---|
| **Overview** | One-click *Fetch KEV + latest CVEs*, risk-ranked CVEs (KEV → EPSS → CVSS), latest KEV additions, headlines, your vendor/product watchlist |
| **CVEs** | Live fetch of newly published CVEs from NVD (last 1–30 days) with EPSS scores; filters, KEV flag, *Draft brief* |
| **KEV** | Live fetch of the CISA Known Exploited Vulnerabilities catalogue; search, ransomware filter |
| **News** | Live security headlines from Hacker News search (topic selector). Main security news sites are linked under Reference → Links |
| **Lookup** | One CVE (NVD, falling back to CIRCL), many CVEs pasted from a ticket (up to 25), or NVD keyword search |
| **ATT&CK** | Full MITRE ATT&CK lookup: matrix, search, groups, software, mitigations, detections, text→technique mapper, Navigator layer export. One-time ~40 MB download, built in a Web Worker and stored in your browser |
| **Templates / Playbooks / Toolkit / Reference** | 11 analyst templates, 6 response checklists, IOC extractor/defanger, email-header analyser, Base64/URL/hex decoder, timestamp + FILETIME, CIDR, CVSS decoder, 17 KQL hunting queries, TLP/kill chain/ports/commands/event IDs, 56 links |
| **Sources** | **Test sources** (which services your browser may read), fetch settings, storage, *Delete fetched data* |

Press **/** anywhere for quick lookup: `T1059.001`, `APT29`, `CVE-2026-1234`.

## Set-up (about 5 minutes, free GitHub account, no Actions needed)
1. Create a **public** repository (GitHub Pages on the free plan needs a public repo).
2. Upload everything in this folder (*Add file → Upload files*). `.nojekyll` can be skipped if your browser hides dot-files.
3. **Settings → Pages → Build and deployment → Deploy from a branch → `main` / `(root)` → Save.**
4. After a minute open `https://<your-username>.github.io/<repo>/` in Edge → **App available** icon in the address bar → **Install**.
5. Open **Sources → Test all sources** once. It tells you, from *your* browser, which services work (see below).

## IMPORTANT: which sources work is decided by each service, not by this app
A web page may only read another website if that site allows it (CORS). I could not test the live services from where this was built,
so the app is designed to **adapt**:

| Capability | Source | If your browser is blocked |
|---|---|---|
| Latest CVEs list, keyword search | NVD | Those two features are unavailable (NVD is the only source with a date-range query); everything else still works |
| Single / bulk CVE lookup | NVD → CIRCL fallback | Works if either is allowed |
| EPSS scores | FIRST API | CVEs are still fetched, just without EPSS (a note says so) |
| KEV catalogue | CISA's GitHub mirror | KEV page stays empty; links to CISA are under Reference |
| ATT&CK | MITRE's GitHub | Use attack.mitre.org; the rest of the app is unaffected |
| Headlines | Hacker News (Algolia) | News page stays empty |

A third-party write-up reports that NVD can't be called from browser JavaScript while CIRCL can; if NVD turns out to be blocked for you, that is the
trade-off of "no backend". The only fixes are a tiny proxy you host yourself (which brings a backend back) or using the scheduled-build version.

## Updating the app
After you change **any** file in `js/`, `css/`, `icons/` or `index.html`, change `BUILD` at the top of **`sw.js`** (any new text, e.g. the date).
The browser then installs the new files in the background and reloads once. If you forget, Edge keeps serving the old files.
Editable content: `js/templates.js`, `js/playbooks.js`, `js/kql.js`, `js/refdata.js` (links, ports, commands). To allow a new data host you must add it to
**both** `js/net.js` (`SOURCES`) and the `connect-src` in `index.html`, and keep the two lists identical.

## What you give up compared with a scheduled / server version
* No automatic refresh – data is as fresh as your last click (the header shows how old it is; a banner appears after 3 days).
* One person, one browser: fetched data and settings live in *this* browser profile.
* News is limited to what allows browser access (see above).
* No NVD API key (a key can't be kept secret in a web page, and keyless limits are fine for manual use: about 5 requests per 30 s, which the app paces itself to).

## Privacy and security
See **SECURITY.md**. In short: requests go from your browser straight to the listed hosts, no cookies, no referrer, HTTPS only, size- and time-limited,
only when you click. Feed text is always rendered as plain text. Your watchlist, templates, checklist ticks and ATT&CK selections stay in this browser.

## Attribution
MITRE ATT&CK® is a registered trademark of The MITRE Corporation; ATT&CK data © The MITRE Corporation, used under its terms of use.
This product uses data from the NVD API but is not endorsed or certified by the NVD. KEV data from CISA. EPSS from FIRST.org. CVE records also from CIRCL.
