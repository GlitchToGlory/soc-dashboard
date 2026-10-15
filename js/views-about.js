import { h, ext } from "./ui.js";
import { SOURCES } from "./net.js";
import { TEMPLATES } from "./templates.js";
import { PLAYBOOKS } from "./playbooks.js";
import { KQL } from "./kql.js";
import { LINK_GROUPS } from "./refdata.js";

const REPO = "https://github.com/GlitchToGlory/soc-dashboard";

const tbl = (head, rows) => h("table", {},
  h("thead", {}, h("tr", {}, head.map((x) => h("th", {}, x)))),
  h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c, i) => h(i === 0 ? "th" : "td", {}, c))))));
const points = (items) => h("ul", { class: "about-points" }, items.map(([title, text]) => h("li", {}, h("strong", {}, title), " ", text)));

const page = (route, name) => h("a", { href: `#/${route}` }, name);

export function renderAbout() {
  const hosts = SOURCES.map((s) => s.host).filter((x, i, a) => a.indexOf(x) === i);
  // Counts come from the data itself, so this page stays right when templates, playbooks, queries or links are added.
  const links = LINK_GROUPS.reduce((n, [, items]) => n + items.length, 0);
  return h("div", { class: "about" },
    h("h1", {}, "About SOC Dashboard"),
    h("p", { class: "about-lead" },
      "A toolkit for security operations analysts: newly published CVEs, CISA's Known Exploited Vulnerabilities, security headlines, a full MITRE ATT&CK lookup, ",
      "analyst templates and response playbooks, and everyday triage tools. It is a set of static files that runs entirely in your web browser – ",
      "there is no server, no account and no background process."),

    h("section", { class: "card about-highlight" },
      h("h2", {}, "Privacy at a glance"),
      points([
        ["No account, no sign-in, no cookies.", "There is nothing to register for and nothing that identifies you to the app."],
        ["No tracking.", "No analytics, ads, telemetry, or third-party scripts, fonts or CDNs. All the app's code comes from this site."],
        ["Nothing runs in the background.", "The app only contacts a data source when you press a button such as ↻ Fetch all feeds, and you can cancel any fetch."],
        ["No middleman.", "Requests go straight from your browser to the data source, without cookies or a referrer. There is no server of ours in between: GitHub Pages only delivers the app's own files."],
        ["No API keys.", "None are used or stored anywhere."],
        ["Your analysis stays on your device.", "The Toolkit (IOC extractor, URL analyser, email-header analyser, timeline builder, decoders) runs in your browser. Text you paste into it is never sent anywhere, and the incident timeline isn't even saved."],
        ["Look-ups elsewhere are your choice.", "VirusTotal, AbuseIPDB and urlscan links open in a new tab, and send only the indicator, only when you select them."],
      ])),

    h("section", { class: "card" },
      h("h2", {}, "What's inside"),
      tbl(["Page", "What it does"], [
        [page("overview", "Overview"), "One click fetches the KEV catalogue, the latest CVEs and news. Shows CVEs ranked by risk (in KEV first, then EPSS exploit probability, then CVSS), the latest KEV additions, headlines and your vendor/product watchlist."],
        [page("cves", "CVEs"), "Newly published CVEs from NVD (last 1–30 days) with EPSS scores; filter by severity, KEV, EPSS, watchlist and date, and draft an advisory brief from any CVE."],
        [page("kev", "KEV"), "CISA's Known Exploited Vulnerabilities catalogue, with search and a known-ransomware-use filter."],
        [page("news", "News"), "Security headlines from Hacker News search across every topic – vulnerabilities, CVEs, ransomware, zero-days, breaches, malware and phishing – with instant topic filters. The main security news sites are linked under Reference → Links."],
        [page("lookup", "Lookup"), "Look up one CVE (NVD, falling back to CIRCL), up to 25 CVEs pasted from a ticket, or search NVD by keyword."],
        [page("attack", "ATT&CK"), "A full MITRE ATT&CK lookup: matrix, search, groups, software, mitigations, detections, a text-to-technique mapper and ATT&CK Navigator layer export. A one-time ~40 MB download, built in the background and kept in your browser."],
        [page("templates", "Templates"), `${TEMPLATES.length} analyst templates (triage notes, escalation, incident report, shift handover…) – fill in the fields and copy the result. You can add your own.`],
        [page("playbooks", "Playbooks"), `${PLAYBOOKS.length} response checklists whose ticks are remembered in your browser.`],
        [page("toolkit", "Toolkit"), "IOC extractor & defanger, URL analyser & unwrapper, incident timeline builder, email-header analyser, Base64 / URL / hex decoder, timestamp converter, CIDR calculator and CVSS decoder."],
        [page("reference", "Reference"), `${KQL.length} KQL hunting queries, TLP / kill chain / Pyramid of Pain, ports, triage commands, Windows event IDs and ${links} useful links.`],
        [page("sources", "Sources"), "Test which services your browser may read, fetch settings, storage use and Delete fetched data."],
      ])),

    h("div", { class: "grid two" },
      h("section", { class: "card" },
        h("h2", {}, "Tips"),
        h("ul", { class: "small" },
          h("li", {}, "Press ", h("code", {}, "/"), " anywhere for quick lookup: an ATT&CK ID (", h("code", {}, "T1059.001"), "), a group (", h("code", {}, "APT29"), ") or a CVE (", h("code", {}, "CVE-2026-1234"), ")."),
          h("li", {}, "Install it as an app: in Edge or Chrome use the install icon in the address bar; on a phone use “Add to Home Screen”."),
          h("li", {}, "After the first visit the app itself opens offline. Data you've already fetched is still there; new fetches need a connection."),
          h("li", {}, "Collapse the menu to icons with ☰ (top left) for more room."))),
      h("section", { class: "card" },
        h("h2", {}, "Which sources work in your browser"),
        h("p", { class: "small muted" }, "A web page may only read another website if that site allows it, and each service decides that for itself – not this app. So the app adapts: anything blocked is skipped with a clear message, and the rest keeps working. ",
          h("a", { href: "#/sources" }, "Sources → Test sources"), " checks them from your browser."),
        tbl(["Feature", "Source", "If it's blocked"], [
          ["Latest CVEs, keyword search", "NVD", "These two are unavailable (NVD is the only source with a date-range search)"],
          ["Single / bulk CVE lookup", "NVD, then CIRCL", "Works if either one is allowed"],
          ["EPSS scores", "FIRST", "CVEs still load, without EPSS"],
          ["KEV catalogue", "CISA (GitHub mirror)", "KEV page stays empty"],
          ["ATT&CK", "MITRE (GitHub)", "Use attack.mitre.org instead"],
          ["Headlines", "Hacker News (Algolia)", "News page stays empty"],
        ]))),

    h("div", { class: "grid two" },
      h("section", { class: "card" },
        h("h2", {}, "What leaves your browser"),
        h("p", { class: "small muted" }, `Only these ${hosts.length} services are ever contacted, and only when you ask. The browser itself enforces this list (see Security below). Like any web request, each one sees your IP address.`),
        tbl(["Service", "When", "What it receives"], [
          ["NIST NVD", "Fetching latest CVEs, a CVE lookup, keyword search", "The date range, the CVE ID or the keyword"],
          ["CIRCL", "CVE lookup when NVD doesn't answer", "The CVE ID"],
          ["FIRST EPSS", "Adding exploit-probability scores", "The CVE IDs being scored"],
          ["GitHub (raw files)", "Fetching the KEV catalogue; downloading ATT&CK", "A request for the public file – nothing about you"],
          ["Hacker News search", "Fetching headlines", "The topic keywords (e.g. “ransomware”, “phishing”)"],
          ["All of the above", "Sources → Test sources", "One small test request each"],
        ]),
        h("p", { class: "small muted" }, "GitHub Pages hosts the app's files, so, like any website host, GitHub sees that the site was loaded.")),

      h("section", { class: "card" },
        h("h2", {}, "What's stored on this device"),
        h("p", { class: "small muted" }, "Everything below stays in this browser profile. Nothing is synced or uploaded."),
        tbl(["What", "Where"], [
          ["Fetched CVEs, KEV, headlines, ATT&CK data", "Browser storage (IndexedDB)"],
          ["Watchlist, your own templates, playbook ticks, ATT&CK selection, settings, theme", "Browser storage (localStorage)"],
          ["The app's own files, for offline use", "Offline cache (service worker)"],
          ["Text pasted into Toolkit tools, CVE look-ups, the incident timeline", "Not stored"],
        ]),
        h("p", { class: "small" }, "To remove fetched data use ", h("a", { href: "#/sources" }, "Sources → Delete fetched data"),
          ". To remove everything, clear this site's data in your browser's settings."))),

    h("section", { class: "card" },
      h("h2", {}, "Security"),
      h("p", { class: "small muted" }, "Built so that opening it, installing it and feeding it hostile data can't hurt you."),
      points([
        ["Feed content can't run code.", "Every CVE description, headline and ATT&CK text is shown as plain text: the app never builds HTML from text."],
        ["Strict Content Security Policy.", `Only the app's own scripts may run, and the browser blocks connections to anything except: ${hosts.join(", ")}.`],
        ["Trusted Types.", "In Chrome and Edge the browser itself refuses any attempt to inject HTML or load an unapproved script – a second line of defence."],
        ["Careful networking.", "HTTPS only, no cookies or credentials, no referrer, and every download is size- and time-limited while it streams."],
        ["Stored data is re-checked.", "Everything read back from browser storage is validated before use, so damaged or tampered data can't break a page or smuggle anything in."],
        ["Hostile input is handled.", "Pasted text and downloaded files are size-capped and parsed with patterns that can't freeze the tab; the large ATT&CK file is processed in a separate worker."],
        ["Clickjacking protection.", "The app refuses to run inside another site's frame."],
        ["No third-party code.", "No libraries, packages or CDNs – nothing outside this repository runs."],
      ]),
      h("p", { class: "small" }, "Full details: ", ext(`${REPO}/blob/main/SECURITY.md`, "SECURITY.md on GitHub ↗"), ".")),

    h("div", { class: "grid two" },
      h("section", { class: "card" },
        h("h2", {}, "Good to know"),
        h("ul", { class: "small" },
          h("li", {}, "The site is public. Keep internal or confidential information out of your custom templates."),
          h("li", {}, "Every site on ", h("code", {}, "glitchtoglory.github.io"), " shares one browser storage area, so other sites hosted under that account could read this app's saved data."),
          h("li", {}, "A look-up tells that service what you looked up (and your IP address), as with any website."),
          h("li", {}, "Data is only as fresh as your last fetch, and only as accurate as its source. Use it alongside your organisation's own tools and procedures."))),
      h("section", { class: "card" },
        h("h2", {}, "Data sources & attribution"),
        h("ul", { class: "small" },
          h("li", {}, "MITRE ATT&CK® is a registered trademark of The MITRE Corporation; ATT&CK data © The MITRE Corporation, used under its terms of use."),
          h("li", {}, "This product uses data from the NVD API but is not endorsed or certified by the NVD."),
          h("li", {}, "Known Exploited Vulnerabilities catalogue from CISA; EPSS scores from FIRST.org; CVE records also from CIRCL; headlines via Hacker News (Algolia).")),
        h("p", { class: "small" }, "Source code: ", ext(REPO, "github.com/GlitchToGlory/soc-dashboard ↗")))));
}
