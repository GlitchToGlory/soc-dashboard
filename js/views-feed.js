import { h, ext, badge, copyBtn, pagedList, field, select, debounce, empty, nodes, lazyDetails } from "./ui.js";
import { state, setWatch } from "./state.js";
import { fmtUTC, timeAgo, matchesWatchlist, SEV_ORDER } from "./lib.js";
import { taskButton, daysSelect, topicPicker, epssCheck, fetchedLine, getStarted } from "./live-ui.js";
import { getSettings } from "./tasks.js";
import { TOPIC_LABELS } from "./live.js";

const pct = (x) => (x * 100).toFixed(1) + "%";
// Plain string order for ISO dates / IDs: much cheaper than localeCompare on every keystroke, and identical for these values.
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
// Lower-cased search text, built once per record and reused on every keystroke (released with the record when data is refetched).
const hayCache = new WeakMap();
const hay = (o, build) => { let s = hayCache.get(o); if (s === undefined) { s = build(o).toLowerCase(); hayCache.set(o, s); } return s; };
const cveHay = (c) => `${c.id} ${c.desc} ${(c.products || []).join(" ")} ${(c.cwes || []).join(" ")}`;
const kevHay = (k) => `${k.id} ${k.vendor} ${k.product} ${k.name} ${k.desc}`;
const sevRank = (s) => SEV_ORDER[s] ?? -1;
const isKev = (c) => c.kev || state.kevSet.has(c.id);

function sevBadge(c) {
  const s = (c.sev || "").toLowerCase() || "unrated";
  return badge(c.cvss != null ? `${Number(c.cvss).toFixed(1)} ${c.sev || ""}`.trim() : "Awaiting score", s);
}

function draftBrief(values) {
  state.prefill = { id: "vuln-advisory", values };
  location.hash = "#/templates/vuln-advisory";
}

// ------------------------------------------------------------------ CVE row
export function cveItem(c, { open = false, via = "" } = {}) {
  const kev = isKev(c);
  const watch = matchesWatchlist(c, state.watch);
  const summary = h("summary", {},
    h("div", { class: "line" },
      h("span", { class: "id" }, c.id), sevBadge(c),
      kev && badge("KEV", "kev"),
      c.epss != null && badge(`EPSS ${pct(c.epss)}`, c.epss >= 0.1 ? "epss-hi" : "epss"),
      watch && badge("Watchlist", "watch"),
      via && badge(`via ${via}`, "epss"),
      h("span", { class: "muted small" }, c.published ? `${fmtUTC(c.published)} · ${timeAgo(c.published)}` : "")),
    h("div", { class: "clamp" }, c.desc));

  const build = () => {
    const dl = h("dl", { class: "kv" },
      h("dt", {}, "Published"), h("dd", {}, fmtUTC(c.published)),
      h("dt", {}, "Last modified"), h("dd", {}, fmtUTC(c.modified)),
      h("dt", {}, "Status"), h("dd", {}, c.status || "—"),
      h("dt", {}, "CVSS vector"), h("dd", {}, c.vector ? h("code", {}, c.vector) : "Not scored yet"),
      h("dt", {}, "EPSS"), h("dd", {}, c.epss != null ? `${pct(c.epss)} probability of exploitation in 30 days (percentile ${(c.epssPct * 100).toFixed(0)})` : "n/a"),
      h("dt", {}, "Weakness"), h("dd", {}, (c.cwes || []).join(", ") || "—"),
      h("dt", {}, "Products"), h("dd", {}, (c.products || []).join(", ") || "—"));
    const refs = (c.refs || []).length ? h("ul", { class: "plain small" }, c.refs.map((r) => h("li", {}, ext(r, r)))) : null;
    return h("div", { class: "body" },
      h("p", {}, c.desc), dl, refs,
      h("div", { class: "actions" },
        copyBtn(c.id, "Copy CVE ID"),
        ext(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}`, "NVD ↗", "btn sm"),
        ext(`https://www.cve.org/CVERecord?id=${encodeURIComponent(c.id)}`, "CVE.org ↗", "btn sm"),
        h("button", { class: "btn sm primary", type: "button", onclick: () => draftBrief({
          cve_id: c.id,
          cvss: c.cvss != null ? `${c.cvss} ${c.sev} (CVSS v${c.cvssVer})` : "Not yet scored",
          epss: c.epss != null ? `${pct(c.epss)} (percentile ${(c.epssPct * 100).toFixed(0)})` : "n/a",
          in_kev: kev ? "Yes" : "No",
          description: c.desc,
          affected_products: (c.products || []).join(", "),
        }) }, "Draft brief")));
  };
  return lazyDetails(summary, build, open);
}

// ------------------------------------------------------------------ KEV row
export function kevItem(k) {
  const ransom = (k.ransomware || "").toLowerCase() === "known";
  const overdue = k.due && Date.parse(k.due + "T23:59:59Z") < state.ref;
  const summary = h("summary", {},
    h("div", { class: "line" },
      h("span", { class: "id" }, k.id), badge("KEV", "kev"),
      ransom && badge("Ransomware", "ransom"),
      h("strong", {}, `${k.vendor} ${k.product}`),
      h("span", { class: "muted small" }, `added ${fmtUTC(k.added)}`)),
    h("div", { class: "clamp" }, k.name + (k.desc ? " — " + k.desc : "")));
  const build = () => h("div", { class: "body" },
    h("p", {}, h("strong", {}, k.name)), h("p", {}, k.desc),
    h("dl", { class: "kv" },
      h("dt", {}, "Date added"), h("dd", {}, fmtUTC(k.added)),
      h("dt", {}, "Federal due date"), h("dd", {}, k.due ? `${fmtUTC(k.due)}${overdue ? " (past)" : ""}` : "—"),
      h("dt", {}, "Ransomware use"), h("dd", {}, k.ransomware || "Unknown"),
      h("dt", {}, "Required action"), h("dd", {}, k.action || "—"),
      h("dt", {}, "CWE"), h("dd", {}, (k.cwes || []).join(", ") || "—")),
    h("div", { class: "actions" },
      copyBtn(k.id, "Copy CVE ID"),
      ext(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(k.id)}`, "NVD ↗", "btn sm"),
      h("button", { class: "btn sm primary", type: "button", onclick: () => {
        const c = state.cves.find((x) => x.id === k.id);
        draftBrief({
          cve_id: k.id, in_kev: "Yes — CISA KEV", description: `${k.name}. ${k.desc}`,
          cvss: c && c.cvss != null ? `${c.cvss} ${c.sev}` : "", epss: c && c.epss != null ? pct(c.epss) : "",
          affected_products: `${k.vendor} ${k.product}`, mitigation: k.action,
        });
      } }, "Draft brief")));
  return lazyDetails(summary, build);
}

// ------------------------------------------------------------------ News row
export function newsItem(n) {
  return h("div", { class: "news-item" },
    h("div", { class: "t" }, ext(n.link, n.title)),
    h("div", { class: "small muted" }, `${n.source}${n.date ? " · " + fmtUTC(n.date) + " · " + timeAgo(n.date) : ""}`),
    n.summary ? h("div", { class: "s" }, n.summary) : null);
}

// ------------------------------------------------------------------ Overview
const rank = (c) => (isKev(c) ? 1000 : 0) + (c.epss || 0) * 100 + (c.cvss || 0);

export function renderOverview() {
  const within = (iso, d) => iso && state.ref - Date.parse(iso.length === 10 ? iso + "T00:00:00Z" : iso) <= d * 86400e3;
  const cves = state.cves;
  const crit = cves.filter((c) => c.sev === "CRITICAL").length;
  const high = cves.filter((c) => c.sev === "HIGH").length;
  const kevCves = cves.filter(isKev).length;
  const kevNew = state.kev.filter((k) => within(k.added, 7));
  const news24 = state.news.filter((n) => within(n.date, 1)).length;
  const watchHits = cves.filter((c) => matchesWatchlist(c, state.watch));
  const nothing = !cves.length && !state.kev.length && !state.news.length;

  const stat = (n, l, cls = "", href = "") =>
    h(href ? "a" : "div", { class: `stat ${cls}`, href: href || null }, h("div", { class: "n" }, String(n)), h("div", { class: "l" }, l));
  const stats = h("div", { class: "stats" },
    stat(cves.length, "CVEs fetched", "", "#/cves"), stat(crit, "Critical", "crit"), stat(high, "High", "high"),
    stat(kevCves, "…also in KEV", "kev"), stat(kevNew.length, "KEV added (7d)", "kev", "#/kev"), stat(news24, "News (24h)", "", "#/news"));

  const riskTop = [...cves].sort((a, b) => rank(b) - rank(a)).slice(0, 8);
  const input = h("input", { type: "text", placeholder: "e.g. fortinet, citrix, exchange, vmware", value: state.watch.join(", "), "aria-label": "Watchlist keywords" });
  const save = () => {
    setWatch(input.value.split(/[,\n]/).map((s) => s.trim().toLowerCase()).filter(Boolean));
    window.dispatchEvent(new Event("hashchange"));
  };
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") save(); });
  const watchCard = h("section", { class: "card" },
    h("h2", {}, "Watchlist", h("a", { href: "#/cves" }, "Open CVE list →")),
    h("p", { class: "small muted" }, "Keywords for vendors/products you run. Matching CVEs are tagged and can be filtered. Saved in this browser only."),
    h("div", { class: "row" }, input, h("button", { class: "btn primary", type: "button", onclick: save }, "Save")),
    state.watch.length
      ? (watchHits.length
          ? h("ul", { class: "plain" }, watchHits.slice(0, 6).map((c) => h("li", {}, h("span", { class: "id" }, c.id + " "), sevBadge(c), h("div", { class: "small muted" }, c.desc.slice(0, 140)))))
          : h("p", { class: "muted small" }, "No fetched CVEs match your keywords."))
      : null);

  return h("div", {}, h("h1", {}, "Overview"),
    h("div", { class: "row" }, taskButton("update", "↻ Fetch KEV, CVEs + News", { primary: true }), daysSelect(), epssCheck()),
    h("div", { class: "row" }, fetchedLine("kev", "KEV"), fetchedLine("cves", "CVEs"), fetchedLine("news", "News")),
    nothing ? getStarted() : null,
    nothing ? null : stats,
    nothing ? null : h("div", { class: "grid two" },
      h("section", { class: "card" }, h("h2", {}, "Highest-risk new CVEs", h("a", { href: "#/cves" }, "All →")),
        h("p", { class: "small muted" }, "Ranked: in KEV first, then EPSS, then CVSS."),
        riskTop.length ? h("div", { class: "list" }, riskTop.map((c) => cveItem(c))) : empty("No CVEs fetched yet.")),
      h("section", { class: "card" }, h("h2", {}, "Latest CISA KEV additions", h("a", { href: "#/kev" }, "All →")),
        state.kev.length ? h("div", { class: "list" }, state.kev.slice(0, 8).map(kevItem)) : empty("KEV not fetched yet.")),
      h("section", { class: "card" }, h("h2", {}, "Latest news", h("a", { href: "#/news" }, "All →")),
        state.news.length ? h("p", { class: "small muted" }, "Newest headlines across all topics.") : null,
        state.news.length ? state.news.slice(0, 8).map(newsItem) : empty("No headlines fetched yet.")),
      watchCard));
}

// ------------------------------------------------------------------ CVEs
export const cveFilter = { q: "", sev: "all", kev: false, epss: "0", watch: false, days: "all", sort: "new" };

function chk(label, value, onchange) {
  const i = h("input", { type: "checkbox" });
  i.checked = !!value;
  i.addEventListener("change", () => onchange(i.checked));
  return h("label", { class: "check" }, i, label);
}

export function renderCves() {
  const results = h("div", {});
  const update = () => {
    const f = cveFilter;
    const q = f.q.trim().toLowerCase();
    let items = state.cves.filter((c) => {
      if (q && !hay(c, cveHay).includes(q)) return false;
      if (f.sev !== "all") { if (f.sev === "unrated" ? c.sev : c.sev !== f.sev.toUpperCase()) return false; }
      if (f.kev && !isKev(c)) return false;
      if (Number(f.epss) > 0 && !((c.epss || 0) >= Number(f.epss))) return false;
      if (f.watch && !matchesWatchlist(c, state.watch)) return false;
      if (f.days !== "all" && state.ref - Date.parse(c.published) > Number(f.days) * 86400e3) return false;
      return true;
    });
    const sorters = {
      new: (a, b) => cmp(b.published, a.published),
      cvss: (a, b) => (b.cvss ?? -1) - (a.cvss ?? -1) || (sevRank(b.sev) - sevRank(a.sev)),
      epss: (a, b) => (b.epss ?? -1) - (a.epss ?? -1),
    };
    items = items.sort(sorters[f.sort]);
    const idQ = /^CVE-\d{4}-\d{4,}$/i.test(f.q.trim());
    results.replaceChildren(h("p", { class: "muted small" }, `${items.length} of ${state.cves.length} CVEs`),
      !items.length && idQ ? h("div", { class: "empty" }, "Not in the fetched list. ", h("a", { href: `#/lookup/${f.q.trim().toUpperCase()}` }, "Look it up live →")) : pagedList(items, (c) => cveItem(c)));
  };
  const search = h("input", { type: "search", placeholder: "CVE ID, product, keyword, CWE…", value: cveFilter.q, "aria-label": "Search CVEs" });
  search.addEventListener("input", debounce(() => { cveFilter.q = search.value; update(); }));
  const upd = (k) => (v) => { cveFilter[k] = v; update(); };
  const bar = h("div", { class: "toolbar" },
    field("Search", search),
    field("Severity", select([["all", "All"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["unrated", "Not yet scored"]], cveFilter.sev, upd("sev"))),
    field("Min EPSS", select([["0", "Any"], ["0.01", "≥ 1%"], ["0.05", "≥ 5%"], ["0.1", "≥ 10%"], ["0.5", "≥ 50%"]], cveFilter.epss, upd("epss"))),
    field("Published", select([["all", "Any time"], ["1", "Last 24h"], ["3", "Last 3 days"], ["7", "Last 7 days"]], cveFilter.days, upd("days"))),
    field("Sort", select([["new", "Newest"], ["cvss", "CVSS"], ["epss", "EPSS"]], cveFilter.sort, upd("sort"))),
    chk("In CISA KEV", cveFilter.kev, upd("kev")), chk("Watchlist only", cveFilter.watch, upd("watch")));
  update();
  return h("div", {}, h("h1", {}, "Newly published CVEs"),
    h("p", { class: "muted small" }, "Fetched live from NVD when you ask, enriched with EPSS and CISA KEV status. Newly published CVEs often have no CVSS score yet."),
    h("div", { class: "row" }, taskButton("cves", "↻ Fetch latest CVEs", { primary: true }), daysSelect(), epssCheck(), fetchedLine("cves", "CVEs")),
    state.meta.note.cves ? h("p", { class: "small muted" }, state.meta.note.cves) : null,
    state.cves.length ? bar : getStarted(), state.cves.length ? results : null);
}

// ------------------------------------------------------------------ KEV
const kevFilter = { q: "", ransom: false, days: "all", sort: "added" };

export function renderKev() {
  const results = h("div", {});
  const update = () => {
    const f = kevFilter, q = f.q.trim().toLowerCase();
    const items = state.kev.filter((k) => {
      if (q && !hay(k, kevHay).includes(q)) return false;
      if (f.ransom && (k.ransomware || "").toLowerCase() !== "known") return false;
      if (f.days !== "all" && state.ref - Date.parse(k.added + "T00:00:00Z") > Number(f.days) * 86400e3) return false;
      return true;
    }).sort(f.sort === "due" ? (a, b) => cmp(b.due || "", a.due || "") : (a, b) => cmp(b.added, a.added));
    results.replaceChildren(h("p", { class: "muted small" }, `${items.length} of ${state.kev.length} entries`), pagedList(items, kevItem));
  };
  const search = h("input", { type: "search", placeholder: "CVE ID, vendor, product…", value: kevFilter.q, "aria-label": "Search KEV" });
  search.addEventListener("input", debounce(() => { kevFilter.q = search.value; update(); }));
  const upd = (k) => (v) => { kevFilter[k] = v; update(); };
  update();
  return h("div", {}, h("h1", {}, "CISA Known Exploited Vulnerabilities"),
    h("p", { class: "muted small" }, "Vulnerabilities with evidence of active exploitation — a strong signal for patch prioritisation."),
    h("div", { class: "row" }, taskButton("kev", "↻ Fetch KEV catalogue", { primary: true }), fetchedLine("kev", "KEV")),
    state.kev.length ? h("div", { class: "toolbar" }, field("Search", search),
      field("Added", select([["all", "Any time"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"]], kevFilter.days, upd("days"))),
      field("Sort", select([["added", "Date added"], ["due", "Due date"]], kevFilter.sort, upd("sort"))),
      chk("Known ransomware use", kevFilter.ransom, upd("ransom"))) : getStarted(),
    state.kev.length ? results : null);
}

// ------------------------------------------------------------------ News
const newsFilter = { q: "" };

export function renderNews() {
  const results = h("div", { class: "card" });
  let topic = getSettings().topic;
  const tagged = state.news.some((n) => n.topics && n.topics.length);
  const update = () => {
    const q = newsFilter.q.trim().toLowerCase();
    const items = state.news.filter((n) => (topic === "all" || !tagged || (n.topics || []).includes(topic)) && (!q || `${n.title} ${n.summary}`.toLowerCase().includes(q)));
    results.replaceChildren(...nodes(
      !tagged && topic !== "all" ? h("p", { class: "small muted" }, "These headlines were fetched before topic filters existed – press ↻ Fetch latest headlines to sort them by topic.") : null,
      h("p", { class: "muted small" }, `${items.length} of ${state.news.length} stories${topic !== "all" && tagged ? ` · ${TOPIC_LABELS[topic]}` : ""}`),
      items.length ? pagedList(items, newsItem, 30) : empty("No stories match.")));
  };
  const search = h("input", { type: "search", placeholder: "Search headlines…", value: newsFilter.q, "aria-label": "Search news" });
  search.addEventListener("input", debounce(() => { newsFilter.q = search.value; update(); }));
  update();
  return h("div", {}, h("h1", {}, "Security news"),
    h("p", { class: "muted small" }, "Headlines come from Hacker News searches for each security topic below, combined — community-ranked links, not a newswire. Each fetch covers every topic; the topic buttons just filter the list. Most security news sites don't allow direct reads from a web page, so the main ones are linked under Reference → Links instead."),
    state.news.length ? topicPicker((t) => { topic = t; update(); }) : null,
    h("div", { class: "row" }, taskButton("news", "↻ Fetch latest headlines", { primary: true }), fetchedLine("news", "News")),
    state.news.length ? h("div", { class: "toolbar" }, field("Search", search)) : getStarted(), state.news.length ? results : null);
}
