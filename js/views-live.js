import { h, badge, field, empty, nodes } from "./ui.js";
import { state } from "./state.js";
import { lookupCve, bulkLookup, searchCves, normaliseCveId } from "./live.js";
import { describeError, SOURCES } from "./net.js";
import { runProbes } from "./live.js";
import { extractIOCs, timeAgo } from "./lib.js";
import { cveItem } from "./views-feed.js";
import { kvClear, storage } from "./store.js";
import { store } from "./ui.js";
import { getSettings } from "./tasks.js";
import { daysSelect, topicSelect, epssCheck } from "./live-ui.js";

const CVE_ID = /^CVE-\d{4}-\d{4,7}$/;
const msg = (e) => String((e && e.message) || e).slice(0, 500);

export function renderLookup(parts) {
  const status = h("p", { class: "small muted", "aria-live": "polite" });
  let ctl = null;
  const cancel = h("button", { class: "btn sm danger", type: "button", hidden: true, onclick: () => ctl && ctl.abort() }, "Cancel");
  const out = h("div", {});
  const kevNote = state.kev.length ? null : h("p", { class: "small muted" }, "KEV status isn't shown because the KEV catalogue hasn't been fetched yet (KEV page → Fetch).");

  const go = async (fn) => {
    if (ctl) return;
    ctl = new AbortController(); cancel.hidden = false; status.classList.remove("err"); out.replaceChildren(); status.textContent = "Working…";
    try { await fn(ctl.signal, (m) => { status.textContent = m; }); }
    catch (e) { status.textContent = e && e.kind === "cancelled" ? "Cancelled." : msg(e); if (!(e && e.kind === "cancelled")) status.classList.add("err"); }
    finally { ctl = null; cancel.hidden = true; }
  };

  // ---- single CVE
  const one = h("input", { type: "text", placeholder: "CVE-2024-3400", maxlength: "20", "aria-label": "CVE ID", value: CVE_ID.test(normaliseCveId(parts[1])) ? normaliseCveId(parts[1]) : "" });
  const doOne = () => go(async (signal, progress) => {
    progress(`Looking up ${normaliseCveId(one.value)}…`);
    const r = await lookupCve(one.value, { signal, epss: getSettings().epss });
    status.textContent = `Found via ${r.via}.${r.notes.length ? " " + r.notes.join(" ") : ""}`;
    out.replaceChildren(h("div", { class: "list" }, cveItem(r.cve, { open: true, via: r.via })));
  });
  one.addEventListener("keydown", (e) => { if (e.key === "Enter") doOne(); });

  // ---- bulk
  const bulk = h("textarea", { rows: "4", maxlength: "20000", class: "mono", placeholder: "Paste text containing CVE IDs (a ticket, scan output, an advisory). Up to 25 distinct IDs are looked up.", "aria-label": "Text containing CVE IDs" });
  const doBulk = () => go(async (signal, progress) => {
    const ids = extractIOCs(bulk.value).cves;
    if (!ids.length) throw new Error("No CVE IDs found in that text.");
    const res = await bulkLookup(ids, { signal, onProgress: progress });
    const ok = res.filter((r) => r.cve), bad = res.filter((r) => !r.cve);
    status.textContent = `${ok.length} found, ${bad.length} not found${ids.length > 25 ? " (only the first 25 IDs were used)" : ""}.`;
    out.replaceChildren(...nodes(
      ok.length ? h("div", { class: "list" }, ok.map((r) => cveItem(r.cve, { via: r.via }))) : null,
      bad.length ? h("div", { class: "card" }, h("h3", {}, "Not found"), h("ul", { class: "plain small" }, bad.map((r) => h("li", {}, h("span", { class: "id" }, r.id), " ", r.error)))) : null));
  });

  // ---- keyword search (NVD)
  const kw = h("input", { type: "search", placeholder: "e.g. fortigate, exchange server, log4j", maxlength: "100", "aria-label": "Keyword" });
  const doKw = () => go(async (signal, progress) => {
    progress("Searching NVD…");
    const r = await searchCves(kw.value, { signal });
    status.textContent = `${r.total} match${r.total === 1 ? "" : "es"} in NVD${r.total > r.cves.length ? ` — showing the ${r.cves.length} returned` : ""}.`;
    out.replaceChildren(r.cves.length ? h("div", { class: "list" }, r.cves.map((c) => cveItem(c, { via: "NVD" }))) : empty("No matches."));
  });
  kw.addEventListener("keydown", (e) => { if (e.key === "Enter") doKw(); });

  const view = h("div", {}, h("h1", {}, "Live lookup"),
    h("p", { class: "muted small" }, "Each lookup contacts a public service from your browser only when you press the button. Nothing you type is stored or sent anywhere else."),
    h("div", { class: "grid two" },
      h("section", { class: "card" }, h("h2", {}, "One CVE"), h("div", { class: "row" }, one, h("button", { class: "btn primary", type: "button", onclick: doOne }, "Look up")),
        h("p", { class: "small muted" }, "Tries NVD first, then CIRCL Vulnerability-Lookup. Adds the EPSS score when available.")),
      h("section", { class: "card" }, h("h2", {}, "Several CVEs"), bulk, h("div", { class: "row" }, h("button", { class: "btn primary", type: "button", onclick: doBulk }, "Look up all"))),
      h("section", { class: "card" }, h("h2", {}, "Search NVD by keyword"), h("div", { class: "row" }, kw, h("button", { class: "btn primary", type: "button", onclick: doKw }, "Search")),
        h("p", { class: "small muted" }, "Product or vendor names work best. Returns up to 50 results."))),
    h("div", { class: "row" }, cancel), status, kevNote, out);
  if (CVE_ID.test(normaliseCveId(parts[1]))) queueMicrotask(doOne);
  // Leaving the page stops a lookup that is still running, instead of letting it keep downloading in the background.
  window.addEventListener("hashchange", () => { if (ctl) ctl.abort(); }, { once: true });
  return view;
}

// ------------------------------------------------------------------ Sources
const NEEDS = [
  ["Latest CVEs list, keyword search", ["nvd"]], ["Single CVE lookup", ["nvd", "circl"], "any"], ["EPSS scores", ["epss"]],
  ["KEV catalogue", ["kev"]], ["ATT&CK data download", ["attack"]], ["Security headlines", ["hn"]],
];

// The sources table is listed A-Z by name. This only changes how the table is DISPLAYED; "Test all sources" still checks them in the order
// defined in net.js, and results appear in their alphabetical row as each check finishes.
const collator = new Intl.Collator("en", { sensitivity: "base", numeric: true });
const SOURCES_AZ = [...SOURCES].sort((a, b) => collator.compare(a.name, b.name));

export function renderSources() {
  const probes = store.get("probe", {}) || {};
  const status = h("p", { class: "small muted", "aria-live": "polite" });
  const body = h("div", {});

  const rows = () => SOURCES_AZ.map((s) => {
    const p = probes[s.id];
    return h("tr", {}, h("td", {}, h("strong", {}, s.name), h("div", { class: "small muted" }, s.use)), h("td", {}, h("code", {}, s.host)),
      h("td", {}, p ? [badge(p.ok ? "Works" : "Blocked / failed", p.ok ? "low" : "critical"), h("div", { class: "small muted" }, `${p.msg} · ${timeAgo(p.at)}`)] : h("span", { class: "muted small" }, "Not tested")));
  });
  const capabilities = () => NEEDS.map(([label, ids, mode]) => {
    const tested = ids.every((i) => probes[i]) || (mode === "any" && ids.some((i) => probes[i]));
    const ok = mode === "any" ? ids.some((i) => probes[i] && probes[i].ok) : ids.every((i) => probes[i] && probes[i].ok);
    return h("li", {}, tested ? badge(ok ? "OK" : "Unavailable", ok ? "low" : "critical") : badge("Untested", "unrated"), " ", label);
  });
  const draw = () => body.replaceChildren(
    h("table", {}, h("thead", {}, h("tr", {}, ["Source", "Host", "Result from this browser"].map((x) => h("th", {}, x)))), h("tbody", {}, rows())),
    h("h3", {}, "What works"), h("ul", { class: "plain" }, capabilities()));
  draw();

  let busy = false;
  const test = h("button", { class: "btn primary", type: "button" }, "Test all sources");
  test.addEventListener("click", async () => {
    if (busy) return; busy = true; test.disabled = true; status.textContent = "Testing… (the large files are only checked for access, not downloaded in full)";
    try {
      await runProbes({ onResult: (id, r) => { probes[id] = r; store.set("probe", probes); draw(); } });
      status.textContent = "Done.";
    } finally { busy = false; test.disabled = false; }
  });

  const storageLine = h("p", { class: "small muted" }, storage.persistent ? "Fetched data is saved in this browser (IndexedDB)." : "This browser blocked IndexedDB, so fetched data is kept in memory for this session only.");
  if (navigator.storage && navigator.storage.estimate) navigator.storage.estimate().then((e) => { if (e && e.usage != null) storageLine.textContent += ` Using about ${(e.usage / 1e6).toFixed(1)} MB.`; }).catch(() => {});
  const persist = h("button", { class: "btn", type: "button", onclick: async () => { try { status.textContent = (await navigator.storage.persist()) ? "Storage marked persistent." : "The browser declined (it may do so automatically for installed apps)."; } catch { status.textContent = "Not supported here."; } } }, "Ask browser to keep my data");
  const clear = h("button", { class: "btn danger", type: "button", onclick: async () => {
    if (!confirm("Delete all fetched data (CVEs, KEV, news, ATT&CK) from this browser? Your templates, watchlist and settings are kept.")) return;
    await kvClear(); store.del("probe"); status.textContent = "Fetched data deleted."; window.dispatchEvent(new Event("data-cleared"));
  } }, "Delete fetched data");

  return h("div", {}, h("h1", {}, "Sources"),
    h("p", { class: "muted small" }, "A web page may only read another website if that site allows it (CORS), and not every service does. Press the button to find out which services your browser can read. The app adapts: anything blocked is skipped with a clear message, and every other page keeps working."),
    h("div", { class: "row" }, test), status, body,
    h("section", { class: "card" }, h("h2", {}, "Fetch settings"),
      h("div", { class: "row" }, field("CVE window", daysSelect()), field("Headline topic", topicSelect()), epssCheck())),
    h("section", { class: "card" }, h("h2", {}, "Stored data"), storageLine, h("div", { class: "row" }, persist, clear)),
    h("section", { class: "card" }, h("h2", {}, "Privacy"),
      h("ul", { class: "small" },
        h("li", {}, "Requests go straight from your browser to the host shown above, with no cookies and no referrer, and only when you press a button."),
        h("li", {}, "No API keys are used or stored. NVD's keyless limit is about 5 requests per 30 seconds; the app paces itself to."),
        h("li", {}, "The reputation links elsewhere (VirusTotal etc.) open a new tab and send the indicator to that site only when you select them."))));
}
