// Manual, live lookups. Nothing here runs unless a click asks for it. Each capability has a fallback chain, because browsers can
// only read sites that allow it (CORS) and I can't know in advance which of them allow YOUR browser: see Sources -> Test sources.
import { fetchLimited, sleep, FetchError, describeError, probeSource, SOURCES, NVD_URL, CIRCL_URL, EPSS_URL, HN_URL, KEV_URL, ATTACK_URL } from "./net.js";
import { nvdToCves, cve5ToCve, kevFromJson, mergeEpss, hnToNews, CVE_ID } from "./convert.js";
import { kvSet } from "./store.js";
import { own } from "./lib.js";
import { scriptURL } from "./trusted.js";

export const TOPICS = { vulnerabilities: "vulnerability", cve: "CVE", ransomware: "ransomware", zeroday: "zero-day", breach: "data breach", malware: "malware", phishing: "phishing" };
// Topic filters on the News page; "all" (the default) shows every headline.
export const TOPIC_LABELS = { all: "All topics", vulnerabilities: "Vulnerabilities", cve: "CVE mentions", ransomware: "Ransomware", zeroday: "Zero-days", breach: "Data breaches", malware: "Malware", phishing: "Phishing" };

const NVD_PAGE = 1000, NVD_MAX_PAGES = 6, NVD_GAP_MS = 6500, KEEP = 1500, EPSS_BATCH = 90;
const noop = () => {};
const nvdDate = (ms) => new Date(ms).toISOString().slice(0, 19) + ".000";    // NVD wants extended ISO-8601, no offset (UTC)
const mb = (n) => (n / 1e6).toFixed(1);
const byPublishedDesc = (a, b) => (a.published < b.published ? 1 : a.published > b.published ? -1 : 0);
const rethrowCancel = (e) => { if (e && e.kind === "cancelled") throw e; };
const NAME = { nvd: "NVD", circl: "CIRCL", epss: "The EPSS service" };
// Re-throw a fetch error with a message written for this specific source (marked so it is shown as-is).
const described = (kind, message) => { const w = new FetchError(kind, message); w.described = true; return w; };
const wrap = (e, who, extra = "") => { const w = new FetchError((e && e.kind) || "blocked", `${describeError(e, who)}${extra}`, (e && e.status) || 0); w.described = true; return w; };

// ---------------------------------------------------------------- EPSS (best effort: a failure never loses the CVEs)
export async function enrichEpss(cves, { signal, onProgress = noop, fetchImpl, concurrency = 2 } = {}) {
  const ids = cves.map((c) => c.id), batches = [];
  for (let i = 0; i < ids.length; i += EPSS_BATCH) batches.push(ids.slice(i, i + EPSS_BATCH));
  let next = 0, done = 0, hit = 0, failure = null;
  const worker = async () => {
    while (next < batches.length && !failure) {
      const b = batches[next++];
      try {
        const j = await fetchLimited(`${EPSS_URL}?${new URLSearchParams({ cve: b.join(","), limit: "100" })}`, { maxBytes: 2_000_000, timeoutMs: 20_000, signal, fetchImpl });
        hit += mergeEpss(cves, j && j.data);
      } catch (e) { rethrowCancel(e); failure = e; }
      done++;
      onProgress(`Adding EPSS scores… ${done}/${batches.length}`);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, batches.length) }, worker));
  const note = failure ? `EPSS scores unavailable — ${describeError(failure, NAME.epss)}` : hit ? `EPSS scores added for ${hit} CVEs.` : "";
  return { hit, failure, note };
}

// ---------------------------------------------------------------- latest CVEs (NVD only: the only source with a date-range query)
export async function fetchLatestCves({ days = 3, epss = true, signal, onProgress = noop, fetchImpl, now = Date.now(), gapMs = NVD_GAP_MS } = {}) {
  days = Math.min(30, Math.max(1, Math.round(Number(days) || 3)));
  const start = now - days * 86_400_000;
  const all = [];
  let total = 0, pages = 0;
  for (let i = 0; i < NVD_MAX_PAGES; i++) {
    const q = new URLSearchParams({ pubStartDate: nvdDate(start), pubEndDate: nvdDate(now), resultsPerPage: String(NVD_PAGE), startIndex: String(i * NVD_PAGE) });
    onProgress(`Asking NVD for CVEs published in the last ${days} day${days > 1 ? "s" : ""}… (page ${i + 1})`);
    let json;
    try { json = await fetchLimited(`${NVD_URL}?${q}`, { maxBytes: 40_000_000, timeoutMs: 90_000, signal, fetchImpl }); }
    catch (e) { rethrowCancel(e); throw wrap(e, "NVD", " The “latest CVEs” list needs NVD (it's the only source with a date-range query)."); }
    total = Number(json && json.totalResults) || 0;
    pages++;
    all.push(...nvdToCves(json));
    if ((i + 1) * NVD_PAGE >= total) break;
    onProgress(`Got ${Math.min(all.length, total)} of ${total}. Waiting a few seconds for NVD's rate limit…`);
    await sleep(gapMs, signal);
  }
  const uniq = new Map();
  for (const c of all) if (!uniq.has(c.id)) uniq.set(c.id, c);
  const cves = [...uniq.values()].sort(byPublishedDesc).slice(0, KEEP);
  let note = total > pages * NVD_PAGE ? `NVD has ${total} CVEs in this window; showing the newest ${cves.length}.` : "";
  if (epss && cves.length) {
    try { const r = await enrichEpss(cves, { signal, onProgress, fetchImpl }); if (r.note) note = (note + " " + r.note).trim(); }
    catch (e) { rethrowCancel(e); }
  }
  await kvSet("cves", { savedAt: Date.now(), via: "NVD", days, total, note, data: cves });
  return { count: cves.length, total, note };
}

// ---------------------------------------------------------------- KEV
export async function fetchKev({ signal, fetchImpl } = {}) {
  let json;
  try { json = await fetchLimited(KEV_URL, { maxBytes: 15_000_000, timeoutMs: 60_000, signal, fetchImpl }); }
  catch (e) { rethrowCancel(e); throw wrap(e, "The CISA KEV mirror on GitHub"); }
  let data;
  try { data = kevFromJson(json); } catch { throw described("format", "The KEV file from GitHub was not in the expected format."); }
  await kvSet("kev", { savedAt: Date.now(), via: "CISA KEV (GitHub mirror)", data });
  return { count: data.count };
}

// ---------------------------------------------------------------- news
// Headlines: one search per topic, run side by side and merged, so every fetch covers all topics. Each headline is tagged with
// the topics whose search found it; the News page's topic buttons filter on those tags without fetching again, and the
// Overview always shows the newest across all topics. (The search service's own match-any-word option can't be used: it would
// split "data breach" into "data" OR "breach" and match almost everything.)
export async function fetchNews({ signal, fetchImpl } = {}) {
  const keys = Object.keys(TOPICS);
  const search = async (key) => {
    // Headline matches only, no typo tolerance: otherwise words found in a story's link or text (or near-misses) pull in
    // unrelated stories – "data breach" matched "Apple Plans to Block…" and startup launch posts.
    const q = new URLSearchParams({ query: TOPICS[key], tags: "story", hitsPerPage: "50", numericFilters: "points>2", restrictSearchableAttributes: "title", typoTolerance: "false" });
    return hnToNews(await fetchLimited(`${HN_URL}?${q}`, { maxBytes: 3_000_000, timeoutMs: 20_000, signal, fetchImpl }));
  };
  const results = await Promise.allSettled(keys.map(search));
  for (const r of results) if (r.status === "rejected") rethrowCancel(r.reason);
  if (!results.some((r) => r.status === "fulfilled")) throw wrap(results[0].reason, "Hacker News search");
  const byLink = new Map();
  results.forEach((r, i) => {
    if (r.status !== "fulfilled") return;
    for (const n of r.value) {
      const k = n.link.toLowerCase();
      const have = byLink.get(k);
      if (have) { if (!have.topics.includes(keys[i])) have.topics.push(keys[i]); }
      else byLink.set(k, { ...n, topics: [keys[i]] });
    }
  });
  const data = [...byLink.values()].sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  const missing = keys.filter((_, i) => results[i].status === "rejected").map((k) => TOPIC_LABELS[k]);
  const note = missing.length ? `couldn't fetch ${missing.join(", ")}` : "";
  await kvSet("news", { savedAt: Date.now(), via: "Hacker News", topic: "all", note, data });
  return { count: data.length, note };
}

// ---------------------------------------------------------------- single CVE (NVD, then CIRCL) and bulk
export const normaliseCveId = (v) => String(v ?? "").trim().toUpperCase();

export async function lookupCve(rawId, { signal, fetchImpl, order = ["nvd", "circl"], epss = true, skip = new Set() } = {}) {
  const id = normaliseCveId(rawId);
  if (!CVE_ID.test(id)) throw new Error("Enter a CVE ID like CVE-2024-3400");
  const notes = [];
  let cve = null, via = "";
  for (const src of order) {
    if (skip.has(src)) continue;
    try {
      if (src === "nvd") {
        const list = nvdToCves(await fetchLimited(`${NVD_URL}?${new URLSearchParams({ cveId: id })}`, { maxBytes: 5_000_000, timeoutMs: 30_000, signal, fetchImpl }));
        if (list[0]) { cve = list[0]; via = "NVD"; break; }
        notes.push("NVD has no record of this ID (yet).");
      } else {
        const c = cve5ToCve(await fetchLimited(`${CIRCL_URL}${encodeURIComponent(id)}`, { maxBytes: 5_000_000, timeoutMs: 30_000, signal, fetchImpl }));
        if (c && c.id === id) { cve = c; via = "CIRCL Vulnerability-Lookup"; break; }
        notes.push("CIRCL answered, but not in a format this app understands.");
      }
    } catch (e) {
      rethrowCancel(e);
      notes.push(describeError(e, NAME[src]));
      if (e && e.kind === "http" && (e.status === 403 || e.status === 429 || e.status >= 500)) skip.add(src);
      if (e && e.kind === "blocked") skip.add(src);
    }
  }
  if (!cve) { const err = new Error(notes.join(" ") || "Not found"); err.notes = notes; throw err; }
  if (epss && !skip.has("epss")) {
    try { mergeEpss([cve], (await fetchLimited(`${EPSS_URL}?${new URLSearchParams({ cve: id })}`, { maxBytes: 200_000, timeoutMs: 15_000, signal, fetchImpl })).data); }
    catch (e) { rethrowCancel(e); skip.add("epss"); notes.push("EPSS score unavailable."); }
  }
  return { cve, via, notes };
}

export async function bulkLookup(rawIds, { signal, fetchImpl, onProgress = noop, pauseMs = 250 } = {}) {
  const ids = [...new Set(rawIds.map(normaliseCveId).filter((x) => CVE_ID.test(x)))].slice(0, 25);
  const skip = new Set(), out = [];
  for (let i = 0; i < ids.length; i++) {
    onProgress(`Looking up ${ids[i]} (${i + 1}/${ids.length})…`);
    try { const r = await lookupCve(ids[i], { signal, fetchImpl, order: ["circl", "nvd"], skip }); out.push({ id: ids[i], ...r }); }
    catch (e) { rethrowCancel(e); out.push({ id: ids[i], error: String((e && e.message) || e).slice(0, 300) }); }
    if (i < ids.length - 1) await sleep(pauseMs, signal);
  }
  return out;
}

export async function searchCves(keyword, { signal, fetchImpl } = {}) {
  const k = String(keyword ?? "").trim();
  if (k.length < 3 || k.length > 100) throw new Error("Type between 3 and 100 characters");
  let json;
  try { json = await fetchLimited(`${NVD_URL}?${new URLSearchParams({ keywordSearch: k, resultsPerPage: "50" })}`, { maxBytes: 20_000_000, timeoutMs: 60_000, signal, fetchImpl }); }
  catch (e) { rethrowCancel(e); throw new Error(describeError(e, "NVD") + " Keyword search needs NVD."); }
  return { cves: nvdToCves(json).sort(byPublishedDesc), total: Number(json && json.totalResults) || 0 };
}

// ---------------------------------------------------------------- ATT&CK (one big download, built in a worker)
const defaultWorker = () => new Worker(scriptURL(new URL("./attack-worker.js", import.meta.url)), { type: "module" });

// `chunks`: the download as received (an array of Uint8Array). Each piece's memory is transferred to the worker, not copied.
export function buildInWorker(chunks, { signal, workerFactory } = {}) {
  return new Promise((resolve, reject) => {
    let w, t, onAbort;
    const finish = (fn) => (v) => { clearTimeout(t); if (signal) signal.removeEventListener("abort", onAbort); try { w && w.terminate(); } catch { /* ignore */ } fn(v); };
    const ok = finish(resolve), bad = finish(reject);
    onAbort = () => bad(new FetchError("cancelled", "Cancelled"));
    if (signal) { if (signal.aborted) return reject(new FetchError("cancelled", "Cancelled")); signal.addEventListener("abort", onAbort, { once: true }); }
    t = setTimeout(() => bad(described("timeout", "Building the ATT&CK data took too long — try again, or close other tabs to free memory.")), 180_000);
    try { w = (workerFactory || defaultWorker)(); } catch { return bad(new Error("Web Workers are not available in this browser")); }
    w.onmessage = (e) => (e.data && e.data.ok ? ok(e.data.data) : bad(new Error((e.data && e.data.error) || "Build failed")));
    w.onerror = () => bad(new Error("The ATT&CK builder crashed (probably out of memory)"));
    // A piece that is a view into a larger or shared buffer is copied first, so every transferred buffer is exactly one piece.
    const own = chunks.map((c) => (c.byteOffset === 0 && c.byteLength === c.buffer.byteLength ? c : c.slice()));
    const buffers = own.map((c) => c.buffer);
    w.postMessage({ chunks: own }, [...new Set(buffers)]);
  });
}

export async function downloadAttack({ signal, onProgress = noop, fetchImpl, workerFactory } = {}) {
  let chunks;
  try {
    chunks = await fetchLimited(ATTACK_URL, {
      as: "chunks", maxBytes: 250_000_000, timeoutMs: 300_000, signal, fetchImpl,
      onProgress: (got, total) => onProgress(`Downloading ATT&CK… ${mb(got)}${total ? ` of ${mb(total)}` : ""} MB`),
    });
  } catch (e) { rethrowCancel(e); throw wrap(e, "The MITRE ATT&CK data on GitHub"); }
  onProgress("Building the ATT&CK lookup (a few seconds)…");
  const data = await buildInWorker(chunks, { signal, workerFactory });
  chunks = null;
  await kvSet("attack", { savedAt: Date.now(), via: "MITRE ATT&CK (GitHub)", version: data.version, data });
  return { version: data.version, techniques: Object.keys(data.techniques).length };
}

// ---------------------------------------------------------------- "Test sources"
export async function runProbes({ ids, fetchImpl, onResult = noop } = {}) {
  const out = {};
  for (const s of SOURCES.filter((x) => !ids || ids.includes(x.id))) { out[s.id] = await probeSource(s, { fetchImpl }); onResult(s.id, out[s.id]); }
  return out;
}
