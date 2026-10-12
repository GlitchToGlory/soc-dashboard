// Pure converters: remote API formats -> the app's own record shapes. No network, no DOM.
// Everything that ends up in a record is trimmed, stripped of control / bidi characters, and URLs must be plain http(s).

const BIDI = /[\u200b\u200e\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069\u061c\ufeff]/g;
const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g;
const URL_BAD = /[\s\x00-\x1f\x7f-\x9f\u200b\u200e\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069\u061c\ufeff]/;

export const stripUnsafe = (t) => String(t ?? "").replace(BIDI, "").replace(CONTROL, "");

export function trim(text, n) {
  const t = stripUnsafe(text).replace(/\s+/g, " ").trim();
  if (t.length <= n) return t;
  const cps = [...t];                                      // count code points, not UTF-16 units
  return cps.length <= n ? t : cps.slice(0, n - 1).join("").trimEnd() + "…";
}

export function safeUrl(url, max = 1000) {
  url = String(url ?? "").trim();
  if (!url || url.length > max || URL_BAD.test(url)) return "";
  let p;
  try { p = new URL(url); } catch { return ""; }
  if (!["http:", "https:"].includes(p.protocol) || !p.hostname || p.username || p.password) return "";
  return url;
}

const isoZ = (d) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
const asId = (v) => (typeof v === "string" ? v.trim().toUpperCase() : "");
export const CVE_ID = /^CVE-\d{4}-\d{4,7}$/;

// ------------------------------------------------------------------ NVD API 2.0
export function pickCvss(metrics) {
  for (const [key, ver] of [["cvssMetricV40", "4.0"], ["cvssMetricV31", "3.1"], ["cvssMetricV30", "3.0"], ["cvssMetricV2", "2.0"]]) {
    const arr = metrics && metrics[key];
    if (!Array.isArray(arr) || !arr.length) continue;
    const sorted = [...arr].sort((a, b) => (a && a.type === "Primary" ? 0 : 1) - (b && b.type === "Primary" ? 0 : 1));
    const m = sorted[0] || {};
    const d = m.cvssData || {};
    if (d.baseScore == null || typeof d.baseScore !== "number") continue;
    return { score: d.baseScore, severity: String(d.baseSeverity || m.baseSeverity || "").toUpperCase(), vector: typeof d.vectorString === "string" ? d.vectorString : "", ver };
  }
  return { score: null, severity: "", vector: "", ver: "" };
}

export function cpeProducts(configs) {
  const seen = [];
  const walk = (nodes) => {
    for (const n of Array.isArray(nodes) ? nodes : []) {
      for (const m of Array.isArray(n && n.cpeMatch) ? n.cpeMatch : []) {
        const parts = String((m && m.criteria) || "").split(":");
        if (parts.length > 5 && ["a", "o", "h"].includes(parts[2])) {
          const vp = `${parts[3]}:${parts[4]}`;
          if (!seen.includes(vp)) seen.push(vp);
        }
      }
      walk(n && n.nodes);
    }
  };
  for (const c of Array.isArray(configs) ? configs : []) walk(c && c.nodes);
  return seen.slice(0, 6);
}

export function nvdToCves(json) {
  const out = [];
  for (const v of Array.isArray(json && json.vulnerabilities) ? json.vulnerabilities : []) {
    const c = (v && v.cve) || {};
    const descs = Array.isArray(c.descriptions) ? c.descriptions : [];
    const desc = (descs.find((d) => d && d.lang === "en") || {}).value || "";
    if (typeof desc === "string" && desc.startsWith("** REJECT **")) continue;
    const cv = pickCvss(c.metrics);
    const cwes = [...new Set((Array.isArray(c.weaknesses) ? c.weaknesses : []).flatMap((w) => (Array.isArray(w && w.description) ? w.description : []))
      .map((d) => d && d.value).filter((x) => typeof x === "string" && x.startsWith("CWE-")))].sort();
    const refs = (Array.isArray(c.references) ? c.references : []).map((r) => safeUrl(r && r.url)).filter(Boolean).slice(0, 4);
    out.push({
      id: typeof c.id === "string" ? c.id : "",
      published: c.published ? c.published + "Z" : "", modified: c.lastModified ? c.lastModified + "Z" : "",
      status: typeof c.vulnStatus === "string" ? c.vulnStatus : "",
      desc: trim(desc, 380), cvss: cv.score, sev: cv.severity, vector: cv.vector, cvssVer: cv.ver,
      cwes: cwes.slice(0, 3), products: cpeProducts(c.configurations), refs, epss: null, epssPct: null,
    });
  }
  return out.filter((c) => CVE_ID.test(c.id));
}

// ------------------------------------------------------------------ CVE Record format 5 (used by CIRCL / cve.org)
export function cve5ToCve(rec) {
  const meta = (rec && rec.cveMetadata) || {};
  const cna = (rec && rec.containers && rec.containers.cna) || {};
  const adp = Array.isArray(rec && rec.containers && rec.containers.adp) ? rec.containers.adp : [];
  const id = asId(meta.cveId);
  if (!CVE_ID.test(id)) return null;
  const descs = Array.isArray(cna.descriptions) ? cna.descriptions : [];
  const en = descs.find((d) => d && typeof d.lang === "string" && d.lang.toLowerCase().startsWith("en")) || descs[0] || {};
  // collect every metric block (CNA first, then ADP such as CISA's), then prefer the newest CVSS version
  const blocks = [cna, ...adp].flatMap((c) => (Array.isArray(c && c.metrics) ? c.metrics : []));
  let cv = { score: null, severity: "", vector: "", ver: "" };
  for (const [key, ver] of [["cvssV4_0", "4.0"], ["cvssV3_1", "3.1"], ["cvssV3_0", "3.0"], ["cvssV2_0", "2.0"]]) {
    const m = blocks.map((b) => b && b[key]).find((x) => x && typeof x.baseScore === "number");
    if (m) { cv = { score: m.baseScore, severity: String(m.baseSeverity || "").toUpperCase(), vector: typeof m.vectorString === "string" ? m.vectorString : "", ver }; break; }
  }
  const cwes = [...new Set((Array.isArray(cna.problemTypes) ? cna.problemTypes : []).flatMap((p) => (Array.isArray(p && p.descriptions) ? p.descriptions : []))
    .map((d) => (d && (d.cweId || (/^CWE-\d+/.test(d.description || "") ? d.description.match(/^CWE-\d+/)[0] : ""))) || "").filter((x) => /^CWE-\d+$/.test(x)))].sort();
  const products = [...new Set((Array.isArray(cna.affected) ? cna.affected : []).map((a) => (a && a.vendor && a.product ? `${a.vendor}:${a.product}`.toLowerCase().replace(/\s+/g, "_") : "")).filter(Boolean))].slice(0, 6);
  const refs = (Array.isArray(cna.references) ? cna.references : []).map((r) => safeUrl(r && r.url)).filter(Boolean).slice(0, 4);
  const stamp = (s) => (typeof s === "string" && s ? (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : s + "Z") : "");
  return {
    id, published: stamp(meta.datePublished), modified: stamp(meta.dateUpdated), status: typeof meta.state === "string" ? meta.state : "",
    desc: trim(en.value, 380), cvss: cv.score, sev: cv.severity, vector: cv.vector, cvssVer: cv.ver,
    cwes: cwes.slice(0, 3), products, refs, epss: null, epssPct: null,
  };
}

// ------------------------------------------------------------------ CISA KEV
export function kevFromJson(data) {
  const vulns = data && data.vulnerabilities;
  if (!Array.isArray(vulns)) throw new Error("not a KEV catalogue");
  const items = vulns.filter((v) => v && typeof v.cveID === "string").map((v) => ({
    id: v.cveID, vendor: String(v.vendorProject || ""), product: String(v.product || ""), name: trim(v.vulnerabilityName, 160),
    added: String(v.dateAdded || ""), due: String(v.dueDate || ""), ransomware: String(v.knownRansomwareCampaignUse || "Unknown"),
    desc: trim(v.shortDescription, 400), action: trim(v.requiredAction, 300), cwes: Array.isArray(v.cwes) ? v.cwes.filter((x) => typeof x === "string") : [],
  }));
  items.sort((a, b) => (a.added < b.added ? 1 : a.added > b.added ? -1 : a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
  return { catalogVersion: String(data.catalogVersion || ""), dateReleased: String(data.dateReleased || ""), count: items.length, items };
}

// ------------------------------------------------------------------ EPSS
export function mergeEpss(cves, rows) {
  const by = new Map(cves.map((c) => [c.id, c]));
  let hit = 0;
  for (const r of Array.isArray(rows) ? rows : []) {
    const t = r && by.get(r.cve);
    const e = Number(r && r.epss), p = Number(r && r.percentile);
    if (t && Number.isFinite(e) && Number.isFinite(p)) { t.epss = Number(e.toFixed(5)); t.epssPct = Number(p.toFixed(4)); hit++; }
  }
  return hit;
}

// ------------------------------------------------------------------ Hacker News (Algolia)
export function hnToNews(json) {
  const out = [];
  for (const h of Array.isArray(json && json.hits) ? json.hits : []) {
    if (!h || typeof h.title !== "string") continue;
    const link = safeUrl(h.url || (h.objectID ? `https://news.ycombinator.com/item?id=${encodeURIComponent(String(h.objectID))}` : ""));
    const d = new Date(h.created_at);
    const title = trim(h.title, 300);
    if (!title || !link) continue;
    out.push({
      title, link, source: "Hacker News", date: isNaN(d) ? "" : isoZ(d),
      summary: `${Number(h.points) || 0} points · ${Number(h.num_comments) || 0} comments on Hacker News`,
    });
  }
  return out;
}
