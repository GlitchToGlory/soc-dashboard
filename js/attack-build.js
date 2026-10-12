// Turns MITRE's raw ATT&CK STIX bundle (tens of MB) into the compact structure the app uses (a few MB).
// Pure functions, run inside a Web Worker (attack-worker.js) so the page stays responsive and the big temporary memory is
// returned to the browser when the worker ends. Tactics are read from the data itself (in matrix order) - nothing is hard-coded,
// so ATT&CK reorganisations (new / renamed tactics) are picked up automatically. Revoked / deprecated objects are dropped.
import { stripUnsafe, safeUrl } from "./convert.js";

// Bounded repetition: unbounded [^)]* / [^\]]+ make these quadratic on hostile text such as 50,000 "[" characters.
const CITATION = /\(Citation:[^)]{0,500}\)/g;
const MD_LINK = /\[([^\]]{1,300})\]\((?:https?:\/\/|\/)[^)]{0,500}\)/g;
const CODE_TAG = /<\/?code>/g;
export const ID_RE = /^(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|M\d{4}|TA\d{4})$/;

export function clean(text, n) {
  let t = stripUnsafe(String(text ?? "").slice(0, 50_000));     // pre-cap keeps the regexes below linear on hostile input
  t = t.replace(CITATION, "").replace(MD_LINK, "$1").replace(CODE_TAG, "").replaceAll("\\n", "\n")
    .replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
  if (t.length > n) {
    const cps = [...t];
    if (cps.length > n) t = cps.slice(0, n - 1).join("").trimEnd() + "…";
  }
  return t;
}

function extId(o) {
  for (const r of Array.isArray(o.external_references) ? o.external_references : []) {
    if (r && ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"].includes(r.source_name) && r.external_id) return [String(r.external_id), safeUrl(r.url || "")];
  }
  return ["", ""];
}
const arr = (v) => (Array.isArray(v) ? v : []);
const addUnique = (list, v) => { if (!list.includes(v)) list.push(v); };

export function buildAttack(bundle) {
  const all = arr(bundle && bundle.objects);
  const objs = all.filter((o) => o && !o.revoked && !o.x_mitre_deprecated);

  let version = "";
  for (const o of all) if (o && o.type === "x-mitre-collection") version = String(o.x_mitre_version ?? "") || version;
  if (!version) for (const o of all) if (o && o.type === "x-mitre-matrix" && o.x_mitre_version) version = String(o.x_mitre_version);

  // ---- tactics (matrix order)
  const tacByShort = new Map(), tacByRef = new Map();
  for (const o of objs) {
    if (o.type !== "x-mitre-tactic") continue;
    const [tid, url] = extId(o);
    const t = { id: tid, short: o.x_mitre_shortname ?? "", name: o.name ?? "", desc: clean(o.description, 500), url };
    tacByShort.set(t.short, t); tacByRef.set(o.id, t);
  }
  const order = [];
  for (const o of objs) if (o.type === "x-mitre-matrix") for (const ref of arr(o.tactic_refs)) { const t = tacByRef.get(ref); if (t && !order.includes(t)) order.push(t); }
  for (const t of tacByShort.values()) if (!order.includes(t)) order.push(t);

  // ---- techniques
  const techniques = Object.create(null), refToTid = new Map();
  for (const o of objs) {
    if (o.type !== "attack-pattern") continue;
    const [tid, url] = extId(o);
    if (!ID_RE.test(tid)) continue;
    refToTid.set(o.id, tid);
    techniques[tid] = {
      id: tid, name: o.name ?? "",
      tactics: arr(o.kill_chain_phases).filter((k) => k && k.kill_chain_name === "mitre-attack").map((k) => k.phase_name),
      platforms: arr(o.x_mitre_platforms), desc: clean(o.description, 1000), detText: clean(o.x_mitre_detection, 700), ds: arr(o.x_mitre_data_sources),
      sub: [], parent: null, url, mit: [], groups: [], sw: [], det: [],
    };
  }

  const groups = Object.create(null), software = Object.create(null), mitigations = Object.create(null);
  const refToG = new Map(), refToS = new Map(), refToM = new Map();
  for (const o of objs) {
    const t = o.type;
    if (!["intrusion-set", "malware", "tool", "course-of-action"].includes(t)) continue;
    const [xid, url] = extId(o);
    if (!ID_RE.test(xid)) continue;
    if (t === "intrusion-set") {
      refToG.set(o.id, xid);
      groups[xid] = { id: xid, name: o.name ?? "", aliases: arr(o.aliases).filter((a) => a !== o.name), desc: clean(o.description, 800), tech: [], sw: [], url };
    } else if (t === "malware" || t === "tool") {
      refToS.set(o.id, xid);
      software[xid] = { id: xid, name: o.name ?? "", type: t, aliases: arr(o.x_mitre_aliases).filter((a) => a !== o.name), platforms: arr(o.x_mitre_platforms), desc: clean(o.description, 600), tech: [], groups: [], url };
    } else {
      refToM.set(o.id, xid);
      mitigations[xid] = { id: xid, name: o.name ?? "", desc: clean(o.description, 500), tech: [], url };
    }
  }

  const detections = new Map();
  for (const o of objs) {
    if (o.type === "x-mitre-detection-strategy" || o.type === "x-mitre-data-component") {
      const [xid, url] = extId(o);
      detections.set(o.id, { id: xid, name: o.name ?? "", url });
    }
  }

  // ---- relationships
  for (const r of objs) {
    if (r.type !== "relationship") continue;
    const rt = r.relationship_type, src = r.source_ref ?? "", dst = r.target_ref ?? "";
    if (rt === "subtechnique-of" && refToTid.has(src) && refToTid.has(dst)) {
      techniques[refToTid.get(src)].parent = refToTid.get(dst);
      addUnique(techniques[refToTid.get(dst)].sub, refToTid.get(src));
    } else if (rt === "uses") {
      if (refToTid.has(dst)) {
        const tid = refToTid.get(dst);
        if (refToG.has(src)) { addUnique(groups[refToG.get(src)].tech, tid); addUnique(techniques[tid].groups, refToG.get(src)); }
        else if (refToS.has(src)) { addUnique(software[refToS.get(src)].tech, tid); addUnique(techniques[tid].sw, refToS.get(src)); }
      } else if (refToG.has(src) && refToS.has(dst)) {
        addUnique(groups[refToG.get(src)].sw, refToS.get(dst)); addUnique(software[refToS.get(dst)].groups, refToG.get(src));
      }
    } else if (rt === "mitigates" && refToM.has(src) && refToTid.has(dst)) {
      mitigations[refToM.get(src)].tech.push({ id: refToTid.get(dst), how: clean(r.description, 280) });
      addUnique(techniques[refToTid.get(dst)].mit, refToM.get(src));
    } else if (rt === "detects" && detections.has(src) && refToTid.has(dst)) {
      const d = detections.get(src), list = techniques[refToTid.get(dst)].det;
      if (d.id && !list.some((x) => x.id === d.id && x.name === d.name && x.url === d.url)) list.push(d);
    }
  }
  for (const t of Object.values(techniques)) { t.sub.sort(); t.det = t.det.slice(0, 8); }

  return { version, generatedAt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), tactics: order, techniques, groups, software, mitigations };
}

export function sanityAttack(d) {
  if (d.tactics.length < 10 || Object.keys(d.techniques).length < 100) throw new Error(`unexpected ATT&CK content (${d.tactics.length} tactics, ${Object.keys(d.techniques).length} techniques)`);
  const shorts = new Set(d.tactics.map((t) => t.short));
  const orphans = Object.values(d.techniques).filter((t) => t && !(t.tactics || []).every((s) => shorts.has(s)) && !t.parent);
  if (orphans.length > Object.keys(d.techniques).length * 0.2) throw new Error("too many techniques reference unknown tactics");
}

export function validateAttack(d) {
  if (!d || typeof d !== "object" || !Array.isArray(d.tactics)) throw new Error("unexpected top-level structure");
  for (const key of ["techniques", "groups", "software", "mitigations"]) {
    if (!d[key] || typeof d[key] !== "object") throw new Error(`${key} must be an object`);
    for (const [k, v] of Object.entries(d[key])) {
      if (!ID_RE.test(k) || !v || typeof v !== "object" || v.id !== k || typeof v.name !== "string") throw new Error(`bad ${key} entry ${String(k).slice(0, 20)}`);
      if (v.url && !safeUrl(v.url)) throw new Error(`unsafe URL in ${k}`);
    }
  }
  for (const t of d.tactics) if (!t || typeof t.short !== "string" || typeof t.name !== "string") throw new Error("bad tactic entry");
  sanityAttack(d);
}
