// Pure ATT&CK helpers (no DOM).

export const TECH_ID = /\bT\d{4}(?:\.\d{3})?\b/g;

export function normaliseId(s) {
  const m = String(s || "").trim().toUpperCase().match(/^(T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|M\d{4}|TA\d{4}|DET\d{4})$/);
  return m ? m[1] : null;
}

export function kindOf(id) {
  if (/^T\d/.test(id)) return "technique";
  if (/^G\d/.test(id)) return "group";
  if (/^S\d/.test(id)) return "software";
  if (/^M\d/.test(id)) return "mitigation";
  return "other";
}

export function lookup(data, id) {
  return data.techniques[id] || data.groups[id] || data.software[id] || data.mitigations[id] || null;
}

const norm = (s) => (s || "").toLowerCase();

export function searchAttack(data, query, { platform = "all", limit = 40 } = {}) {
  const q = norm(query).trim();
  const out = { techniques: [], groups: [], software: [], mitigations: [] };
  if (!q) return out;
  const exactId = normaliseId(q);
  const terms = q.split(/\s+/).filter(Boolean);
  const hit = (hay) => terms.every((t) => hay.includes(t));

  const score = (name, id, extra) => {
    if (exactId && id === exactId) return 100;
    const n = norm(name);
    if (n === q) return 90;
    if (n.startsWith(q)) return 70;
    if (n.includes(q)) return 60;
    if (hit(norm(`${name} ${id} ${extra}`))) return 30;
    return 0;
  };
  const add = (list, item, sc) => { if (sc > 0) list.push({ item, sc }); };

  for (const t of Object.values(data.techniques)) {
    if (platform !== "all" && !(t.platforms || []).includes(platform)) continue;
    const parent = t.parent ? data.techniques[t.parent]?.name || "" : "";
    const sc = score(`${parent ? parent + ": " : ""}${t.name}`, t.id, `${t.desc}`.slice(0, 300));
    add(out.techniques, t, sc || (exactId && t.id.startsWith(exactId + ".") ? 80 : 0));
  }
  for (const g of Object.values(data.groups)) add(out.groups, g, score(g.name, g.id, (g.aliases || []).join(" ")) || ((g.aliases || []).some((a) => norm(a).includes(q)) ? 65 : 0));
  for (const s of Object.values(data.software)) add(out.software, s, score(s.name, s.id, (s.aliases || []).join(" ")) || ((s.aliases || []).some((a) => norm(a).includes(q)) ? 65 : 0));
  for (const m of Object.values(data.mitigations)) add(out.mitigations, m, score(m.name, m.id, m.desc.slice(0, 200)));

  for (const k of Object.keys(out)) {
    out[k].sort((a, b) => b.sc - a.sc || a.item.name.localeCompare(b.item.name));
    out[k] = { total: out[k].length, items: out[k].slice(0, limit).map((x) => x.item) };
  }
  return out;
}

// Find techniques mentioned in free text: explicit T-IDs plus exact technique names (as whole words).
// Plain indexOf with a manual word-boundary check: no per-technique RegExp to compile, and no lookbehind (Safari < 16.4 lacks it).
const isWordChar = (c) => (c >= 97 && c <= 122) || (c >= 48 && c <= 57);   // a-z, 0-9 (text is lower-cased first)
function hasWord(low, word) {
  for (let i = low.indexOf(word); i !== -1; i = low.indexOf(word, i + 1)) {
    const before = i === 0 ? -1 : low.charCodeAt(i - 1), after = low.charCodeAt(i + word.length);
    if (!isWordChar(before) && !isWordChar(after)) return true;
  }
  return false;
}
export function findTechniquesInText(data, text) {
  text = String(text ?? "").slice(0, 500_000);
  const found = new Map();
  for (const id of (text.toUpperCase().match(TECH_ID) || [])) if (data.techniques[id]) found.set(id, "ID");
  const low = text.toLowerCase();
  for (const t of Object.values(data.techniques)) {
    if (found.has(t.id) || t.name.length < 7) continue;
    if (hasWord(low, t.name.toLowerCase())) found.set(t.id, "name");
  }
  return [...found].map(([id, how]) => ({ id, how, t: data.techniques[id] }));
}

const tacticIndex = new WeakMap();   // one short-name -> name map per loaded dataset, instead of one per call
export function tacticNames(data, t) {
  let byShort = tacticIndex.get(data);
  if (!byShort) { byShort = new Map(data.tactics.map((x) => [x.short, x.name])); tacticIndex.set(data, byShort); }
  return (t.tactics || []).map((s) => byShort.get(s) || s);
}

export function navigatorLayer(data, ids, name = "SOC dashboard selection") {
  const major = String(data.version || "").split(".")[0] || "17";
  return {
    name,
    versions: { attack: major, navigator: "5.1.0", layer: "4.5" },
    domain: "enterprise-attack",
    description: `Exported from the SOC Dashboard on ${new Date().toISOString().slice(0, 10)}`,
    sorting: 0,
    layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true, showAggregatedTechniques: false, countUnscored: false },
    hideDisabled: false,
    techniques: [...ids].sort().map((id) => ({ techniqueID: id, score: 1, color: "#e60d0d", comment: "", enabled: true, showSubtechniques: id.includes(".") })),
    gradient: { colors: ["#ffffff", "#ff6666"], minValue: 0, maxValue: 1 },
    legendItems: [], metadata: [], links: [], showTacticRowBackground: false, tacticRowBackground: "#dddddd", selectTechniquesAcrossTactics: true,
  };
}

// For group/software pages: group used techniques by tactic, ordered like the matrix.
export function groupByTactic(data, ids) {
  const rows = data.tactics.map((tac) => ({ tactic: tac, items: [] }));
  const idx = Object.fromEntries(rows.map((r) => [r.tactic.short, r]));
  const other = { tactic: { short: "?", name: "Other" }, items: [] };
  for (const id of ids) {
    const t = data.techniques[id];
    if (!t) continue;
    const tacs = t.tactics.length ? t.tactics : (t.parent ? data.techniques[t.parent]?.tactics || [] : []);
    if (!tacs.length) other.items.push(t);
    for (const s of tacs) (idx[s] || other).items.push(t);
  }
  return [...rows, other].filter((r) => r.items.length).map((r) => ({ ...r, items: r.items.sort((a, b) => a.id.localeCompare(b.id)) }));
}
