// Trust boundary: everything read back from browser storage passes through here before any view sees it.
// Unexpected types are coerced to safe defaults, lengths are capped, URLs must be http(s), and map keys must look like real IDs.
// A corrupt or tampered record can therefore degrade a page, but never break the app or smuggle in odd values.
import { isHttpUrl } from "./lib.js";

const str = (v, max = 2000) => (typeof v === "string" ? v.slice(0, max) : "");
const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const strs = (v, n = 20, max = 500) => (Array.isArray(v) ? v.filter((x) => typeof x === "string").slice(0, n).map((x) => x.slice(0, max)) : []);
const url = (v) => (isHttpUrl(str(v, 1000)) ? str(v, 1000) : "");
export const ID = /^(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|M\d{4}|TA\d{4})$/;
const objs = (v, max) => (Array.isArray(v) ? v.filter((x) => x && typeof x === "object" && !Array.isArray(x)).slice(0, max) : []);

export function cleanCves(list) {
  return objs(list, 5000).map((c) => ({
    id: str(c.id, 40), published: str(c.published, 40), modified: str(c.modified, 40), status: str(c.status, 40),
    desc: str(c.desc, 2000), cvss: num(c.cvss), sev: str(c.sev, 12).toUpperCase(), vector: str(c.vector, 200), cvssVer: str(c.cvssVer, 5),
    cwes: strs(c.cwes, 5, 20), products: strs(c.products, 6, 100), refs: strs(c.refs, 6, 1000).filter(isHttpUrl),
    epss: num(c.epss), epssPct: num(c.epssPct), kev: c.kev === true,
  })).filter((c) => c.id);
}

export function cleanKev(list) {
  return objs(list, 5000).map((k) => ({
    id: str(k.id, 40), vendor: str(k.vendor, 200), product: str(k.product, 200), name: str(k.name, 300), added: str(k.added, 10), due: str(k.due, 10),
    ransomware: str(k.ransomware, 20) || "Unknown", desc: str(k.desc, 1000), action: str(k.action, 600), cwes: strs(k.cwes, 5, 20),
  })).filter((k) => k.id);
}

export function cleanNews(list) {
  return objs(list, 1000).map((n) => ({
    title: str(n.title, 400), link: url(n.link), source: str(n.source, 100), date: str(n.date, 40), summary: str(n.summary, 600),
    topics: Array.isArray(n.topics) ? n.topics.filter((t) => typeof t === "string" && /^[a-z]{2,20}$/.test(t)).slice(0, 10) : [],
  })).filter((n) => n.title && n.link);
}

function idMap(obj, build, max = 3000) {
  const out = Object.create(null);                      // no inherited keys like "constructor"
  if (!obj || typeof obj !== "object") return out;
  for (const [k, v] of Object.entries(obj).slice(0, max)) {
    if (ID.test(k) && v && typeof v === "object") out[k] = build(k, v);
  }
  return out;
}

export function cleanAttack(d) {
  if (!d || typeof d !== "object" || !Array.isArray(d.tactics)) return null;
  const idl = (v, n = 400) => strs(v, n, 12).filter((x) => ID.test(x));
  return {
    version: str(d.version, 20), generatedAt: str(d.generatedAt, 40),
    tactics: objs(d.tactics, 40).map((t) => ({ id: str(t.id, 10), short: str(t.short, 60), name: str(t.name, 100), desc: str(t.desc, 600), url: url(t.url) })).filter((t) => t.short),
    techniques: idMap(d.techniques, (k, t) => ({
      id: k, name: str(t.name, 200), tactics: strs(t.tactics, 10, 60), platforms: strs(t.platforms, 20, 40), desc: str(t.desc, 1200), detText: str(t.detText, 800),
      ds: strs(t.ds, 30, 100), sub: idl(t.sub, 60), parent: ID.test(str(t.parent, 12)) ? t.parent : null, url: url(t.url),
      mit: idl(t.mit), groups: idl(t.groups), sw: idl(t.sw),
      det: objs(t.det, 8).map((x) => ({ id: str(x.id, 20), name: str(x.name, 200), url: url(x.url) })),
    })),
    groups: idMap(d.groups, (k, g) => ({ id: k, name: str(g.name, 200), aliases: strs(g.aliases, 20, 100), desc: str(g.desc, 900), tech: idl(g.tech, 1000), sw: idl(g.sw), url: url(g.url) })),
    software: idMap(d.software, (k, s) => ({ id: k, name: str(s.name, 200), type: str(s.type, 10), aliases: strs(s.aliases, 20, 100), platforms: strs(s.platforms, 20, 40),
      desc: str(s.desc, 700), tech: idl(s.tech, 1000), groups: idl(s.groups), url: url(s.url) })),
    mitigations: idMap(d.mitigations, (k, m) => ({ id: k, name: str(m.name, 200), desc: str(m.desc, 600), url: url(m.url),
      tech: objs(m.tech, 1000).filter((x) => ID.test(str(x.id, 12))).map((x) => ({ id: x.id, how: str(x.how, 320) })) })),
  };
}
