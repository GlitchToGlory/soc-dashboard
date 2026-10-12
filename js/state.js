import { store } from "./ui.js";
import { kvGet, storage } from "./store.js";
import { cleanCves, cleanKev, cleanNews, cleanAttack } from "./sanitize.js";

export const state = {
  cves: [], kev: [], news: [],
  meta: { fetched: {}, via: {}, note: {} },      // when / where each dataset came from
  kevSet: new Set(),
  ref: Date.now(),                                // "now" for freshness windows
  prefill: null,                                  // {id, values} handed from a CVE to the Templates page
  watch: store.get("watch", []),
  attack: null,                                   // loaded lazily (a few MB)
  attackState: "idle",                            // idle | loading | missing | ready
  attackMeta: null,
};

export function setWatch(words) {
  state.watch = words;
  store.set("watch", words);
}

const rec = (r) => (r && typeof r === "object" ? r : null);

export async function loadAll() {
  const [c, k, n] = await Promise.all([kvGet("cves").catch(() => null), kvGet("kev").catch(() => null), kvGet("news").catch(() => null)]);
  const C = rec(c), K = rec(k), N = rec(n);
  state.cves = cleanCves(C && C.data);
  state.kev = cleanKev(K && K.data && K.data.items);
  state.news = cleanNews(N && N.data);
  state.kevSet = new Set(state.kev.map((x) => x.id));
  const ts = (r) => (r && Number.isFinite(r.savedAt) ? r.savedAt : 0);
  const txt = (v, m) => (typeof v === "string" ? v.slice(0, m) : "");
  state.meta = {
    fetched: { cves: ts(C), kev: ts(K), news: ts(N) },
    via: { cves: txt(C && C.via, 60), kev: txt(K && K.via, 60), news: txt(N && N.via, 60) },
    note: { cves: txt(C && C.note, 400) },
    days: C && Number.isFinite(C.days) ? C.days : 0, topic: txt(N && N.topic, 30),
  };
  state.ref = Date.now();
  state.persistent = storage.persistent;
}

export async function loadAttack(force = false) {
  if (state.attack && !force) return state.attack;
  state.attackState = "loading";
  try {
    const r = rec(await kvGet("attack"));
    const d = r ? cleanAttack(r.data) : null;
    if (!d || Object.keys(d.techniques).length < 1 || !d.tactics.length) throw new Error("no ATT&CK data stored yet");
    state.attack = d; state.attackState = "ready";
    state.attackMeta = { savedAt: Number.isFinite(r.savedAt) ? r.savedAt : 0 };
  } catch {
    state.attack = null; state.attackState = "missing"; state.attackMeta = null;
  }
  return state.attack;
}
