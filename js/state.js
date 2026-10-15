import { store } from "./ui.js";
import { kvGet, storage } from "./store.js";
import { cleanCves, cleanKev, cleanNews, cleanAttack } from "./sanitize.js";

export const state = {
  cves: [], kev: [], news: [],
  meta: { fetched: {}, via: {}, note: {}, days: 0, topic: "" },   // when / where each dataset came from
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

const ts = (r) => (r && Number.isFinite(r.savedAt) ? r.savedAt : 0);
const txt = (v, m) => (typeof v === "string" ? v.slice(0, m) : "");

// Reads the stored feeds back into `state`. Pass the keys that just changed (e.g. ["kev"] after a KEV fetch) so the other
// datasets aren't read and re-checked again for nothing; with no argument everything is (re)loaded.
export async function loadAll(keys = ["cves", "kev", "news"]) {
  const want = new Set(keys);
  const [C, K, N] = (await Promise.all(["cves", "kev", "news"].map((k) => (want.has(k) ? kvGet(k).catch(() => null) : null)))).map(rec);
  const m = state.meta;
  if (want.has("cves")) {
    state.cves = cleanCves(C && C.data);
    m.fetched.cves = ts(C); m.via.cves = txt(C && C.via, 60); m.note.cves = txt(C && C.note, 400);
    m.days = C && Number.isFinite(C.days) ? C.days : 0;
  }
  if (want.has("kev")) {
    state.kev = cleanKev(K && K.data && K.data.items);
    state.kevSet = new Set(state.kev.map((x) => x.id));
    m.fetched.kev = ts(K); m.via.kev = txt(K && K.via, 60);
  }
  if (want.has("news")) {
    state.news = cleanNews(N && N.data);
    m.fetched.news = ts(N); m.via.news = txt(N && N.via, 60); m.topic = txt(N && N.topic, 30);
  }
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
