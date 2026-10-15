// One-at-a-time, cancellable background jobs started by buttons. The UI listens through onStatus().
import { store } from "./ui.js";
import { describeError } from "./net.js";
import { fetchLatestCves, fetchKev, fetchNews, downloadAttack, TOPICS } from "./live.js";
import { loadAll, loadAttack } from "./state.js";

export const DAY_CHOICES = [1, 3, 7, 14, 30];

export function getSettings() {
  const s = store.get("settings", {}) || {};
  return { days: DAY_CHOICES.includes(s.days) ? s.days : 3, epss: s.epss !== false, topic: Object.hasOwn(TOPICS, s.topic) ? s.topic : "vulnerabilities" };
}
export function saveSettings(patch) { store.set("settings", { ...getSettings(), ...patch }); }

const listeners = new Set();
let current = null;
export const onStatus = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };
const emit = (s) => { for (const f of listeners) f(s); };
export const isBusy = () => !!current;
export const busyName = () => (current ? current.name : "");
export const cancelTask = () => { if (current) current.controller.abort(); };

const pluralise = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

export async function runTask(name, overrides = {}) {
  if (current) return { ok: false, message: "Another fetch is already running." };
  const controller = new AbortController();
  current = { name, controller };
  const signal = controller.signal;
  const s = { ...getSettings(), ...overrides };
  const progress = (message) => emit({ running: true, name, message });
  progress("Starting…");
  const parts = [];
  try {
    if (name === "kev" || name === "update") { progress("Fetching the CISA KEV catalogue…"); const r = await fetchKev({ signal }); parts.push(`${r.count} KEV ${r.count === 1 ? "entry" : "entries"}`); await loadAll(); }
    if (name === "cves" || name === "update") { const r = await fetchLatestCves({ days: s.days, epss: s.epss, signal, onProgress: progress }); parts.push(`${pluralise(r.count, "new CVE")}${r.note ? ` — ${r.note.replace(/\.$/, "")}` : ""}`); await loadAll(); }
    if (name === "news" || name === "update") { progress("Fetching headlines…"); const r = await fetchNews({ topic: s.topic, signal }); parts.push(pluralise(r.count, "headline")); await loadAll(); }
    if (name === "attack") { const r = await downloadAttack({ signal, onProgress: progress }); parts.push(`ATT&CK v${r.version || "?"}: ${pluralise(r.techniques, "technique")}`); await loadAttack(true); }
    const result = { ok: true, name, message: `Done — ${parts.join("; ")}.` };
    emit({ running: false, ...result });
    return result;
  } catch (e) {
    const saved = parts.length ? ` Already saved: ${parts.join("; ")}.` : "";
    const message = e && e.kind === "cancelled" ? (parts.length ? `Cancelled.${saved}` : "Cancelled — nothing was changed.") : `${describeError(e, "The source")}${saved}`;
    const result = { ok: false, name, message };
    emit({ running: false, ...result });
    return result;
  } finally { current = null; }
}
