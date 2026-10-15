// Browser storage for fetched data (IndexedDB). Written only when you fetch something; read once at start-up.
// If IndexedDB is unavailable (some private-browsing modes) it falls back to memory for this session only.
const DB = "soc-dashboard", STORE = "kv";
let dbp = null;
const mem = new Map();
export const storage = { persistent: true };

function open() {
  const p = new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") return reject(new Error("IndexedDB unavailable"));
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => { r.result.createObjectStore(STORE); };
    r.onsuccess = () => {
      const d = r.result;
      // The browser can close a long-lived connection on its own (Safari does for idle or background tabs, others under storage
      // pressure), and another tab may need to upgrade or delete the database. Forget it either way so the next call reopens.
      d.onclose = () => { if (dbp === p) dbp = null; };
      d.onversionchange = () => { d.close(); if (dbp === p) dbp = null; };
      resolve(d);
    };
    r.onerror = () => reject(r.error || new Error("IndexedDB error"));
    r.onblocked = () => reject(new Error("IndexedDB blocked"));
  });
  return p;
}
const db = () => (dbp ||= open());

async function tx(mode, fn, retried = false) {
  let d;
  try { d = await db(); } catch { storage.persistent = false; return null; }
  let t;
  try { t = d.transaction(STORE, mode); }
  catch (e) {
    // "The database connection is closing": the connection was closed after we cached it (see open()). Reopen once and retry.
    if (e && e.name === "InvalidStateError" && !retried) { dbp = null; return tx(mode, fn, true); }
    throw e;
  }
  return new Promise((resolve, reject) => {
    const s = t.objectStore(STORE);
    let out;
    const r = fn(s);
    if (r) r.onsuccess = () => { out = r.result; };
    t.oncomplete = () => resolve(out);
    t.onerror = () => reject(t.error || new Error("storage error"));
    t.onabort = () => reject(t.error || new Error("storage aborted"));
  });
}

export async function kvGet(key) {
  const v = await tx("readonly", (s) => s.get(key));
  return storage.persistent ? v : mem.get(key);
}
export async function kvSet(key, value) {
  const r = await tx("readwrite", (s) => s.put(value, key));
  if (!storage.persistent) mem.set(key, value);
  return r;
}
export async function kvClear() {
  await tx("readwrite", (s) => s.clear());
  mem.clear();
}
export function _resetForTests() { dbp = null; mem.clear(); storage.persistent = true; }
