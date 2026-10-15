import { h, store } from "./ui.js";
import { state, loadAll } from "./state.js";
import { onStatus, runTask, cancelTask } from "./tasks.js";
import { timeAgo } from "./lib.js";

// Clickjacking guard (GitHub Pages can't send X-Frame-Options / frame-ancestors, so refuse to run inside someone else's frame).
if (window.top !== window.self) {
  document.body.textContent = "This app can't run inside a frame. Open it directly in its own tab or window.";
  throw new Error("framed");
}

const safeDecode = (s) => { try { return decodeURIComponent(s); } catch { return s; } };

// Page code is loaded on demand (dynamic import), so only the page you open is downloaded, parsed and compiled.
const LOADERS = {
  overview: () => import("./views-feed.js").then((m) => m.renderOverview),
  cves: () => import("./views-feed.js").then((m) => m.renderCves),
  kev: () => import("./views-feed.js").then((m) => m.renderKev),
  news: () => import("./views-feed.js").then((m) => m.renderNews),
  lookup: () => import("./views-live.js").then((m) => m.renderLookup),
  sources: () => import("./views-live.js").then((m) => m.renderSources),
  attack: () => import("./views-attack.js").then((m) => m.renderAttack),
  templates: () => import("./views-templates.js").then((m) => m.renderTemplates),
  playbooks: () => import("./views-playbooks.js").then((m) => m.renderPlaybooks),
  toolkit: () => import("./views-toolkit.js").then((m) => m.renderToolkit),
  reference: () => import("./views-reference.js").then((m) => m.renderReference),
};
const DATA_ROUTES = new Set(["overview", "cves", "kev", "news", "lookup"]);                        // need the stored feed data
const REDRAW_AFTER_TASK = new Set(["overview", "cves", "kev", "news", "attack", "sources"]);       // pages that show fetched data (never the ones with forms)

const app = document.getElementById("app");
const routeName = () => {
  const first = safeDecode(location.hash.replace(/^#\/?/, "").split("/")[0]);
  return Object.hasOwn(LOADERS, first) ? first : "overview";       // Object.hasOwn: "#/constructor" must not reach Object.prototype
};

let dataReady = loadAll().catch(() => {});
let renderToken = 0;

async function render() {
  const token = ++renderToken;
  const parts = location.hash.replace(/^#\/?/, "").split("/").map(safeDecode);
  const name = routeName();
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === name));
  document.body.dataset.wide = name === "attack" && !parts[1] ? "1" : "0";   // the ATT&CK matrix tab (#/attack) gets the full width
  let view;
  try {
    const [fn] = await Promise.all([LOADERS[name](), DATA_ROUTES.has(name) ? dataReady : null]);
    if (token !== renderToken) return;                              // the user navigated again while this page was loading
    view = fn(parts);
  } catch (e) {
    if (token !== renderToken) return;
    console.error(e);
    view = h("div", { class: "empty err" }, `Something went wrong rendering this page: ${e.message}`);
  }
  app.replaceChildren(view);
  window.scrollTo(0, 0);
}

// ---------------------------------------------------------------- header line + banner
function updateChrome() {
  const label = document.getElementById("updated");
  const banner = document.getElementById("banner");
  const f = state.meta.fetched;
  const bits = [["KEV", f.kev], ["CVEs", f.cves], ["News", f.news]].filter(([, t]) => t).map(([n, t]) => `${n} ${timeAgo(t)}`);
  label.textContent = bits.length ? `Fetched: ${bits.join(" · ")}` : "";
  const msgs = [];
  if (!bits.length) msgs.push("No data fetched yet. Nothing is downloaded until you press ↻ Fetch all feeds (or a Fetch button on a page).");
  else if (f.cves && Date.now() - f.cves > 3 * 86_400_000) msgs.push("The CVE list is more than 3 days old — press ↻ Fetch all feeds for the latest.");
  if (state.persistent === false) msgs.push("This browser blocked saving data, so fetched data is kept in memory for this session only.");
  banner.hidden = msgs.length === 0;
  banner.textContent = msgs.join(" ");
}

// ---------------------------------------------------------------- status bar for fetch tasks
const live = document.getElementById("live");
const liveMsg = document.getElementById("live-msg");
const liveCancel = document.getElementById("live-cancel");
const refreshBtn = document.getElementById("refresh");
liveCancel.addEventListener("click", cancelTask);
document.getElementById("live-close").addEventListener("click", () => { live.hidden = true; });

onStatus(async (s) => {
  live.hidden = false;
  liveMsg.textContent = s.message || "";
  live.classList.toggle("err", s.running === false && s.ok === false);
  live.classList.toggle("ok", s.running === false && s.ok === true);
  liveCancel.hidden = !s.running;
  document.body.dataset.busy = s.running ? "1" : "0";
  refreshBtn.textContent = s.running ? "Fetching…" : "↻ Fetch all feeds";
  if (s.running === false) {
    updateChrome();
    if (REDRAW_AFTER_TASK.has(routeName())) await render();
  }
});

// ---------------------------------------------------------------- quick lookup
async function quickLookup(raw) {
  const v = raw.trim();
  if (!v) return;
  const { normaliseId } = await import("./attack-lib.js");
  const id = normaliseId(v);
  if (id && !id.startsWith("TA") && !id.startsWith("DET")) { location.hash = `#/attack/${id}`; return; }
  if (/^CVE-\d{4}-\d{4,7}$/i.test(v)) { location.hash = `#/lookup/${v.toUpperCase()}`; return; }
  const { atk } = await import("./views-attack.js");
  atk.q = v;
  if (location.hash === "#/attack") await render(); else location.hash = "#/attack";
}

function applyTheme(t) { document.documentElement.dataset.theme = t; }
applyTheme(store.get("theme", matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
document.getElementById("theme").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  applyTheme(next); store.set("theme", next);
});
// ---------------------------------------------------------------- side nav: collapses to icons on wide screens, a drawer on narrow ones
const navToggle = document.getElementById("nav-toggle");
const scrim = document.getElementById("scrim");
const narrow = matchMedia("(max-width: 900px)");
function syncNavToggle() {
  const open = narrow.matches ? document.body.classList.contains("nav-open") : !document.body.classList.contains("nav-collapsed");
  const label = `${open ? "Collapse" : "Expand"} navigation`;
  navToggle.setAttribute("aria-expanded", String(open));
  navToggle.setAttribute("aria-label", label);
  navToggle.title = label;
  scrim.hidden = !(narrow.matches && open);
}
function closeDrawer() { document.body.classList.remove("nav-open"); syncNavToggle(); }
document.body.classList.toggle("nav-collapsed", store.get("navCollapsed", false));
navToggle.addEventListener("click", () => {
  if (narrow.matches) document.body.classList.toggle("nav-open");
  else store.set("navCollapsed", document.body.classList.toggle("nav-collapsed"));
  syncNavToggle();
});
scrim.addEventListener("click", closeDrawer);
document.getElementById("nav").addEventListener("click", (e) => { if (narrow.matches && e.target.closest("a")) closeDrawer(); });
window.addEventListener("keydown", (e) => { if (e.key === "Escape" && document.body.classList.contains("nav-open")) closeDrawer(); });
narrow.addEventListener("change", closeDrawer);
syncNavToggle();

refreshBtn.addEventListener("click", () => { runTask("update"); });
const quick = document.getElementById("quick");
quick.addEventListener("keydown", (e) => { if (e.key === "Enter") { const v = quick.value; quick.value = ""; return quickLookup(v); } });
window.addEventListener("hashchange", render);
window.addEventListener("keydown", (e) => { if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "")) { e.preventDefault(); quick.focus(); } });
window.addEventListener("data-cleared", async () => { state.attack = null; state.attackState = "idle"; await loadAll(); updateChrome(); await render(); });

dataReady.then(updateChrome);
render();                                // the first paint does not wait for the stored data unless the page needs it

// ---------------------------------------------------------------- service worker (app files only; fetched data lives in IndexedDB)
function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  const hadController = !!navigator.serviceWorker.controller;
  let reloaded = false;
  // After an app update the new service worker takes over; reload once so the page and its cached modules are the same version.
  navigator.serviceWorker.addEventListener("controllerchange", () => { if (hadController && !reloaded) { reloaded = true; location.reload(); } });
  navigator.serviceWorker.register("sw.js").catch((e) => console.warn("Service worker not registered:", e));
}
if (document.readyState === "complete") setTimeout(registerServiceWorker, 0);
else window.addEventListener("load", () => setTimeout(registerServiceWorker, 0), { once: true });
