// Service worker: caches the app's own files so it opens instantly and works offline. It never touches fetched data
// (that lives in IndexedDB) and never intercepts cross-origin requests.
//
// >>> After you change ANY file in js/, css/, icons/ or index.html, change BUILD below. <<<
// A new BUILD creates a new cache, installs it in the background, and the page reloads once. The test suite fails if a
// file is missing from SHELL_FILES, so offline loading of every page is guaranteed.
const BUILD = "2026-10-15.10";
const SHELL = `soc-shell-${BUILD}`;
const SHELL_FILES = [
  "./", "index.html", "css/styles.css", "manifest.webmanifest", "icons/icon-192.png", "icons/icon-512.png", "icons/icon-maskable-512.png",
  "js/app.js", "js/ui.js", "js/lib.js", "js/state.js", "js/store.js", "js/sanitize.js", "js/tasks.js", "js/net.js", "js/live.js", "js/convert.js",
  "js/live-ui.js", "js/attack-build.js", "js/attack-worker.js", "js/attack-lib.js",
  "js/views-feed.js", "js/views-live.js", "js/views-attack.js", "js/views-templates.js", "js/views-playbooks.js", "js/views-toolkit.js", "js/views-reference.js",
  "js/templates.js", "js/kql.js", "js/playbooks.js", "js/refdata.js", "js/trusted.js",
];

self.addEventListener("install", (e) => {
  // A new build must never be assembled from a mix of old and new files. cache:"no-store" skips the browser's HTTP cache, and the
  // ?v=BUILD query skips GitHub Pages' CDN, which can keep serving the previous copy of a file for minutes after a deploy.
  // Each file is stored under its plain URL, which is what the page requests.
  e.waitUntil(
    caches.open(SHELL)
      .then((c) => Promise.all(SHELL_FILES.map(async (f) => {
        const res = await fetch(`${f}?v=${encodeURIComponent(BUILD)}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`${f}: HTTP ${res.status}`);
        await c.put(f, res);
      })))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      // Only this app's own older caches: <user>.github.io is one origin shared by all of the account's Pages sites, so a plain
      // "delete everything else" would also wipe the other sites' caches.
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith("soc-shell-") && k !== SHELL).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  if (new URL(req.url).origin !== self.location.origin) return;     // fetched-data requests go straight to the network, never through here
  e.respondWith(
    caches.match(req, { cacheName: SHELL, ignoreSearch: req.mode === "navigate" }).then((hit) => hit || fetch(req))
  );
});
