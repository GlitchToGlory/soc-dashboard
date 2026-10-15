// Tiny DOM helpers. Everything is built with createElement/textContent - never from HTML strings -
// so untrusted feed content (titles, descriptions) can't inject markup or script.
import { isHttpUrl } from "./lib.js";

// Defence in depth on top of "never build HTML from strings": refuse to create elements or attributes that can run code
// or load remote content, even if a future edit accidentally passes untrusted values here.
const BLOCKED_TAGS = new Set(["script", "iframe", "frame", "frameset", "object", "embed", "applet", "link", "meta", "base", "style",
  "svg", "math", "form", "template", "noscript", "img", "video", "audio", "source", "track"]);
const BLOCKED_ATTRS = new Set(["style", "srcdoc", "src", "srcset", "data", "action", "formaction", "xlink:href", "is", "http-equiv"]);
const ATTR_NAME = /^[a-zA-Z][a-zA-Z0-9-]*$/;

export function h(tag, props, ...kids) {
  if (BLOCKED_TAGS.has(String(tag).toLowerCase())) throw new Error(`Blocked element <${tag}>`);
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (/^on/i.test(k)) { if (typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v); /* string handlers are never attached */ }
    else if (k === "href") { if (isHttpUrl(v) || String(v).startsWith("#")) el.setAttribute("href", v); }
    else if (BLOCKED_ATTRS.has(k.toLowerCase()) || !ATTR_NAME.test(k)) continue;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(typeof kid === "object" ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

// Real DOM append()/replaceChildren() print the text "null" for a null argument. Wrap child lists with nodes() to drop empties.
export const nodes = (...list) => list.flat(Infinity).filter((x) => x != null && x !== false);

export const ext = (url, text, cls) =>
  h("a", { href: url, class: cls, target: "_blank", rel: "noopener noreferrer" }, text);

export const badge = (text, cls) => h("span", { class: `badge ${cls}` }, text);

export const store = {
  get(k, d) { try { const v = localStorage.getItem("soc." + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("soc." + k, JSON.stringify(v)); } catch { /* storage unavailable */ } },
  del(k) { try { localStorage.removeItem("soc." + k); } catch { /* ignore */ } },
};

// Values read back from localStorage are untrusted like everything else in browser storage: they may be corrupt, and on
// <user>.github.io every other Pages site of the same account can write them. Each reader checks the shape it expects and
// falls back to a safe default, so a bad value can't break a page.
export const read = {
  bool: (k, d = false) => { const v = store.get(k, d); return typeof v === "boolean" ? v : d; },
  str: (k, max = 200, d = "") => { const v = store.get(k, d); return typeof v === "string" ? v.slice(0, max) : d; },
  oneOf: (k, allowed, d) => { const v = store.get(k, d); return allowed.includes(v) ? v : d; },
  strs: (k, { max = 1000, len = 200, test } = {}) => {
    const v = store.get(k, []);
    return Array.isArray(v) ? v.filter((x) => typeof x === "string" && x.length <= len && (!test || test(x))).slice(0, max) : [];
  },
  obj: (k) => { const v = store.get(k, null); return v && typeof v === "object" && !Array.isArray(v) ? v : {}; },
  objs: (k, max = 500) => { const v = store.get(k, []); return Array.isArray(v) ? v.filter((x) => x && typeof x === "object" && !Array.isArray(x)).slice(0, max) : []; },
};

export function copyBtn(getText, label = "Copy") {
  const b = h("button", { class: "btn sm", type: "button" }, label);
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(typeof getText === "function" ? getText() : getText);
      b.textContent = "Copied ✓";
    } catch { b.textContent = "Copy failed"; }
    setTimeout(() => { b.textContent = label; }, 1500);
  });
  return b;
}

export function debounce(fn, ms = 150) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// A <details> row whose (relatively large) body is only built the first time the row is opened.
export function lazyDetails(summary, buildBody, open = false) {
  const d = h("details", { class: "item" }, summary);
  let built = false;
  const fill = () => { if (!built) { built = true; d.append(buildBody()); } };
  d.addEventListener("toggle", () => { if (d.open) fill(); });
  if (open) { d.open = true; fill(); }
  return d;
}

export const empty = (msg) => h("div", { class: "empty" }, msg);

export function pagedList(items, render, size = 40) {
  if (!items.length) return empty("Nothing matches these filters.");
  const box = h("div", { class: "list" });
  const more = h("button", { class: "btn", type: "button" });
  let shown = 0;
  const step = () => {
    items.slice(shown, shown + size).forEach((i) => box.append(render(i)));
    shown = Math.min(items.length, shown + size);
    more.hidden = shown >= items.length;
    more.textContent = `Show more (${items.length - shown} left)`;
  };
  more.addEventListener("click", step);
  step();
  return h("div", {}, box, more);
}

export function field(label, control, cls = "") {
  return h("label", { class: cls }, label, control);
}

export function select(options, value, onchange) {
  const s = h("select", {}, options.map(([v, t]) => h("option", { value: v }, t)));
  s.value = value;
  s.addEventListener("change", () => onchange(s.value));
  return s;
}

export function download(filename, text, type = "text/markdown") {
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const a = h("a", { href: "#", download: filename });
  a.href = url; // blob: URL set directly (h() only accepts http(s) / # for href)
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);   // generous: slow mobile browsers can still be reading it after 1s
}
