// URL analyser: unwraps link-protection and redirect wrappers (Safe Links, Proofpoint, ...) and flags common phishing tricks.
// Pure functions: no DOM and no network. The link being analysed is never visited, fetched or made clickable.
import { refang } from "./lib.js";

const MAX_INPUT = 100_000, MAX_URLS = 20, MAX_URL_LEN = 8000, MAX_HOPS = 6;

// ------------------------------------------------------------------ Punycode (RFC 3492): show xn-- labels as the Unicode a victim sees
const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700;
function adapt(delta, num, first) {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / num);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) { delta = Math.floor(delta / (BASE - TMIN)); k += BASE; }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}
const digitOf = (c) => (c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : BASE);
export function punyDecode(input) {
  const out = [];
  let i = 0, n = 128, bias = 72;
  const b = input.lastIndexOf("-");
  for (let j = 0; j < Math.max(b, 0); j++) out.push(input.charCodeAt(j));
  for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new Error("bad punycode");
      const digit = digitOf(input.charCodeAt(idx++));
      if (digit >= BASE) throw new Error("bad punycode");
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
      if (i > 0x7fffffff || w > 0x7fffffff) throw new Error("bad punycode");
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n > 0x10ffff) throw new Error("bad punycode");
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}
export const toUnicodeHost = (host) => host.split(".").map((l) => {
  if (!l.startsWith("xn--")) return l;
  try { return punyDecode(l.slice(4)); } catch { return l; }
}).join(".");

// Letters from other alphabets that look like Latin ones, and the Latin letter each imitates.
const LOOKALIKE = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
  "ӏ": "l", "ѵ": "v", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "ε": "e", "υ": "u", "ѡ": "w",
};
const LATIN = /\p{Script=Latin}/u, OTHER = /[\p{Script=Cyrillic}\p{Script=Greek}]/u;

// ------------------------------------------------------------------ reference lists
// Second-level public suffixes, so "evil.co.uk" counts as the registered domain (a short list: the result is labelled approximate).
const SECOND_LEVEL = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.hk", "com.sg", "com.tw", "com.tr", "com.mx", "com.ar", "co.in", "co.za",
  "co.kr", "com.my", "com.ph", "com.vn", "co.id", "com.ng", "com.pk", "com.sa", "com.eg", "co.il", "com.ua"]);
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
  "rb.gy", "bl.ink", "t.ly", "s.id", "lnkd.in", "qrco.de", "v.gd", "shorte.st", "adf.ly", "bit.do", "urlz.fr", "surl.li", "tinu.be"]);
// Free hosting, tunnels and dynamic DNS: legitimate services, but phishing kits are very often hosted on them.
const FREE_HOSTING = ["ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "workers.dev", "pages.dev", "r2.dev", "glitch.me", "web.app",
  "firebaseapp.com", "netlify.app", "vercel.app", "github.io", "herokuapp.com", "onrender.com", "replit.dev", "repl.co", "azurewebsites.net",
  "blob.core.windows.net", "web.core.windows.net", "storage.googleapis.com", "s3.amazonaws.com", "000webhostapp.com", "weebly.com", "wixsite.com",
  "square.site", "godaddysites.com", "duckdns.org", "ddns.net", "hopto.org", "no-ip.com", "ipfs.io", "dweb.link", "cloudflare-ipfs.com",
  "notion.site", "webflow.io", "framer.website", "translate.goog", "sites.google.com", "firebasestorage.googleapis.com", "appspot.com"];
// TLDs heavily abused for phishing and malware relative to legitimate use.
const RISKY_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "link", "tk", "ml", "ga", "cf", "gq", "work", "support", "rest", "cam", "quest",
  "icu", "buzz", "monster", "sbs", "cfd", "lol", "country", "kim", "men", "loan", "win", "bid", "date", "racing", "review", "download", "stream", "gdn", "cyou", "bond"]);
// Brands phishing pages imitate. Short or common words only count as a whole word ("ups", not "groups").
const BRANDS = ["microsoft", "office365", "outlook", "onedrive", "sharepoint", "azure", "apple", "icloud", "google", "gmail", "amazon", "paypal",
  "docusign", "dropbox", "adobe", "linkedin", "facebook", "instagram", "whatsapp", "netflix", "royalmail", "okta", "coinbase", "binance",
  "metamask", "wellsfargo", "bankofamerica", "barclays", "santander", "natwest", "lloyds", "hsbc", "chase", "dhl", "fedex", "ups", "usps",
  "hmrc", "office", "teams", "zoom", "webex", "aws", "steam", "roblox", "yahoo", "dpd", "evri"];
// Brands owned by the same company count as one, so outlook.office365.com or mail.google.com with "gmail" aren't flagged.
const FAMILY = { office365: "microsoft", outlook: "microsoft", onedrive: "microsoft", sharepoint: "microsoft", azure: "microsoft", office: "microsoft",
  teams: "microsoft", icloud: "apple", gmail: "google", aws: "amazon", instagram: "meta", whatsapp: "meta", facebook: "meta" };
const family = (b) => (b ? FAMILY[b] || b : b);
// Official domains whose name doesn't contain the brand. (Shared hosting such as windows.net storage is deliberately NOT here:
// "outlook" on someone's storage account is a classic phishing setup.)
const OFFICIAL = { "live.com": "microsoft", "msn.com": "microsoft", "bing.com": "microsoft", "skype.com": "microsoft", "xbox.com": "microsoft",
  "office.net": "microsoft", "msft.net": "microsoft", "youtube.com": "google", "fb.com": "meta", "messenger.com": "meta", "me.com": "apple" };
// Brands that are also everyday words or parts of them ("chase" in "purchase") only count as a whole word.
const WHOLE_WORD = new Set(["office", "teams", "zoom", "steam", "chase", "apple", "ups", "aws", "dhl", "dpd", "evri", "usps", "hmrc", "okta", "hsbc", "yahoo", "adobe", "google", "amazon"]);
const EXEC_EXT = /\.(exe|scr|msi|pif|com|js|jse|vbs|vbe|wsf|wsh|hta|ps1|psm1|bat|cmd|lnk|iso|img|vhdx?|jar|apk|dmg|one|docm|xlsm|pptm|xll|appx|msix|reg|cpl)$/i;
const ARCHIVE_EXT = /\.(zip|rar|7z|cab|gz|tgz|ace|arj)$/i;
const LOGIN_WORDS = /(^|[^a-z])(log-?in|sign-?in|verify|verification|account|password|passwd|credential|secure|update|unlock|suspend|wallet|mfa|2fa|auth|webmail|invoice|payment)([^a-z]|$)/i;
const EMAIL = /[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}/;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

// ------------------------------------------------------------------ unwrapping
const param = (u, ...names) => { for (const n of names) { const v = u.searchParams.get(n); if (v) return v; } return null; };
const decodeSafe = (s) => { try { return decodeURIComponent(s); } catch { return s; } };

// Proofpoint URL Defense v3: characters Proofpoint removed are replaced by "*" (one character) or "**X" (a run), and stored base64url-encoded
// after "__;". Follows Proofpoint's own published decoder.
const RUNS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
export function proofpointV3(href) {
  const m = href.match(/\/v3\/__(.{1,8000}?)__;([A-Za-z0-9_-]{0,8000})!/);
  if (!m) return null;
  const url = decodeSafe(m[1]);
  let b64 = m[2].replace(/-/g, "+").replace(/_/g, "/");
  b64 += "=".repeat((4 - (b64.length % 4)) % 4);
  const chars = Array.from(new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))));
  let pos = 0;
  return url.replace(/\*(\*.)?/g, (tok, run) => {
    if (!run) return chars[pos++] ?? "";
    const len = RUNS.indexOf(run[1]) + 2;
    const s = chars.slice(pos, pos + len).join("");
    pos += len;
    return s;
  });
}

const WRAPPERS = [
  { name: "Microsoft Safe Links", test: (h) => /(^|\.)safelinks\.protection\.(outlook\.com|office365\.us)$/.test(h), get: (u) => param(u, "url") },
  { name: "Microsoft Teams Safe Links", test: (h, u) => h === "statics.teams.cdn.office.net" && /safelinks/i.test(u.pathname), get: (u) => param(u, "url") },
  { name: "Proofpoint URL Defense v1", test: (h, u) => h === "urldefense.proofpoint.com" && u.pathname.startsWith("/v1/"), get: (u) => param(u, "u") },
  { name: "Proofpoint URL Defense v2", test: (h, u) => h === "urldefense.proofpoint.com" && u.pathname.startsWith("/v2/"),
    get: (u) => { const v = param(u, "u"); return v && decodeSafe(v.replace(/_/g, "/").replace(/-([0-9A-Fa-f]{2})/g, "%$1")); } },
  { name: "Proofpoint URL Defense v3", test: (h, u) => (h === "urldefense.com" || h === "urldefense.proofpoint.com") && u.pathname.startsWith("/v3/"), get: (u) => proofpointV3(u.href) },
  { name: "Barracuda Link Protection", test: (h) => h === "linkprotect.cudasvc.com", get: (u) => param(u, "a") },
  { name: "Google redirect", test: (h, u) => /^(www\.)?google\.[a-z]{2,3}(\.[a-z]{2})?$/.test(h) && u.pathname === "/url", get: (u) => param(u, "q", "url") },
  { name: "Facebook link shim", test: (h) => ["l.facebook.com", "lm.facebook.com", "l.messenger.com"].includes(h), get: (u) => param(u, "u") },
  { name: "Instagram link shim", test: (h) => h === "l.instagram.com", get: (u) => param(u, "u") },
  { name: "LinkedIn redirect", test: (h, u) => /(^|\.)linkedin\.com$/.test(h) && u.pathname.startsWith("/redir/"), get: (u) => param(u, "url") },
  { name: "Slack redirect", test: (h) => h === "slack-redir.net", get: (u) => param(u, "url") },
  { name: "YouTube redirect", test: (h, u) => /(^|\.)youtube\.com$/.test(h) && u.pathname === "/redirect", get: (u) => param(u, "q") },
  { name: "Mimecast protected link", test: (h) => /(^|\.)protect(-[a-z0-9]+)?\.mimecast\.com$/.test(h), opaque: true },
];

// ------------------------------------------------------------------ helpers
// The host exactly as written in the link (before the browser normalises it), to catch IPs written as one big number or in hex.
function rawHostOf(s) {
  const m = s.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i);
  if (!m) return "";
  let a = m[1];
  a = a.slice(a.lastIndexOf("@") + 1);
  if (!a.startsWith("[")) a = a.replace(/:\d*$/, "");
  return a.toLowerCase();
}
export function registeredDomain(host) {
  if (IPV4.test(host) || host.startsWith("[")) return host;
  const labels = host.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  return labels.slice(SECOND_LEVEL.has(labels.slice(-2).join(".")) ? -3 : -2).join(".");
}
const tokens = (s) => s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
function brandIn(text) {
  const ts = tokens(text);
  return BRANDS.find((b) => ts.some((t) => t === b || (!WHOLE_WORD.has(b) && t.includes(b))));
}
// Text that might hide an email address in base64 (phishing links often carry the target's address so the page can pre-fill it).
function b64Text(s) {
  if (!/^[A-Za-z0-9+/_-]{12,}={0,2}$/.test(s) || s.length > 2000) return "";
  try {
    let t = s.replace(/-/g, "+").replace(/_/g, "/");
    t += "=".repeat((4 - (t.length % 4)) % 4);
    const out = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(atob(t), (c) => c.charCodeAt(0)));
    return /^[\x20-\x7e]+$/.test(out) ? out : "";
  } catch { return ""; }
}

// ------------------------------------------------------------------ analysis of one link
export function analyseUrl(input) {
  const res = { input: String(input).slice(0, MAX_URL_LEN), chain: [], flags: [], final: "", parts: null, params: [], error: "" };
  const flag = (level, text) => res.flags.push({ level, text });
  let cur = res.input.trim();

  for (let hop = 0; hop < MAX_HOPS; hop++) {
    let u;
    try { u = new URL(cur); } catch { break; }
    const w = WRAPPERS.find((x) => x.test(u.hostname, u));
    if (!w) break;
    if (w.opaque) { flag("info", `${w.name}: the real destination is held by Mimecast and can't be revealed offline. Check it in your Mimecast console.`); break; }
    let next = null;
    try { next = w.get(u); } catch { next = null; }
    if (!next || !/^[a-z][a-z0-9+.-]*:/i.test(next.trim())) { flag("medium", `Looks like a ${w.name} link, but it couldn't be unwrapped.`); break; }
    res.chain.push({ via: w.name, url: cur });
    cur = next.trim().slice(0, MAX_URL_LEN);
  }
  res.final = cur;
  if (res.chain.length) flag("info", `Unwrapped ${res.chain.length} layer${res.chain.length > 1 ? "s" : ""} of link protection / redirects.`);

  let u;
  try { u = new URL(cur); } catch { res.error = "This isn't a valid URL."; return finish(res); }
  const scheme = u.protocol.slice(0, -1).toLowerCase();
  if (scheme === "javascript" || scheme === "vbscript") flag("high", `A ${scheme}: link runs code when clicked instead of opening a website.`);
  else if (scheme === "data") flag("high", "A data: link carries a whole page or file inside the link itself – a common way to show a fake login page.");
  else if (scheme === "file" || scheme === "blob") flag("high", `A ${scheme}: link points at a local or in-browser file, not a website.`);
  else if (scheme !== "http" && scheme !== "https") flag("medium", `Unusual link type (${scheme}:).`);
  if (scheme !== "http" && scheme !== "https") {
    res.parts = { scheme, host: "", unicodeHost: "", domain: "", port: "", path: cur.slice(scheme.length + 1, 300), fragment: "" };
    return finish(res);
  }
  if (scheme === "http") flag("info", "Not encrypted (http, not https).");

  const host = u.hostname.toLowerCase();
  const isIp = IPV4.test(host) || host.startsWith("[");
  const unicodeHost = toUnicodeHost(host);
  const domain = registeredDomain(host);
  const labels = host.split(".");
  const tld = isIp ? "" : labels[labels.length - 1];
  const path = decodeSafe(u.pathname);

  if (u.username || u.password) flag("high", `The text before "@" (${decodeSafe(u.username).slice(0, 80)}) is not the website – the link really goes to ${unicodeHost}.`);
  if (isIp) {
    const raw = rawHostOf(cur);
    if (IPV4.test(host) && raw && raw !== host) flag("high", `IP address disguised as "${raw.slice(0, 60)}" – the browser reads it as ${host}.`);
    else flag("medium", "Uses an IP address instead of a domain name.");
  }
  if (!isIp && unicodeHost !== host) {
    flag("medium", `International (IDN) domain – it displays as ${unicodeHost}.`);
    for (const label of unicodeHost.split(".")) {
      if (!OTHER.test(label)) continue;
      const chars = Array.from(label);
      const imitation = chars.map((c) => LOOKALIKE[c] || c).join("");
      if (LATIN.test(label)) flag("high", `"${label}" mixes Latin letters with Cyrillic/Greek lookalikes${/^[a-z0-9-]+$/.test(imitation) ? ` – it imitates "${imitation}"` : ""}.`);
      else if (chars.every((c) => LOOKALIKE[c] || /[0-9-]/.test(c))) flag("high", `"${label}" is made entirely of lookalike letters – it imitates "${imitation}".`);
    }
  }
  if (!isIp && RISKY_TLDS.has(tld)) flag("medium", `The .${tld} domain ending is heavily used for phishing and malware.`);
  if (SHORTENERS.has(host) || SHORTENERS.has(domain)) flag("medium", `Shortened link (${host}) – it hides the real destination.`);
  const hosting = FREE_HOSTING.find((d) => host === d || host.endsWith("." + d));
  if (hosting) flag("info", `Hosted on ${hosting} – free/public hosting that phishing kits often use.`);
  if (u.port && u.port !== "80" && u.port !== "443") flag("medium", `Unusual port (${u.port}).`);
  if (!isIp && labels.length > 4) flag("info", `Many subdomain levels (${labels.length - 2}) – used to push the real domain out of view.`);

  const domainLabel = domain.split(".")[0];
  const domainBrand = isIp ? undefined : OFFICIAL[domain] || brandIn(domainLabel);
  const otherText = `${host.slice(0, Math.max(0, host.length - domain.length))} ${path}`;
  const brand = brandIn(otherText);
  if (brand && family(brand) !== family(domainBrand) && !isIp) flag("medium", `Mentions "${brand}", but the site is ${domain}.`);
  // A brand inside the domain name itself is normal for the brand's own sites ("microsoftonline.com"), but brand-plus-words with
  // hyphens ("paypal-secure-login") or on a high-risk ending is the classic lookalike pattern.
  if (domainBrand && domainLabel !== domainBrand && (domainLabel.includes("-") || RISKY_TLDS.has(tld)))
    flag("medium", `The domain ${domain} uses the "${domainBrand}" name but doesn't look like ${domainBrand}'s own site.`);
  if (LOGIN_WORDS.test(`${host} ${path}`) && !domainBrand) flag("info", "Uses sign-in / account / payment wording.");

  const file = path.split("/").pop() || "";
  if (EXEC_EXT.test(file)) flag("medium", `Downloads a ${file.split(".").pop().toLowerCase()} file (${file.slice(0, 80)}) – a type that can run code.`);
  else if (ARCHIVE_EXT.test(file)) flag("info", `Downloads an archive (${file.slice(0, 80)}).`);

  // Query parameters and fragment: embedded links (redirects) and the recipient's email address (plain or base64).
  const emails = new Set();
  for (const [k, v] of u.searchParams) {
    const decoded = b64Text(v);
    res.params.push({ name: k.slice(0, 100), value: v.slice(0, 500), decoded: decoded.slice(0, 500) });
    if (/^(https?:)?\/\//i.test(v.trim())) flag("medium", `Parameter "${k.slice(0, 40)}" contains another link (${v.trim().slice(0, 120)}) – possible open redirect.`);
    const e = (v.match(EMAIL) || decoded.match(EMAIL) || [])[0];
    if (e) emails.add(e);
    if (res.params.length >= 50) break;
  }
  const frag = decodeSafe(u.hash.slice(1));
  for (const piece of frag.split(/[&=/?#]/)) { const e = (piece.match(EMAIL) || b64Text(piece).match(EMAIL) || [])[0]; if (e) emails.add(e); }
  const pathEmail = path.match(EMAIL);
  if (pathEmail) emails.add(pathEmail[0]);
  if (emails.size) flag("medium", `Contains an email address (${[...emails].slice(0, 3).join(", ")}) – targeted links pre-fill or track the recipient.`);
  if (/%25[0-9a-f]{2}/i.test(cur)) flag("info", "Double-encoded characters (%25…) – sometimes used to slip past filters.");
  if (cur.length > 300) flag("info", `Very long link (${cur.length} characters).`);

  res.parts = { scheme, host, unicodeHost: unicodeHost !== host ? unicodeHost : "", domain, port: u.port, path: path.slice(0, 500), fragment: frag.slice(0, 300) };
  return finish(res);
}

const ORDER = { high: 0, medium: 1, info: 2 };
function finish(res) {
  res.flags.sort((a, b) => ORDER[a.level] - ORDER[b.level]);
  res.risk = res.error ? "error" : res.flags.some((f) => f.level === "high") ? "high" : res.flags.some((f) => f.level === "medium") ? "medium" : "low";
  return res;
}

// ------------------------------------------------------------------ input: one or more links in pasted text
// Drop sentence punctuation stuck to the end of a pasted link, but keep a closing bracket that belongs to it ("void(0)", wiki links).
function trimTrailing(s) {
  for (;;) {
    const t = s.replace(/[.,;:!?'"\]]+$/, "");
    const opens = (t.match(/\(/g) || []).length, closes = (t.match(/\)/g) || []).length;
    const next = t.endsWith(")") && closes > opens ? t.slice(0, -1) : t;
    if (next === s) return s;
    s = next;
  }
}
export function findUrls(text) {
  const t = refang(String(text ?? "").slice(0, MAX_INPUT));
  const out = [];
  for (const line of t.split(/\r?\n/)) {
    const found = line.match(/\b(?:[a-z][a-z0-9+.-]{1,15}:\/\/|(?:javascript|vbscript|data):)[^\s"'<>]{1,8000}/gi);
    if (found) out.push(...found.map(trimTrailing));
    else if (/^\s*(?:www\.)?(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}(?::\d{1,5})?(?:[/?#]\S*)?\s*$/i.test(line)) out.push("http://" + line.trim());
  }
  return [...new Set(out)].slice(0, MAX_URLS);
}
export const analyseText = (text) => findUrls(text).map(analyseUrl);
