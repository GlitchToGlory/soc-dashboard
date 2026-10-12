// Pure helper functions (no DOM access) so they can be unit-tested.

// Upper bound for any text a user pastes into a tool. Keeps the tab responsive even with hostile input.
export const MAX_TEXT = 1_000_000;
export const capText = (s, n = MAX_TEXT) => String(s ?? "").slice(0, n);

export const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0, "": -1 };

export function fmtUTC(iso) {
  if (!iso) return "—";
  const d = new Date(iso.length === 10 ? iso + "T00:00:00Z" : iso);
  if (isNaN(d)) return "—";
  const p = (n) => String(n).padStart(2, "0");
  const date = `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
  return iso.length === 10 ? date : `${date} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

export function timeAgo(iso, now = Date.now()) {
  const t = typeof iso === "number" ? iso : new Date(iso.length === 10 ? iso + "T00:00:00Z" : iso).getTime();
  if (isNaN(t)) return "";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export const isHttpUrl = (u) => /^https?:\/\//i.test(u || "");

// ---------- IOC handling ----------
export function refang(s) {
  return s
    .replace(/hxxp/gi, "http")
    .replace(/\[\s*:\/\/\s*\]/g, "://")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[\s*@\s*\]|\(\s*at\s*\)|\[at\]/gi, "@")
    .replace(/\[\s*\/\s*\]/g, "/");
}

export function defang(s) {
  return s
    .replace(/https?:\/\//gi, (m) => m.replace(/^http/i, "hxxp").replace("://", "[://]"))
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

const uniq = (a) => [...new Set(a)];
const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const URLS = /\bhttps?:\/\/[^\s"'<>)\]]{1,2000}/gi;
// Bounded repetition everywhere: unbounded nested quantifiers are quadratic on input like "a.a.a.a…".
const EMAILS = /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z]{2,24}\b/g;
const SHA256 = /\b[a-fA-F0-9]{64}\b/g;
const SHA1 = /\b[a-fA-F0-9]{40}\b/g;
const MD5 = /\b[a-fA-F0-9]{32}\b/g;
const CVES = /\bCVE-\d{4}-\d{4,7}\b/gi;
const DOMAINS = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}[a-z]{2,24}\b/gi;
const FILE_EXT = /\.(?:exe|dll|txt|docx?|xlsx?|pdf|png|jpe?g|gif|js|ps1|bat|cmd|zip|rar|7z|iso|lnk|msi|sys|log|json|xml|html?|php|py|sh)$/i;

export function extractIOCs(raw) {
  const text = refang(capText(raw));
  const urls = uniq(text.match(URLS) || []);
  const emails = uniq(text.match(EMAILS) || []);
  const ips = uniq(text.match(IPV4) || []);
  const sha256 = uniq((text.match(SHA256) || []).map((h) => h.toLowerCase()));
  const sha1 = uniq((text.match(SHA1) || []).map((h) => h.toLowerCase()).filter((h) => !sha256.some((x) => x.includes(h))));
  const md5 = uniq((text.match(MD5) || []).map((h) => h.toLowerCase()).filter((h) => !sha256.some((x) => x.includes(h)) && !sha1.some((x) => x.includes(h))));
  const cves = uniq((text.match(CVES) || []).map((c) => c.toUpperCase()));
  const emailDomains = new Set(emails.map((e) => e.split("@")[1].toLowerCase()));
  const urlHosts = new Set(urls.map((u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } }));
  const domains = uniq((text.match(DOMAINS) || []).map((d) => d.toLowerCase()))
    .filter((d) => !FILE_EXT.test(d) && !/^\d+(\.\d+)+$/.test(d) && !emailDomains.has(d) && !urlHosts.has(d) && !ips.includes(d));
  return { urls, domains, ips, emails, sha256, sha1, md5, cves, emailDomains: [...emailDomains], urlHosts: [...urlHosts].filter(Boolean) };
}

// ---------- Decoders ----------
export function b64decode(s) {
  const clean = capText(s, 4_000_000).trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  const bin = atob(clean + "=".repeat((4 - (clean.length % 4)) % 4));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  // PowerShell -EncodedCommand is UTF-16LE: detect lots of NUL bytes
  const nuls = bytes.filter((b) => b === 0).length;
  const dec = nuls > bytes.length / 4 ? new TextDecoder("utf-16le") : new TextDecoder("utf-8", { fatal: false });
  return dec.decode(bytes);
}
export function b64encode(s) {
  const bytes = new TextEncoder().encode(capText(s, 2_000_000));
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}
export function hexdecode(s) {
  const clean = capText(s, 4_000_000).replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2) throw new Error("Odd number of hex digits");
  const bytes = new Uint8Array(clean.match(/../g).map((h) => parseInt(h, 16)));
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}
export function hexencode(s) {
  return [...new TextEncoder().encode(capText(s, 2_000_000))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------- Time ----------
export function parseTimeInput(v) {
  v = (v || "").trim();
  if (!v) return null;
  if (/^-?\d+(\.\d+)?$/.test(v)) {
    let n = Number(v);
    const len = v.replace(/^-/, "").split(".")[0].length;
    if (len >= 16) n = n / 1e6;        // microseconds -> seconds
    else if (len >= 13) n = n / 1e3;   // milliseconds -> seconds
    return new Date(n * 1000);
  }
  const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(v) ? v : v.replace(" ", "T") + "Z");
  return isNaN(d) ? null : d;
}

// ---------- Templates ----------
export const PLACEHOLDER = /\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g;
export function placeholdersOf(body) {
  const out = [];
  for (const m of body.matchAll(PLACEHOLDER)) if (!out.includes(m[1])) out.push(m[1]);
  return out;
}
export function fillTemplate(body, values) {
  // Own properties only: a placeholder named {{constructor}} or {{__proto__}} must not reach Object.prototype.
  return body.replace(PLACEHOLDER, (m, k) => {
    const v = Object.hasOwn(values, k) ? values[k] : "";
    return typeof v === "string" && v.trim() ? v : `[${k}]`;
  });
}

// ---------- CVE filtering ----------
export function matchesWatchlist(item, words) {
  if (!words.length) return false;
  const hay = `${item.desc || ""} ${(item.products || []).join(" ")} ${item.id || ""}`.toLowerCase();
  return words.some((w) => hay.includes(w));
}

// ---------- Email headers ----------
export function parseHeaders(raw) {
  const text = capText(raw, 500_000).replace(/\r\n/g, "\n").split(/\n\n/)[0]; // headers end at first blank line
  const lines = text.split("\n");
  const headers = [];
  for (const line of lines) {
    if (/^[ \t]+/.test(line) && headers.length) headers[headers.length - 1][1] += " " + line.trim();
    else {
      const i = line.indexOf(":");
      if (i > 0) headers.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
    }
  }
  const all = (n) => headers.filter(([k]) => k.toLowerCase() === n.toLowerCase()).map(([, v]) => v);
  const first = (n) => all(n)[0] || "";
  const addr = (v) => (v.match(/<([^>]+)>/)?.[1] || v.match(/[^\s<>"]+@[^\s<>"]+/)?.[0] || "").toLowerCase();
  const domain = (v) => (addr(v).split("@")[1] || "").toLowerCase();

  const auth = all("Authentication-Results").join(" ; ");
  const pick = (k) => (auth.match(new RegExp(`\\b${k}=(\\w+)`, "i"))?.[1] || (k === "spf" ? first("Received-SPF").match(/^(\w+)/)?.[1] : "") || "").toLowerCase();
  const res = { spf: pick("spf"), dkim: pick("dkim"), dmarc: pick("dmarc") };

  const hops = all("Received").map((v) => {
    const ips = [...new Set(v.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || [])];
    return { text: v.replace(/\s+/g, " "), ips, date: (v.split(";").pop() || "").trim() };
  }).reverse(); // oldest first

  const from = first("From"), replyTo = first("Reply-To"), returnPath = first("Return-Path");
  const flags = [];
  const fd = domain(from);
  if (returnPath && domain(returnPath) && fd && domain(returnPath) !== fd) flags.push(`Return-Path domain (${domain(returnPath)}) differs from From domain (${fd})`);
  if (replyTo && domain(replyTo) && fd && domain(replyTo) !== fd) flags.push(`Reply-To domain (${domain(replyTo)}) differs from From domain (${fd})`);
  for (const [k, v] of Object.entries(res)) if (v && v !== "pass") flags.push(`${k.toUpperCase()} result is "${v}"`);
  for (const [k, v] of Object.entries(res)) if (!v) flags.push(`No ${k.toUpperCase()} result found in headers`);
  if (/^[^<]*@[^<]*<[^>]+>/.test(from)) {
    const shown = from.match(/^"?([^"<]*@[^"<]*)"?\s*</)?.[1]?.trim().toLowerCase();
    if (shown && shown !== addr(from)) flags.push(`Display name contains a different address (${shown})`);
  }
  return {
    summary: [["Subject", first("Subject")], ["From", from], ["Reply-To", replyTo], ["Return-Path", returnPath], ["To", first("To")], ["Date", first("Date")],
      ["Message-ID", first("Message-ID")], ["X-Originating-IP", first("X-Originating-IP")], ["Sender IP (X-Sender-IP)", first("X-Sender-IP")]].filter(([, v]) => v),
    auth: res, hops, flags, headerCount: headers.length,
  };
}

// ---------- CIDR (IPv4) ----------
const ip2int = (ip) => {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) throw new Error(`"${ip}" is not a valid IPv4 address`);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
};
const int2ip = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");

export function cidrInfo(input, testIp = "") {
  const m = String(input).trim().match(/^([\d.]+)\/(\d{1,2})$/);
  if (!m) throw new Error("Enter a CIDR like 10.0.0.0/8");
  const bits = Number(m[2]);
  if (bits > 32) throw new Error("Prefix must be 0–32");
  const ip = ip2int(m[1]);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const net = (ip & mask) >>> 0, bc = (net | (~mask >>> 0)) >>> 0;
  const total = 2 ** (32 - bits);
  const res = {
    network: int2ip(net), broadcast: int2ip(bc), mask: int2ip(mask), wildcard: int2ip(~mask >>> 0),
    first: bits >= 31 ? int2ip(net) : int2ip(net + 1), last: bits >= 31 ? int2ip(bc) : int2ip(bc - 1),
    total, usable: bits >= 31 ? total : total - 2,
  };
  if (testIp.trim()) { const t = ip2int(testIp.trim()); res.contains = t >= net && t <= bc; }
  return res;
}

export function ipClass(ip) {
  try {
    const n = ip2int(ip);
    const inR = (c) => { const i = cidrInfo(c); return n >= ip2int(i.network) && n <= ip2int(i.broadcast); };
    if (inR("10.0.0.0/8") || inR("172.16.0.0/12") || inR("192.168.0.0/16")) return "Private (RFC 1918)";
    if (inR("127.0.0.0/8")) return "Loopback";
    if (inR("169.254.0.0/16")) return "Link-local";
    if (inR("100.64.0.0/10")) return "Carrier-grade NAT";
    if (inR("224.0.0.0/4")) return "Multicast";
    if (inR("192.0.2.0/24") || inR("198.51.100.0/24") || inR("203.0.113.0/24")) return "Documentation range";
    return "Public";
  } catch { return ""; }
}

// ---------- CVSS vector decoder ----------
const V3 = {
  AV: ["Attack Vector", { N: "Network", A: "Adjacent", L: "Local", P: "Physical" }],
  AC: ["Attack Complexity", { L: "Low", H: "High" }],
  PR: ["Privileges Required", { N: "None", L: "Low", H: "High" }],
  UI: ["User Interaction", { N: "None", R: "Required" }],
  S: ["Scope", { U: "Unchanged", C: "Changed" }],
  C: ["Confidentiality", { N: "None", L: "Low", H: "High" }],
  I: ["Integrity", { N: "None", L: "Low", H: "High" }],
  A: ["Availability", { N: "None", L: "Low", H: "High" }],
};
const V4 = {
  AV: V3.AV, AC: V3.AC, AT: ["Attack Requirements", { N: "None", P: "Present" }], PR: V3.PR,
  UI: ["User Interaction", { N: "None", P: "Passive", A: "Active" }],
  VC: ["Vulnerable System Confidentiality", V3.C[1]], VI: ["Vulnerable System Integrity", V3.I[1]], VA: ["Vulnerable System Availability", V3.A[1]],
  SC: ["Subsequent System Confidentiality", V3.C[1]], SI: ["Subsequent System Integrity", V3.I[1]], SA: ["Subsequent System Availability", V3.A[1]],
};

export function decodeCvss(vector) {
  if (String(vector || "").length > 500) throw new Error("That doesn't look like a CVSS vector (too long)");
  const parts = String(vector || "").trim().split("/");
  const ver = parts[0].match(/^CVSS:(\d\.\d)$/);
  if (!ver) throw new Error("Vector must start with CVSS:3.0, CVSS:3.1 or CVSS:4.0");
  const table = ver[1] === "4.0" ? V4 : V3;
  const rows = [];
  for (const p of parts.slice(1)) {
    const [k, v] = p.split(":");
    if (!Object.hasOwn(table, k)) { rows.push([k, v, "(temporal / environmental or unknown metric)"]); continue; }
    rows.push([table[k][0], table[k][1][v] || v, k + ":" + v]);
  }
  return { version: ver[1], rows };
}
