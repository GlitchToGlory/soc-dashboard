import { h, ext, copyBtn, field, select, debounce, nodes } from "./ui.js";
import { analyseText } from "./urltool.js";
import { extractIOCs, defang, refang, b64decode, b64encode, hexdecode, hexencode, parseTimeInput, timeAgo, parseHeaders, cidrInfo, ipClass, decodeCvss } from "./lib.js";

const enc = encodeURIComponent;
const IOC_SHOW = 300;   // rows drawn per indicator type; a huge paste can't freeze the page ("Copy all" still copies every one)
const IOC_LABELS = [
  ["ips", "IPv4 addresses"], ["domains", "Domains"], ["urls", "URLs"], ["emails", "Email addresses"],
  ["urlHosts", "Hosts found in URLs"], ["emailDomains", "Sender / email domains"],
  ["sha256", "SHA-256"], ["sha1", "SHA-1"], ["md5", "MD5"], ["cves", "CVE IDs"],
];

function lookupLinks(kind, v) {
  if (kind === "ips") return [ext(`https://www.virustotal.com/gui/ip-address/${enc(v)}`, "VT", "btn sm"), ext(`https://www.abuseipdb.com/check/${enc(v)}`, "AbuseIPDB", "btn sm")];
  if (["domains", "urlHosts", "emailDomains"].includes(kind)) return [ext(`https://www.virustotal.com/gui/domain/${enc(v)}`, "VT", "btn sm")];
  if (["sha256", "sha1", "md5"].includes(kind)) return [ext(`https://www.virustotal.com/gui/file/${enc(v)}`, "VT", "btn sm")];
  if (kind === "cves") return [h("a", { class: "btn sm", href: `#/lookup/${enc(v)}` }, "Live lookup"), ext(`https://nvd.nist.gov/vuln/detail/${enc(v)}`, "NVD", "btn sm")];
  return [];
}

function iocCard() {
  const input = h("textarea", { rows: "7", maxlength: "1000000", class: "mono", placeholder: "Paste an email, log excerpt, report or a list of indicators. Defanged IOCs (hxxp, [.]) are handled automatically.", "aria-label": "Text to extract indicators from" });
  const out = h("div", {});
  const defangBox = h("input", { type: "checkbox" });
  defangBox.checked = true;
  let last = null;
  const show = (v) => (defangBox.checked ? defang(v) : v);
  const render = () => {
    if (!last) return;
    const groups = IOC_LABELS.filter(([k]) => last[k].length).map(([k, label]) =>
      h("div", { class: "ioc-group" },
        h("div", { class: "row" }, h("h3", {}, `${label} (${last[k].length})`), copyBtn(() => last[k].map(show).join("\n"), "Copy all")),
        h("ul", { class: "plain" }, last[k].slice(0, IOC_SHOW).map((v) => h("li", {}, h("code", {}, show(v)), copyBtn(() => show(v), "Copy"), lookupLinks(k, v)))),
        last[k].length > IOC_SHOW ? h("p", { class: "small muted" }, `Showing the first ${IOC_SHOW} of ${last[k].length}. “Copy all” copies every one.`) : null));
    out.replaceChildren(...(groups.length ? groups : [h("p", { class: "muted" }, "No indicators found.")]));
  };
  const run = () => { last = extractIOCs(input.value); render(); };
  defangBox.addEventListener("change", render);
  const transform = (fn) => () => { input.value = fn(input.value); };
  return h("section", { class: "card" },
    h("h2", {}, "IOC extractor & defanger"),
    h("p", { class: "small muted" }, "Runs entirely in your browser. “VT” / “AbuseIPDB” links open those sites in a new tab only when you select them."),
    input,
    h("div", { class: "row" },
      h("button", { class: "btn primary", type: "button", onclick: run }, "Extract IOCs"),
      h("button", { class: "btn", type: "button", onclick: transform(defang) }, "Defang text"),
      h("button", { class: "btn", type: "button", onclick: transform(refang) }, "Refang text"),
      h("label", { class: "small" }, defangBox, " Show / copy results defanged")),
    out);
}

function headersCard() {
  const input = h("textarea", { rows: "7", maxlength: "500000", class: "mono", placeholder: "Paste the full raw email headers (in Outlook: File → Properties → Internet headers; or “View message source”).", "aria-label": "Email headers" });
  const out = h("div", {});
  const run = () => {
    if (!input.value.trim()) { out.replaceChildren(); return; }
    const r = parseHeaders(input.value);
    if (!r.headerCount) { out.replaceChildren(h("p", { class: "err" }, "No headers found – paste the raw header block.")); return; }
    const authBadge = (k, v) => h("span", { class: `badge ${v === "pass" ? "low" : v ? "critical" : "unrated"}` }, `${k.toUpperCase()}: ${v || "none found"}`);
    out.replaceChildren(...nodes(
      h("div", { class: "row" }, Object.entries(r.auth).map(([k, v]) => authBadge(k, v))),
      r.flags.length ? h("div", { class: "ioc-group" }, h("h3", {}, "Things to check"), h("ul", { class: "plain" }, r.flags.map((f) => h("li", {}, f)))) : h("p", { class: "muted small" }, "No obvious red flags in the headers parsed."),
      h("table", {}, h("tbody", {}, r.summary.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, h("code", {}, v)))))),
      r.hops.length ? h("div", { class: "ioc-group" }, h("h3", {}, `Delivery path (${r.hops.length} hops, oldest first)`),
        h("ol", { class: "plain" }, r.hops.map((hop) => h("li", {}, hop.ips.length ? h("strong", {}, hop.ips.join(", ") + "  ") : null, h("span", { class: "small muted" }, hop.text.slice(0, 220)))))) : null,
      h("p", { class: "small muted" }, "Headers can be forged below the point where your own mail system added them – trust the topmost hops (closest to you) most.")));
  };
  return h("section", { class: "card" }, h("h2", {}, "Email header analyser"), input,
    h("div", { class: "row" }, h("button", { class: "btn primary", type: "button", onclick: run }, "Analyse headers")), out);
}

function decoderCard() {
  const input = h("textarea", { rows: "4", maxlength: "2000000", class: "mono", placeholder: "Encoded or plain text…", "aria-label": "Input" });
  const output = h("textarea", { rows: "4", class: "mono", readonly: true, "aria-label": "Output" });
  const msg = h("div", { class: "err small" });
  const ops = {
    b64d: ["Base64 decode (UTF-8 / PowerShell UTF-16LE)", b64decode], b64e: ["Base64 encode", b64encode],
    urld: ["URL decode", (s) => decodeURIComponent(s.replace(/\+/g, " "))], urle: ["URL encode", enc],
    hexd: ["Hex decode", hexdecode], hexe: ["Hex encode", hexencode],
  };
  const op = select(Object.entries(ops).map(([k, [t]]) => [k, t]), "b64d", () => run());
  const run = () => {
    msg.textContent = "";
    try { output.value = ops[op.value][1](input.value); } catch (e) { output.value = ""; msg.textContent = `Could not convert: ${e.message}`; }
  };
  input.addEventListener("input", debounce(run, 200));
  return h("section", { class: "card" }, h("h2", {}, "Decoder / encoder"),
    h("div", { class: "row" }, field("Operation", op)), input, msg,
    h("div", { class: "row" }, copyBtn(() => output.value, "Copy output")), output);
}

function timeCard() {
  const input = h("input", { type: "text", placeholder: "Unix seconds / ms, or 2026-10-12 09:30:00", "aria-label": "Timestamp" });
  const tbody = h("tbody", {});
  const msg = h("div", { class: "err small" });
  const run = () => {
    msg.textContent = "";
    const d = parseTimeInput(input.value);
    if (!d) { tbody.replaceChildren(); if (input.value.trim()) msg.textContent = "Could not parse that value."; return; }
    const ms = d.getTime();
    const filetime = (BigInt(ms) + 11644473600000n) * 10000n;
    const rows = [
      ["UTC (ISO 8601)", d.toISOString()], ["Your local time", d.toString()],
      ["Unix seconds", String(Math.floor(ms / 1000))], ["Unix milliseconds", String(ms)],
      ["Windows FILETIME", filetime.toString()], ["Relative", timeAgo(d.toISOString())],
    ];
    tbody.replaceChildren(...rows.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, h("code", {}, v), " ", copyBtn(v, "Copy")))));
  };
  input.addEventListener("input", run);
  return h("section", { class: "card" }, h("h2", {}, "Timestamp converter"),
    h("div", { class: "row" }, input, h("button", { class: "btn", type: "button", onclick: () => { input.value = String(Math.floor(Date.now() / 1000)); run(); } }, "Now")),
    msg, h("table", {}, tbody));
}

function cidrCard() {
  const cidr = h("input", { type: "text", placeholder: "10.0.0.0/8", "aria-label": "CIDR" });
  const test = h("input", { type: "text", placeholder: "IP to test (optional)", "aria-label": "IP to test" });
  const out = h("div", {});
  const run = () => {
    try {
      const r = cidrInfo(cidr.value, test.value);
      const rows = [["Network", r.network], ["Broadcast", r.broadcast], ["Netmask", r.mask], ["Wildcard", r.wildcard], ["First host", r.first], ["Last host", r.last], ["Addresses", r.total.toLocaleString()], ["Usable hosts", r.usable.toLocaleString()]];
      if (test.value.trim()) rows.push(["Test IP", `${test.value.trim()} is ${r.contains ? "INSIDE" : "outside"} this range · ${ipClass(test.value.trim())}`]);
      out.replaceChildren(h("table", {}, h("tbody", {}, rows.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, h("code", {}, v)))))));
    } catch (e) { out.replaceChildren(h("p", { class: "err small" }, e.message)); }
  };
  [cidr, test].forEach((i) => i.addEventListener("input", debounce(run, 150)));
  return h("section", { class: "card" }, h("h2", {}, "CIDR / IP range calculator (IPv4)"), h("div", { class: "row" }, cidr, test), out);
}

function cvssCard() {
  const input = h("input", { type: "text", placeholder: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "aria-label": "CVSS vector" });
  const out = h("div", {});
  const run = () => {
    if (!input.value.trim()) { out.replaceChildren(); return; }
    try {
      const r = decodeCvss(input.value);
      out.replaceChildren(h("p", { class: "small muted" }, `CVSS v${r.version} vector`), h("table", {}, h("tbody", {}, r.rows.map(([k, v, c]) => h("tr", {}, h("th", {}, k), h("td", {}, v), h("td", { class: "muted" }, h("code", {}, c)))))));
    } catch (e) { out.replaceChildren(h("p", { class: "err small" }, e.message)); }
  };
  input.addEventListener("input", debounce(run, 150));
  return h("section", { class: "card" }, h("h2", {}, "CVSS vector decoder"), h("p", { class: "small muted" }, "Paste a vector (shown in the CVE details) for a plain-English breakdown."), input, out);
}

function urlCard() {
  const input = h("textarea", { rows: "4", maxlength: "100000", class: "mono", placeholder: "Paste a link, or several (one per line). Safe Links, Proofpoint and other wrapped links are unwrapped; defanged links (hxxp, [.]) work too.", "aria-label": "Links to analyse" });
  const out = h("div", {});
  const defangBox = h("input", { type: "checkbox" });
  defangBox.checked = true;
  let last = null;
  const show = (v) => (defangBox.checked ? defang(v) : v);
  const RISK = { high: ["High risk", "critical"], medium: ["Suspicious", "high"], low: ["No obvious red flags", "low"], error: ["Not a valid link", "unrated"] };
  const LEVEL = { high: ["High", "critical"], medium: ["Check", "high"], info: ["Info", "unrated"] };
  const table = (rows) => h("table", {}, h("tbody", {}, rows.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, v)))));
  const result = (r) => {
    const [riskLabel, riskCls] = RISK[r.risk];
    const p = r.parts;
    const domain = p && p.domain;
    const isIp = !!domain && /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
    return h("div", { class: "ioc-group url-result" },
      h("div", { class: "line" }, h("span", { class: `badge ${riskCls}` }, riskLabel), h("code", {}, show((p && (p.unicodeHost || p.host)) || r.final).slice(0, 200))),
      r.error ? h("p", { class: "err small" }, r.error) : null,
      r.flags.length ? h("ul", { class: "plain" }, r.flags.map((f) => h("li", { class: "url-flag" }, h("span", { class: `badge ${LEVEL[f.level][1]}` }, LEVEL[f.level][0]), " ", f.text)))
        : (r.error ? null : h("p", { class: "small muted" }, "Nothing suspicious found by these checks. That isn't proof it's safe – check the domain's reputation too.")),
      r.chain.length ? h("div", {}, h("h3", {}, "Unwrapping"), h("ol", { class: "plain small" },
        r.chain.map((c) => h("li", {}, h("strong", {}, c.via), " ", h("code", {}, show(c.url).slice(0, 300)))),
        h("li", {}, h("strong", {}, "Destination"), " ", h("code", {}, show(r.final).slice(0, 1000))))) : null,
      p ? table([
        ["Final link", h("code", {}, show(r.final).slice(0, 1000))],
        domain ? ["Domain (approx.)", h("code", {}, show(domain))] : null,
        p.unicodeHost ? ["Displays as", h("code", {}, show(p.unicodeHost))] : null,
        p.host && p.host !== domain ? ["Full host", h("code", {}, show(p.host))] : null,
        p.port ? ["Port", p.port] : null,
        p.path && p.path !== "/" ? ["Path", h("code", {}, p.path)] : null,
        p.fragment ? ["After # (fragment)", h("code", {}, p.fragment)] : null,
      ].filter(Boolean)) : null,
      r.params.length ? h("div", {}, h("h3", {}, `Query parameters (${r.params.length})`), table(r.params.map((x) => [x.name, [h("code", {}, x.value), x.decoded ? h("div", { class: "small muted" }, `base64 → ${x.decoded}`) : null]]))) : null,
      h("div", { class: "actions" },
        copyBtn(() => show(r.final), "Copy final link"),
        domain ? copyBtn(() => show(domain), "Copy domain") : null,
        domain ? ext(isIp ? `https://www.virustotal.com/gui/ip-address/${enc(domain)}` : `https://www.virustotal.com/gui/domain/${enc(domain)}`, "VT ↗", "btn sm") : null,
        domain ? ext(isIp ? `https://urlscan.io/ip/${enc(domain)}` : `https://urlscan.io/domain/${enc(domain)}`, "urlscan ↗", "btn sm") : null));
  };
  const render = () => {
    if (!last) return;
    out.replaceChildren(...(last.length ? last.map(result) : [h("p", { class: "muted" }, "No links found.")]));
  };
  const run = () => { last = analyseText(input.value); render(); };
  defangBox.addEventListener("change", render);
  return h("section", { class: "card" },
    h("h2", {}, "URL analyser & unwrapper"),
    h("p", { class: "small muted" }, "Unwraps Microsoft Safe Links, Proofpoint, Barracuda and common redirects, then checks the real destination for phishing tricks: lookalike letters, disguised IPs, user@host, brand impersonation, shorteners, risky domains and more. Runs in your browser – the link is never opened. “VT” / “urlscan” send only the domain, and only when you select them."),
    input,
    h("div", { class: "row" },
      h("button", { class: "btn primary", type: "button", onclick: run }, "Analyse"),
      h("label", { class: "small" }, defangBox, " Show / copy results defanged")),
    out);
}

export function renderToolkit() {
  // Tools are listed A-Z by title: CIDR / IP range calculator, CVSS vector decoder, Decoder / encoder, Email header analyser, IOC extractor & defanger,
  // Timestamp converter, URL analyser & unwrapper.
  // (In the two-column grid the order reads left to right, then down.) A new tool should be inserted in its alphabetical place.
  return h("div", {}, h("h1", {}, "Analyst toolkit"),
    h("div", { class: "grid two" }, cidrCard(), cvssCard(), decoderCard(), headersCard(), iocCard(), timeCard(), urlCard()));
}
