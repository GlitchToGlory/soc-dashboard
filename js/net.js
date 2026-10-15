// The ONLY place the app talks to the internet. Every request is:
//   * HTTPS to a host on the allow-list below (the page's Content-Security-Policy lists exactly the same hosts - a test enforces it)
//   * sent without cookies or credentials, with no referrer
//   * size-capped while streaming (so a hostile or broken server can't fill memory) and time-limited
//   * started only by a click (nothing runs in the background)

export const KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
export const ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
export const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
export const CIRCL_URL = "https://vulnerability.circl.lu/api/vulnerability/";
export const EPSS_URL = "https://api.first.org/data/v1/epss";
export const HN_URL = "https://hn.algolia.com/api/v1/search_by_date";

// `probe` is a cheap request used by the "Test sources" button.
export const SOURCES = [
  { id: "nvd", name: "NIST NVD CVE API", host: "services.nvd.nist.gov", use: "Latest CVEs, CVE details, keyword search", probe: `${NVD_URL}?resultsPerPage=1` },
  { id: "circl", name: "CIRCL Vulnerability-Lookup", host: "vulnerability.circl.lu", use: "CVE details (fallback when NVD is blocked)", probe: `${CIRCL_URL}CVE-2021-44228` },
  { id: "kev", name: "CISA KEV catalogue (GitHub mirror)", host: "raw.githubusercontent.com", use: "Known exploited vulnerabilities", probe: KEV_URL },
  { id: "epss", name: "FIRST EPSS API", host: "api.first.org", use: "Exploit-probability scores", probe: `${EPSS_URL}?cve=CVE-2021-44228` },
  { id: "attack", name: "MITRE ATT&CK data (GitHub)", host: "raw.githubusercontent.com", use: "ATT&CK dataset (one-time download, ~40 MB)", probe: ATTACK_URL },
  { id: "hn", name: "Hacker News search (Algolia)", host: "hn.algolia.com", use: "Security-related news headlines", probe: `${HN_URL}?query=cve&tags=story&hitsPerPage=1` },
];
export const ALLOWED_HOSTS = new Set(SOURCES.map((s) => s.host));

export class FetchError extends Error {
  constructor(kind, message, status = 0) { super(message); this.name = "FetchError"; this.kind = kind; this.status = status; }
}

export function assertAllowed(url) {
  let u;
  try { u = new URL(url); } catch { throw new FetchError("policy", "Invalid URL"); }
  if (u.protocol !== "https:") throw new FetchError("policy", "Only HTTPS is allowed");
  if (u.username || u.password) throw new FetchError("policy", "Credentials in URLs are not allowed");
  if (u.port) throw new FetchError("policy", "Custom ports are not allowed");
  if (!ALLOWED_HOSTS.has(u.hostname)) throw new FetchError("policy", `Host ${u.hostname} is not on the allow-list`);
  return u;
}

const classify = (e, timedOut, signal) => {
  if (e instanceof FetchError) return e;
  if (e && e.name === "AbortError") {
    if (timedOut) return new FetchError("timeout", "The request timed out");
    if (signal && signal.aborted) return new FetchError("cancelled", "Cancelled");
    return new FetchError("cancelled", "Cancelled");
  }
  return new FetchError("blocked", "The browser blocked or could not complete the request");
};

export function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) return reject(new FetchError("cancelled", "Cancelled"));
    const t = setTimeout(() => { if (signal) signal.removeEventListener("abort", onAbort); resolve(); }, ms);
    const onAbort = () => { clearTimeout(t); reject(new FetchError("cancelled", "Cancelled")); };
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * GET a URL with the safety limits above.
 * as: "json" (default) | "text" | "bytes" | "chunks"   — fetchImpl / maxBytes / timeoutMs are overridable (tests, big downloads)
 * Memory: "json" / "text" decode each piece as it arrives and keep no copy of the raw bytes; "chunks" returns the pieces as they
 * came (no joined copy) so a big download can be handed to a worker; only "bytes" builds one contiguous buffer.
 */
export async function fetchLimited(url, { maxBytes = 8_000_000, timeoutMs = 30_000, signal, onProgress, as = "json", fetchImpl, headers } = {}) {
  assertAllowed(url);
  const doFetch = fetchImpl || globalThis.fetch.bind(globalThis);
  const ctl = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; ctl.abort(); }, timeoutMs);
  const onAbort = () => ctl.abort();
  if (signal) {
    if (signal.aborted) { clearTimeout(timer); throw new FetchError("cancelled", "Cancelled"); }
    signal.addEventListener("abort", onAbort, { once: true });
  }
  try {
    let res;
    try {
      res = await doFetch(url, { method: "GET", mode: "cors", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", redirect: "follow", signal: ctl.signal, headers });
    } catch (e) { throw classify(e, timedOut, signal); }
    if (!res.ok) {
      try { await res.body?.cancel(); } catch { /* ignore */ }
      throw new FetchError("http", `HTTP ${res.status}`, res.status);
    }
    const len = Number(res.headers.get("content-length"));
    if (Number.isFinite(len) && len > maxBytes) {
      try { await res.body?.cancel(); } catch { /* ignore */ }
      throw new FetchError("toolarge", `Response is larger than the ${Math.round(maxBytes / 1e6)} MB limit`);
    }
    const total = Number.isFinite(len) ? len : 0;
    const tooLarge = () => new FetchError("toolarge", `Response is larger than the ${Math.round(maxBytes / 1e6)} MB limit`);
    const decode = as === "json" || as === "text";
    const decoder = decode ? new TextDecoder("utf-8") : null;
    const chunks = [], texts = [];
    let got = 0;
    try {
      if (!res.body) {
        const ab = new Uint8Array(await res.arrayBuffer());
        if (ab.byteLength > maxBytes) throw tooLarge();
        got = ab.byteLength;
        if (decode) texts.push(decoder.decode(ab)); else chunks.push(ab);
      } else {
        const reader = res.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          got += value.byteLength;
          if (got > maxBytes) { ctl.abort(); throw tooLarge(); }
          if (decode) texts.push(decoder.decode(value, { stream: true })); else chunks.push(value);
          if (onProgress) onProgress(got, total);
        }
        if (decode) texts.push(decoder.decode());
      }
    } catch (e) { throw classify(e, timedOut, signal); }
    if (as === "chunks") return chunks;
    if (as === "bytes") {
      if (chunks.length === 1) return chunks[0];
      const buf = new Uint8Array(got);
      let o = 0;
      for (const c of chunks) { buf.set(c, o); o += c.byteLength; }
      return buf;
    }
    const text = texts.join("");
    texts.length = 0;
    if (as === "text") return text;
    try { return JSON.parse(text); } catch { throw new FetchError("format", "The response was not valid JSON"); }
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener("abort", onAbort);
  }
}

/** Plain-English message for any error thrown by the functions above. */
export function describeError(e, who = "the source") {
  if (e instanceof FetchError && e.described) return e.message;          // already written for a specific source: don't replace it with the generic text
  if (!(e instanceof FetchError)) return `Unexpected error: ${String((e && e.message) || e).slice(0, 160)}`;
  switch (e.kind) {
    case "blocked": return `${who} could not be reached from the browser. Most often the site doesn't allow cross-origin reads (CORS), or you're offline. Use Sources → Test sources to see which sources work from your browser.`;
    case "timeout": return `${who} took too long to answer.`;
    case "cancelled": return "Cancelled.";
    case "toolarge": return e.message;
    case "format": return `${who} sent something unexpected (${e.message}).`;
    case "policy": return `Blocked by the app's safety rules: ${e.message}.`;
    case "http":
      if (e.status === 403 || e.status === 429) return `${who} refused the request (HTTP ${e.status}) — most likely a rate limit. NVD allows about 5 requests per 30 seconds without an API key; wait a minute and try again.`;
      if (e.status === 404) return `${who} has no record for that request (HTTP 404).`;
      return `${who} answered HTTP ${e.status}.`;
    default: return e.message;
  }
}

/** One cheap request per source: did the browser let us read the answer? */
export async function probeSource(src, { fetchImpl, timeoutMs = 15_000 } = {}) {
  const doFetch = fetchImpl || globalThis.fetch.bind(globalThis);
  assertAllowed(src.probe);
  const ctl = new AbortController();
  const t0 = Date.now();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await doFetch(src.probe, { method: "GET", mode: "cors", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", signal: ctl.signal });
    try { await res.body?.cancel(); } catch { /* we only need the headers */ }
    return { ok: res.ok, status: res.status, ms: Date.now() - t0, at: Date.now(), msg: res.ok ? "Works from this browser" : `Reachable, but answered HTTP ${res.status}` };
  } catch (e) {
    const aborted = e && e.name === "AbortError";
    return { ok: false, status: 0, ms: Date.now() - t0, at: Date.now(), msg: aborted ? "Timed out" : "Blocked (usually CORS) or offline" };
  } finally { clearTimeout(timer); }
}
