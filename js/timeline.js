// Incident timeline builder: finds a timestamp in each pasted line (most log, SIEM, EDR and email formats), converts it to UTC and
// sorts the events. Pure functions: no DOM, no network, nothing stored.

const MAX_INPUT = 500_000, MAX_LINES = 5000, MAX_LINE = 2000;

const MON = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
const MONTH = String.raw`(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]{0,6}\.?`;
const WEEKDAY = String.raw`(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]{0,6},?\s+)?`;
const TIME = String.raw`(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?(?:\s*([AaPp]\.?[Mm]\.?))?`;
const ZONE = String.raw`(?:\s*(Z|(?:UTC|GMT)(?:\s*[+-]\d{1,2}(?::?\d{2})?)?|[+-]\d{2}:?\d{2}))?`;
const AFTER = String.raw`(?![\d:])`;   // the match must not stop in the middle of a longer number or time

// Each pattern names where its parts are. `lead` means group 1 is a non-digit just before the date (the regexes avoid lookbehind,
// which Safari before 16.4 lacks), so the date itself starts after it.
const P = [
  { re: new RegExp(String.raw`(\d{4})-(\d{1,2})-(\d{1,2})(?:(?:T|\s+|\s*,\s*)${TIME}${ZONE})?${AFTER}`, "i"), y: 1, mo: 2, d: 3, t: 4 },
  { re: new RegExp(String.raw`(\d{4})/(\d{1,2})/(\d{1,2})(?:(?:T|\s+|\s*,\s*)${TIME}${ZONE})?${AFTER}`, "i"), y: 1, mo: 2, d: 3, t: 4 },
  { re: new RegExp(String.raw`(^|[^\w.:/-])(\d{1,2})[/.-](\d{1,2})[/.-](\d{4}|\d{2})(?:(?:T|\s+|\s*,\s*)${TIME}${ZONE})?(?![\d.:/-])`, "i"), lead: true, a: 2, b: 3, y: 4, t: 5, numeric: true },
  { re: new RegExp(String.raw`${WEEKDAY}(\d{1,2})(?:st|nd|rd|th)?[\s-]+${MONTH},?[\s-]+(\d{4})(?:(?:\s+|\s*,\s*|T)(?:at\s+)?${TIME}${ZONE})?${AFTER}`, "i"), d: 1, mon: 2, y: 3, t: 4 },
  { re: new RegExp(String.raw`${WEEKDAY}${MONTH}\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})(?:(?:\s+|\s*,\s*)(?:at\s+)?${TIME}${ZONE})?${AFTER}`, "i"), mon: 1, d: 2, y: 3, t: 4 },
  // ctime / Unix date: "Tue Oct 12 09:30:15 2026" (year after the time)
  { re: new RegExp(String.raw`${WEEKDAY}${MONTH}\s+(\d{1,2})\s+${TIME}${ZONE}\s+(\d{4})${AFTER}`, "i"), mon: 1, d: 2, t: 3, y: 9 },
  // syslog: "Oct 12 09:30:15" (no year)
  { re: new RegExp(String.raw`${MONTH}\s+(\d{1,2})\s+${TIME}${ZONE}${AFTER}`, "i"), mon: 1, d: 2, t: 3, noYear: true },
  { re: /^(\s*)(\d{13}|\d{10})(?:\.\d{1,6})?(?![\d.])/, lead: true, epoch: 2 },
];
const TIME_ONLY = new RegExp(String.raw`^\s*${TIME}${ZONE}(?![\d:])`, "i");

function zoneMinutes(z) {
  if (!z) return null;
  const s = z.replace(/\s+/g, "").toUpperCase();
  if (s === "Z" || s === "UTC" || s === "GMT") return 0;
  const m = s.match(/^(?:UTC|GMT)?([+-])(\d{1,2}):?(\d{2})?$/);
  if (!m) return null;
  const mins = Number(m[2]) * 60 + Number(m[3] || 0);
  return mins > 14 * 60 ? null : (m[1] === "-" ? -mins : mins);
}

// Builds a UTC timestamp from parts. `tz` (minutes east of UTC, or "local") applies when the text itself carries no zone.
function build(y, mo, d, tg, g, tz) {
  let h = 0, mi = 0, s = 0, ms = 0, zone = null, hasTime = false;
  if (tg && g[tg] !== undefined) {
    hasTime = true;
    h = Number(g[tg]); mi = Number(g[tg + 1]); s = Number(g[tg + 2] || 0);
    if (g[tg + 3]) ms = Number(g[tg + 3].slice(0, 3).padEnd(3, "0"));
    const ampm = g[tg + 4];
    if (ampm) { if (h < 1 || h > 12) return null; h = (h % 12) + (/^p/i.test(ampm) ? 12 : 0); }
    zone = zoneMinutes(g[tg + 5]);
    if (g[tg + 5] && zone === null) return null;
  }
  if (y < 100) y += 2000;
  if (mo < 0 || mo > 11 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60 || y < 1970 || y > 2100) return null;
  const off = zone !== null ? zone : tz === "local" ? null : tz;
  let t;
  if (off === null) {
    const dt = new Date(y, mo, d, h, mi, s, ms);
    if (dt.getMonth() !== mo || dt.getDate() !== d) return null;
    t = dt.getTime();
  } else {
    const u = Date.UTC(y, mo, d, h, mi, s, ms);
    const dt = new Date(u);
    if (dt.getUTCMonth() !== mo || dt.getUTCDate() !== d) return null;   // e.g. 31 April
    t = u - off * 60_000;
  }
  return { t, hasTime, zoned: zone !== null, y, mo, d };
}

// Finds the earliest timestamp in a line. Returns { t, index, length, hasTime, ambiguous, noYear } or null.
export function findTimestamp(line, { tz = 0, dayFirst = true, year = new Date().getUTCFullYear() } = {}) {
  let best = null;
  for (const p of P) {
    const g = line.match(p.re);
    if (!g) continue;
    const lead = p.lead ? g[1].length : 0;
    const index = g.index + lead, length = g[0].length - lead;
    if (best && (index > best.index || (index === best.index && length <= best.length))) continue;
    let r = null, ambiguous = false;
    if (p.epoch) {
      const n = Number(g[p.epoch]);
      const t = g[p.epoch].length === 13 ? n : n * 1000;
      const yy = new Date(t).getUTCFullYear();
      if (yy >= 1990 && yy <= 2100) { const dt = new Date(t); r = { t, hasTime: true, zoned: true, y: yy, mo: dt.getUTCMonth(), d: dt.getUTCDate() }; }
    } else if (p.numeric) {
      const A = Number(g[p.a]), B = Number(g[p.b]);
      let d = dayFirst ? A : B, mo = dayFirst ? B : A;
      if (mo > 12 && d <= 12) [d, mo] = [mo, d];                     // 25/12 can only be day-first, 12/25 only month-first
      ambiguous = A <= 12 && B <= 12 && A !== B;
      r = build(Number(g[p.y]), mo - 1, d, p.t, g, tz);
    } else {
      const mo = p.mon ? MON[g[p.mon].slice(0, 3).toLowerCase()] : Number(g[p.mo]) - 1;
      r = build(p.noYear ? year : Number(g[p.y]), mo, Number(g[p.d]), p.t, g, tz);
    }
    if (r) best = { ...r, index, length, ambiguous, noYear: !!p.noYear };
  }
  return best;
}

const SEP_START = /^[\s,;|:>\])}–—-]+/, SEP_END = /[\s,;|:<[({–—-]+$/;
const clean = (s) => s.replace(SEP_START, "").replace(SEP_END, "").replace(/\s+/g, " ").trim();
// "[EDR] text" or "EDR: text" at the start of the description is taken as the event's source.
function splitSource(text) {
  const m = text.match(/^\[([^\]]{1,40})\]\s*(.*)$/);
  return m ? { source: m[1].trim(), text: m[2] } : { source: "", text };
}

/**
 * Parses pasted text into events.
 * opts: tz (minutes east of UTC for times with no zone, or "local"), dayFirst (03/04 = 3 April), year (for syslog-style lines with none).
 * Returns { events: [{ t, text, source, line, hasTime, ambiguous }], unparsed: [{ line, text }], ambiguous, guessedYear }.
 */
export function parseTimeline(input, opts = {}) {
  const lines = String(input ?? "").slice(0, MAX_INPUT).split(/\r?\n/).slice(0, MAX_LINES);
  // Year for lines that have none (syslog "Oct 12 09:30:15"): the latest full date in the paste, else this year.
  let year = opts.year;
  if (!year) {
    let latest = 0;
    for (const l of lines) { const f = findTimestamp(l.slice(0, MAX_LINE), { ...opts, year: 2000 }); if (f && !f.noYear) latest = Math.max(latest, f.t); }
    year = latest ? new Date(latest).getUTCFullYear() : new Date().getUTCFullYear();
  }
  const o = { tz: 0, dayFirst: true, ...opts, year };
  const events = [], unparsed = [];
  let contextDate = null;      // { y, mo, d } from a line holding only a date, used by following time-only lines
  lines.forEach((raw, i) => {
    const line = raw.slice(0, MAX_LINE);
    if (!line.trim()) return;
    const n = i + 1;

    // Markdown table row (e.g. a timeline copied back in): time in one cell, event and source in the next ones.
    if (/^\s*\|/.test(line)) {
      if (/^[\s|:-]+$/.test(line)) return;
      const cells = line.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      const at = cells.findIndex((c) => findTimestamp(c, o));
      if (at === -1) { if (!/\b(time|date|when)\b/i.test(line)) unparsed.push({ line: n, text: line.trim() }); return; }
      const f = findTimestamp(cells[at], o);
      const rest = cells.filter((_, j) => j !== at);
      events.push({ t: f.t, text: rest[0] || "", source: rest[1] || "", line: n, hasTime: f.hasTime, ambiguous: f.ambiguous });
      return;
    }

    const f = findTimestamp(line, o);
    if (f) {
      const text = clean(line.slice(0, f.index) + " " + line.slice(f.index + f.length));
      if (!text && !f.hasTime) { contextDate = { y: f.y, mo: f.mo, d: f.d }; return; }   // a date on its own: the date for the lines below
      const s = splitSource(text);
      events.push({ t: f.t, text: s.text, source: s.source, line: n, hasTime: f.hasTime, ambiguous: f.ambiguous });
      return;
    }
    const tm = contextDate !== null && line.match(TIME_ONLY);
    if (tm) {
      const r = build(contextDate.y, contextDate.mo, contextDate.d, 1, tm, o.tz);
      if (r) {
        const s = splitSource(clean(line.slice(tm[0].length)));
        events.push({ t: r.t, text: s.text, source: s.source, line: n, hasTime: true, ambiguous: false });
        return;
      }
    }
    if (/^\s/.test(raw) && events.length) { const last = events[events.length - 1]; last.text = clean(`${last.text} ${line}`); return; }   // indented: continues the event above
    unparsed.push({ line: n, text: line.trim().slice(0, 200) });
  });
  events.sort((a, b) => a.t - b.t || a.line - b.line);
  return { events, unparsed, ambiguous: events.filter((e) => e.ambiguous).length, year };
}

// ------------------------------------------------------------------ formatting and export
const p2 = (n) => String(n).padStart(2, "0");
export function fmtUtc(t, withMs = false) {
  const d = new Date(t);
  return `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}${withMs ? "." + String(d.getUTCMilliseconds()).padStart(3, "0") : ""}`;
}
export function fmtGap(ms) {
  if (ms <= 0) return ms === 0 ? "same time" : "";
  const s = Math.round(ms / 1000);
  if (s < 60) return `+${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `+${m}m ${p2(s % 60)}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `+${h}h ${p2(m % 60)}m`;
  return `+${Math.floor(h / 24)}d ${h % 24}h`;
}
export const fmtSpan = (ms) => (ms < 1000 ? "under a second" : fmtGap(ms).replace(/^\+/, ""));
const needMs = (events) => events.some((e) => e.t % 1000 !== 0);
const timeOf = (e, ms) => fmtUtc(e.t, ms) + (e.hasTime ? "" : " (date only)");

const mdCell = (s) => String(s).replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
export function toMarkdown(events) {
  const ms = needMs(events);
  return ["| Time (UTC) | Event | Source |", "|---|---|---|", ...events.map((e) => `| ${timeOf(e, ms)} | ${mdCell(e.text)} | ${mdCell(e.source)} |`)].join("\n");
}
// CSV cells starting with = + - @ are prefixed with ' so a spreadsheet can't treat pasted log text as a formula.
const csvCell = (s) => { let v = String(s); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
export function toCsv(events) {
  const ms = needMs(events);
  return ["time_utc,event,source", ...events.map((e) => [timeOf(e, ms), e.text, e.source].map(csvCell).join(","))].join("\r\n");
}
export function toText(events) {
  const ms = needMs(events);
  return events.map((e) => `${timeOf(e, ms)} UTC — ${e.source ? `[${e.source}] ` : ""}${e.text}`).join("\n");
}
