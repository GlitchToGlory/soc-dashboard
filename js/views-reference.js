import { h, ext, copyBtn, field, debounce, empty, lazyDetails } from "./ui.js";
import { KQL } from "./kql.js";
import { PORTS, COMMANDS, FRAMEWORKS, LINK_GROUPS, WIN_EVENTS } from "./refdata.js";

const TABS = [["hunting", "Hunting queries (KQL)"], ["frameworks", "Frameworks"], ["ports", "Ports"], ["commands", "Triage commands"], ["events", "Event IDs"], ["links", "Links"]];

export function renderReference(parts) {
  const tab = TABS.some(([k]) => k === parts[1]) ? parts[1] : "hunting";
  const tabs = h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, t]) => h("a", { href: `#/reference/${k}`, class: `tab ${k === tab ? "active" : ""}`, role: "tab" }, t)));
  const view = { hunting: () => hunting(parts[2]), frameworks, ports, commands, events, links }[tab]();
  return h("div", {}, h("h1", {}, "Reference"), tabs, view);
}

function filterable(placeholder, build) {
  const out = h("div", {});
  const q = h("input", { type: "search", placeholder, "aria-label": placeholder });
  const draw = () => out.replaceChildren(build(q.value.trim().toLowerCase()));
  q.addEventListener("input", debounce(draw, 100));
  draw();
  return h("div", {}, h("div", { class: "toolbar" }, field("Filter", q)), out);
}

function hunting(focusId) {
  return h("div", {},
    h("p", { class: "muted small" }, "Starter queries for Microsoft Sentinel and Microsoft Defender XDR advanced hunting. Table names and columns depend on your licences and connected data – run on a short time range first and tune before turning anything into an alert."),
    filterable("Filter queries: password, PowerShell, T1110…", (f) => {
      const items = KQL.filter((k) => !f || `${k.title} ${k.area} ${k.attack.join(" ")} ${k.query}`.toLowerCase().includes(f));
      if (!items.length) return empty("No queries match.");
      return h("div", { class: "list" }, items.map((k) => lazyDetails(
        h("summary", {}, h("div", { class: "line" }, h("strong", {}, k.title), h("span", { class: "badge epss" }, k.area), k.attack.map((a) => h("a", { class: "badge watch", href: `#/attack/${a}` }, a)))),
        () => h("div", { class: "body" }, k.note ? h("p", { class: "muted small" }, k.note) : null, h("pre", { class: "out" }, k.query), h("div", { class: "actions" }, copyBtn(k.query, "Copy query"))),
        focusId === k.id)));
    }));
}

function frameworks() {
  const tbl = (head, rows) => h("table", {}, h("thead", {}, h("tr", {}, head.map((x) => h("th", {}, x)))), h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c, i) => h(i === 0 ? "th" : "td", {}, c))))));
  return h("div", { class: "grid two" },
    h("section", { class: "card" }, h("h2", {}, "TLP 2.0 – sharing markings"), tbl(["Marking", "Who can see it"], FRAMEWORKS.tlp)),
    h("section", { class: "card" }, h("h2", {}, "Cyber Kill Chain"), tbl(["Stage", "Meaning"], FRAMEWORKS.killchain)),
    h("section", { class: "card" }, h("h2", {}, "Pyramid of Pain"), h("p", { class: "small muted" }, "How much it hurts the attacker when you detect/deny each indicator type."), tbl(["Indicator", "Pain to attacker", "Note"], FRAMEWORKS.pyramid)),
    h("section", { class: "card" }, h("h2", {}, "Example SOC severity model"), h("p", { class: "small muted" }, "A common starting point – replace with your organisation's own definitions and SLAs."), tbl(["Level", "Typical criteria", "Response"], FRAMEWORKS.severity)),
    h("section", { class: "card" }, h("h2", {}, "CVSS severity bands"), tbl(["Severity", "Score"], FRAMEWORKS.cvss),
      h("p", { class: "small muted" }, "CVSS measures technical severity, not likelihood. Combine with EPSS (probability of exploitation) and CISA KEV (known exploited) when prioritising.")));
}

function ports() {
  return filterable("Filter ports: 445, rdp, smb…", (f) => h("table", {}, h("thead", {}, h("tr", {}, ["Port", "Proto", "Service", "Why a SOC cares"].map((x) => h("th", {}, x)))),
    h("tbody", {}, PORTS.filter((r) => !f || r.join(" ").toLowerCase().includes(f)).map((r) => h("tr", {}, r.map((c, i) => h("td", {}, i === 0 ? h("code", {}, c) : c)))))));
}

function commands() {
  return h("div", {}, h("p", { class: "muted small" }, "Read-only triage commands. Only run them on systems you're authorised to investigate, and follow your evidence-handling procedures."),
    filterable("Filter: network, persistence, hash…", (f) => h("div", { class: "list" }, COMMANDS.filter((c) => !f || c.join(" ").toLowerCase().includes(f)).map(([os, title, cmd]) =>
      h("div", { class: "card cmd" }, h("div", { class: "line" }, h("span", { class: "badge epss" }, os), h("strong", {}, title)), h("pre", { class: "out" }, cmd), h("div", { class: "actions" }, copyBtn(cmd, "Copy")))))));
}

function events() {
  return filterable("Filter: logon, 4624, kerberos…", (f) => h("table", {}, h("thead", {}, h("tr", {}, ["Event ID", "Log", "Meaning"].map((x) => h("th", {}, x)))),
    h("tbody", {}, WIN_EVENTS.filter((r) => !f || r.join(" ").toLowerCase().includes(f)).map(([id, log, d]) => h("tr", {}, h("td", {}, h("code", {}, id)), h("td", { class: "muted" }, log), h("td", {}, d))))));
}

function links() {
  return filterable("Filter links…", (f) => h("div", { class: "grid two" }, LINK_GROUPS.map(([g, items]) => {
    const rows = items.filter(([t, u]) => !f || `${g} ${t} ${u}`.toLowerCase().includes(f));
    return rows.length ? h("section", { class: "card" }, h("h2", {}, g), h("ul", { class: "plain" }, rows.map(([t, u]) => h("li", {}, ext(u, t))))) : null;
  }).filter(Boolean)));
}
