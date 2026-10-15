import { h, ext, badge, copyBtn, download, field, select, debounce, empty, store, read } from "./ui.js";
import { state, loadAttack } from "./state.js";
import { ID } from "./sanitize.js";
import { normaliseId, kindOf, lookup, searchAttack, findTechniquesInText, tacticNames, navigatorLayer, groupByTactic } from "./attack-lib.js";
import { KQL } from "./kql.js";
import { taskButton } from "./live-ui.js";
import { timeAgo, own } from "./lib.js";

export const atk = { q: "", platform: "all", subs: false };
const marks = () => new Set(read.strs("attackMarks", { max: 5000, len: 12, test: (x) => ID.test(x) }));
const saveMarks = (s) => store.set("attackMarks", [...s]);
const href = (id) => `#/attack/${id}`;
const link = (id, text) => h("a", { href: href(id) }, text || id);

// ------------------------------------------------------------------ shell
export function renderAttack(parts) {
  const root = h("div", {});
  const sub = parts[1];
  const tab = ["groups", "software", "mitigations", "tools"].includes(sub) ? sub : normaliseId(sub) ? "detail" : "matrix";
  const tabs = h("div", { class: "tabs", role: "tablist" },
    [["matrix", "Matrix & search", "#/attack"], ["groups", "Groups", "#/attack/groups"], ["software", "Software", "#/attack/software"],
     ["mitigations", "Mitigations", "#/attack/mitigations"], ["tools", `My selection (${marks().size}) & tools`, "#/attack/tools"]]
      .map(([k, t, u]) => h("a", { href: u, class: `tab ${tab === k || (tab === "detail" && k === "matrix") ? "active" : ""}`, role: "tab" }, t)));
  root.append(h("h1", {}, "MITRE ATT&CK lookup"), tabs);
  const body = h("div", {});
  root.append(body);
  if (state.attack) { draw(body, tab, sub); return root; }
  body.append(h("div", { class: "card" }, h("p", { class: "muted" }, "Loading ATT&CK data…")));
  loadAttack().then((d) => { body.replaceChildren(); if (d) draw(body, tab, sub); else body.append(missingCard()); });
  return root;
}

function draw(body, tab, sub) {
  const d = state.attack;
  const saved = state.attackMeta && state.attackMeta.savedAt;
  body.append(h("div", { class: "row" },
    h("span", { class: "muted small" }, `ATT&CK Enterprise v${d.version || "?"} · ${Object.keys(d.techniques).length} techniques/sub-techniques · ${Object.keys(d.groups).length} groups · ${Object.keys(d.software).length} software${saved ? ` · downloaded ${timeAgo(saved)}` : ""}`),
    taskButton("attack", "Update ATT&CK data", { title: "Downloads the latest ATT&CK release (about 40 MB) and rebuilds the lookup" })));
  if (tab === "matrix") body.append(matrixView(d));
  else if (tab === "detail") body.append(detailView(d, normaliseId(sub)));
  else if (tab === "tools") body.append(toolsView(d));
  else body.append(listView(d, tab));
}

function missingCard() {
  return h("div", { class: "card" },
    h("h2", {}, "ATT&CK data isn't downloaded yet"),
    h("p", {}, "The lookup uses MITRE's official ATT&CK dataset. It is downloaded once from MITRE's GitHub (about 40 MB), compacted inside your browser, and saved here. Nothing is sent to MITRE except the download request."),
    h("div", { class: "row" }, taskButton("attack", "Download ATT&CK data", { primary: true })),
    h("p", { class: "muted small" }, "If the download is blocked, check ", h("a", { href: "#/sources" }, "Sources → Test sources"), ". Meanwhile you can use ", ext("https://attack.mitre.org/", "attack.mitre.org"), "."));
}

// ------------------------------------------------------------------ cards
// `m` is the current selection; callers drawing many rows pass it in so it is read from storage once, not once per row.
function techRow(t, d, opts = {}, m = marks()) {
  const parent = t.parent ? d.techniques[t.parent] : null;
  const tacs = opts.noTactic ? [] : tacticNames(d, parent || t);
  return h("li", { class: "attack-row" },
    h("span", { class: "id" }, link(t.id)), " ",
    h("span", {}, parent ? `${parent.name}: ${t.name}` : t.name), " ",
    m.has(t.id) ? badge("★ selected", "watch") : null,
    opts.how ? h("div", { class: "small muted" }, opts.how) : null,
    tacs.length ? h("div", { class: "small muted" }, tacs.join(" · ")) : null);
}

// ------------------------------------------------------------------ matrix + search
function matrixView(d) {
  const results = h("div", {});
  const platforms = [...new Set(Object.values(d.techniques).flatMap((t) => t.platforms || []))].sort();
  const update = () => { results.replaceChildren(atk.q.trim() ? searchResults(d) : matrix(d)); };
  const q = h("input", { type: "search", placeholder: "T1059, powershell, APT29, Cobalt Strike, lateral movement…", value: atk.q, "aria-label": "Search ATT&CK" });
  q.addEventListener("input", debounce(() => { atk.q = q.value; update(); }, 120));
  const subs = h("input", { type: "checkbox" });
  subs.checked = atk.subs;
  subs.addEventListener("change", () => { atk.subs = subs.checked; update(); });
  update();
  return h("div", {},
    h("div", { class: "toolbar" }, field("Search", q),
      field("Platform", select([["all", "All platforms"], ...platforms.map((p) => [p, p])], atk.platform, (v) => { atk.platform = v; update(); })),
      h("label", { class: "check" }, subs, "Show sub-techniques in matrix")),
    results);
}

function matrix(d) {
  const byTactic = Object.fromEntries(d.tactics.map((t) => [t.short, []]));
  for (const t of Object.values(d.techniques)) {
    if (t.parent) continue;
    if (atk.platform !== "all" && !(t.platforms || []).includes(atk.platform)) continue;
    for (const s of t.tactics) if (own(byTactic, s)) byTactic[s].push(t);
  }
  const m = marks();
  const cols = d.tactics.map((tac) => {
    const items = (byTactic[tac.short] || []).sort((a, b) => a.name.localeCompare(b.name));
    return h("div", { class: "mx-col" },
      h("div", { class: "mx-head", title: tac.desc }, tac.name, h("span", { class: "small muted" }, ` ${items.length}`)),
      items.map((t) => {
        const subs = (t.sub || []).filter((s) => d.techniques[s] && (atk.platform === "all" || (d.techniques[s].platforms || []).includes(atk.platform)));
        return h("div", { class: `mx-cell ${m.has(t.id) ? "marked" : ""}` },
          h("a", { href: href(t.id), class: "mx-t" }, h("span", { class: "mx-id" }, t.id), " ", t.name),
          atk.subs ? subs.map((s) => h("a", { href: href(s), class: `mx-s ${m.has(s) ? "marked" : ""}` }, h("span", { class: "mx-id" }, s), " ", d.techniques[s].name))
                   : (subs.length ? h("div", { class: "small muted" }, `${subs.length} sub-technique${subs.length > 1 ? "s" : ""}`) : null));
      }));
  });
  const grid = h("div", { class: "matrix", role: "region", "aria-label": "ATT&CK matrix", tabindex: "0" }, cols);

  // The horizontal scroll bar sits ABOVE the tactic headings instead of at the very bottom of a long page. It is a thin strip with one
  // empty 1px-high placeholder per column; the stylesheet gives the placeholders the same width and gap as the columns (shared CSS
  // variables), so both scroll the same distance. Moving either one moves the other. (The matrix's own bottom scroll bar is hidden in CSS.)
  const top = h("div", { class: "mx-top", "aria-hidden": "true", tabindex: "-1" }, d.tactics.map(() => h("span", {})));
  const follow = (from, to) => () => { if (Math.abs(to.scrollLeft - from.scrollLeft) > 0.5) to.scrollLeft = from.scrollLeft; };   // only moves when they differ, so the two can't ping-pong
  top.addEventListener("scroll", follow(top, grid));
  grid.addEventListener("scroll", follow(grid, top));
  return h("div", { class: "mx-wrap" }, top, grid);
}

function searchResults(d) {
  const r = searchAttack(d, atk.q, { platform: atk.platform });
  const m = marks();
  const sec = (title, bucket, render) => bucket.total ? h("section", { class: "card" },
    h("h2", {}, `${title} (${bucket.total})`), h("ul", { class: "plain" }, bucket.items.map(render)),
    bucket.total > bucket.items.length ? h("p", { class: "muted small" }, `Showing the top ${bucket.items.length} – refine your search to narrow down.`) : null) : null;
  const parts = [
    sec("Techniques", r.techniques, (t) => techRow(t, d, {}, m)),
    sec("Groups", r.groups, (g) => h("li", {}, h("span", { class: "id" }, link(g.id)), " ", g.name, g.aliases.length ? h("span", { class: "small muted" }, ` (${g.aliases.slice(0, 4).join(", ")})`) : null)),
    sec("Software", r.software, (s) => h("li", {}, h("span", { class: "id" }, link(s.id)), " ", s.name, " ", badge(s.type, "epss"))),
    sec("Mitigations", r.mitigations, (m) => h("li", {}, h("span", { class: "id" }, link(m.id)), " ", m.name)),
  ].filter(Boolean);
  return parts.length ? h("div", { class: "grid two" }, parts) : empty(`Nothing in ATT&CK matches “${atk.q}”.`);
}

// ------------------------------------------------------------------ lists
function listView(d, tab) {
  const src = { groups: d.groups, software: d.software, mitigations: d.mitigations }[tab];
  const q = h("input", { type: "search", placeholder: `Filter ${tab}…`, "aria-label": `Filter ${tab}` });
  const out = h("ul", { class: "plain" });
  // Sorted and lower-cased once per visit, not on every keystroke.
  const all = Object.values(src).sort((a, b) => a.name.localeCompare(b.name)).map((x) => [x, `${x.id} ${x.name} ${(x.aliases || []).join(" ")}`.toLowerCase()]);
  const redraw = () => {
    const f = q.value.trim().toLowerCase();
    const items = all.filter(([, s]) => !f || s.includes(f)).map(([x]) => x);
    out.replaceChildren(...items.map((x) => h("li", {}, h("span", { class: "id" }, link(x.id)), " ", x.name,
      x.aliases?.length ? h("span", { class: "small muted" }, ` (${x.aliases.slice(0, 3).join(", ")})`) : null,
      x.tech ? h("span", { class: "small muted" }, ` · ${x.tech.length} technique${x.tech.length === 1 ? "" : "s"}`) : null)));
    if (!items.length) out.append(h("li", { class: "muted" }, "No matches."));
  };
  q.addEventListener("input", debounce(redraw, 100));
  redraw();
  return h("div", {}, h("div", { class: "toolbar" }, field("Filter", q)), h("div", { class: "card" }, out));
}

// ------------------------------------------------------------------ detail pages
function markButton(ids, label, bulk = false) {
  const b = h("button", { class: "btn sm", type: "button" });
  const paint = () => { const m = marks(); b.textContent = bulk ? label : (m.has(ids[0]) ? "★ Remove from my selection" : "☆ Add to my selection"); };
  b.addEventListener("click", () => {
    const m = marks();
    if (bulk) { ids.forEach((i) => m.add(i)); saveMarks(m); b.textContent = `Added ${ids.length} ✓`; return; }
    m.has(ids[0]) ? m.delete(ids[0]) : m.add(ids[0]);
    saveMarks(m); paint();
  });
  paint();
  return b;
}

function detailView(d, id) {
  const kind = kindOf(id);
  const o = lookup(d, id);
  if (!o) return h("div", { class: "card" }, h("h2", {}, `${id} not found`), h("p", { class: "muted" }, "It may have been revoked or renamed in the stored ATT&CK version."),
    ext(`https://attack.mitre.org/search/?q=${encodeURIComponent(id)}`, "Search attack.mitre.org ↗"));
  const back = h("p", { class: "small" }, h("a", { href: "#/attack" }, "← Matrix & search"));
  const idLine = h("div", { class: "line" }, h("span", { class: "id" }, o.id), h("h2", { class: "flat" }, o.name));

  const sel = marks();
  if (kind === "technique") {
    const parent = o.parent ? d.techniques[o.parent] : null;
    const rel = KQL.filter((q) => q.attack.some((a) => o.id === a || o.id.startsWith(a + ".") || a.startsWith(o.id + ".")));
    return h("div", {}, back, h("section", { class: "card" },
      idLine,
      parent ? h("p", { class: "small" }, "Sub-technique of ", link(parent.id, `${parent.id} ${parent.name}`)) : null,
      h("div", { class: "line" }, tacticNames(d, parent || o).map((t) => badge(t, "epss")), (o.platforms || []).map((p) => badge(p, "unrated"))),
      h("p", { class: "pre-wrap" }, o.desc),
      h("div", { class: "actions" },
        markButton([o.id]), copyBtn(`${o.id} – ${o.name}`, "Copy ID + name"),
        copyBtn(`${o.id} – ${parent ? parent.name + ": " : ""}${o.name} (${tacticNames(d, parent || o).join(", ")})`, "Copy for ticket"),
        ext(o.url || `https://attack.mitre.org/techniques/${o.id.replace(".", "/")}/`, "MITRE page ↗", "btn sm")),
      o.sub?.length ? h("div", {}, h("h3", {}, `Sub-techniques (${o.sub.length})`), h("ul", { class: "plain" }, o.sub.map((s) => d.techniques[s] ? techRow(d.techniques[s], d, { noTactic: true }, sel) : null))) : null,
      (o.det?.length || o.detText) ? h("div", {}, h("h3", {}, "Detection"),
        o.detText ? h("p", { class: "pre-wrap" }, o.detText) : null,
        o.det?.length ? h("ul", { class: "plain" }, o.det.map((x) => h("li", {}, h("span", { class: "id" }, x.id), " ", x.name))) : null) : null,
      o.ds?.length ? h("p", { class: "small" }, h("strong", {}, "Data sources: "), o.ds.join(", ")) : null,
      rel.length ? h("div", {}, h("h3", {}, "Related hunting queries"), h("ul", { class: "plain" }, rel.map((q) => h("li", {}, h("a", { href: `#/reference/hunting/${q.id}` }, q.title))))) : null,
      o.mit?.length ? h("div", {}, h("h3", {}, `Mitigations (${o.mit.length})`), h("ul", { class: "plain" }, o.mit.map((m) => {
        const mm = d.mitigations[m]; const how = mm?.tech.find((x) => x.id === o.id)?.how;
        return h("li", {}, h("span", { class: "id" }, link(m)), " ", mm?.name || "", how ? h("div", { class: "small muted" }, how) : null);
      }))) : null,
      o.groups?.length ? h("div", {}, h("h3", {}, `Groups known to use it (${o.groups.length})`), h("p", {}, o.groups.map((g, i) => [i ? ", " : "", link(g, d.groups[g]?.name || g)]))) : null,
      o.sw?.length ? h("div", {}, h("h3", {}, `Software (${o.sw.length})`), h("p", {}, o.sw.map((s, i) => [i ? ", " : "", link(s, d.software[s]?.name || s)]))) : null));
  }

  if (kind === "group" || kind === "software") {
    const techIds = o.tech || [];
    const byTac = groupByTactic(d, techIds);
    return h("div", {}, back, h("section", { class: "card" }, idLine,
      o.aliases?.length ? h("p", { class: "small muted" }, `Also known as: ${o.aliases.join(", ")}`) : null,
      kind === "software" ? h("p", {}, badge(o.type, "epss"), " ", (o.platforms || []).map((p) => badge(p, "unrated"))) : null,
      h("p", { class: "pre-wrap" }, o.desc),
      h("div", { class: "actions" },
        techIds.length ? markButton(techIds, `Add all ${techIds.length} technique${techIds.length === 1 ? "" : "s"} to my selection`, true) : null,
        copyBtn(`${o.id} – ${o.name}`, "Copy ID + name"),
        ext(o.url || `https://attack.mitre.org/${kind === "group" ? "groups" : "software"}/${o.id}/`, "MITRE page ↗", "btn sm")),
      kind === "group" && o.sw?.length ? h("div", {}, h("h3", {}, `Software used (${o.sw.length})`), h("p", {}, o.sw.map((s, i) => [i ? ", " : "", link(s, d.software[s]?.name || s)]))) : null,
      kind === "software" && o.groups?.length ? h("div", {}, h("h3", {}, `Groups using it (${o.groups.length})`), h("p", {}, o.groups.map((g, i) => [i ? ", " : "", link(g, d.groups[g]?.name || g)]))) : null,
      h("h3", {}, `Techniques (${techIds.length})`),
      byTac.length ? byTac.map((r) => h("div", { class: "ioc-group" }, h("strong", {}, r.tactic.name), h("ul", { class: "plain" }, r.items.map((t) => techRow(t, d, { noTactic: true }, sel))))) : h("p", { class: "muted" }, "No technique mappings recorded.")));
  }

  return h("div", {}, back, h("section", { class: "card" }, idLine, h("p", { class: "pre-wrap" }, o.desc),
    h("div", { class: "actions" }, copyBtn(`${o.id} – ${o.name}`, "Copy ID + name"), ext(o.url || `https://attack.mitre.org/mitigations/${o.id}/`, "MITRE page ↗", "btn sm")),
    h("h3", {}, `Mitigates (${o.tech.length})`),
    h("ul", { class: "plain" }, o.tech.map((x) => d.techniques[x.id] ? techRow(d.techniques[x.id], d, { how: x.how }, sel) : null))));
}

// ------------------------------------------------------------------ selection + text mapper
function toolsView(d) {
  const sel = h("div", {});
  const drawSel = () => {
    const ids = [...marks()].sort();
    sel.replaceChildren(
      h("h2", {}, `My selection (${ids.length})`),
      h("p", { class: "small muted" }, "Collect techniques from the matrix, group pages or the text mapper, then export a layer file you can open in ATT&CK Navigator. Stored in this browser only."),
      ids.length ? h("ul", { class: "plain" }, ids.map((id) => h("li", {}, h("span", { class: "id" }, link(id)), " ", d.techniques[id]?.name || "(not in this ATT&CK version)", " ",
        h("button", { class: "btn sm", type: "button", onclick: () => { const s = marks(); s.delete(id); saveMarks(s); drawSel(); } }, "Remove")))) : empty("Nothing selected yet."),
      h("div", { class: "row" },
        h("button", { class: "btn primary", type: "button", disabled: !ids.length, onclick: () => download(`attack-layer-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(navigatorLayer(d, ids), null, 2), "application/json") }, "Export Navigator layer (.json)"),
        copyBtn(() => ids.map((id) => `${id} – ${d.techniques[id]?.name || ""}`).join("\n"), "Copy list"),
        h("button", { class: "btn danger", type: "button", disabled: !ids.length, onclick: () => { saveMarks(new Set()); drawSel(); } }, "Clear")),
      h("p", { class: "small muted" }, "In Navigator: Open Existing Layer → Upload from local."));
  };
  drawSel();
  const ta = h("textarea", { rows: "8", maxlength: "500000", class: "mono", placeholder: "Paste a threat report, ticket, or alert text. T-IDs (e.g. T1059.001) and technique names are matched against ATT&CK.", "aria-label": "Text to map" });
  const out = h("div", {});
  const run = () => {
    const found = findTechniquesInText(d, ta.value);
    const picked = marks();
    if (!found.length) { out.replaceChildren(empty("No techniques recognised.")); return; }
    out.replaceChildren(
      h("p", { class: "small muted" }, `${found.length} found. Matches by name can be false positives – review before adding.`),
      h("ul", { class: "plain" }, found.map((f) => techRow(f.t, d, { how: f.how === "ID" ? "matched by ID" : "matched by name" }, picked))),
      h("button", { class: "btn primary", type: "button", onclick: () => { const s = marks(); found.forEach((f) => s.add(f.id)); saveMarks(s); drawSel(); } }, `Add all ${found.length} to my selection`));
  };
  return h("div", { class: "grid two" }, h("section", { class: "card" }, sel),
    h("section", { class: "card" }, h("h2", {}, "Map text to techniques"), ta, h("div", { class: "row" }, h("button", { class: "btn primary", type: "button", onclick: run }, "Find techniques")), out));
}
