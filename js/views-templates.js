import { h, copyBtn, download, store, empty } from "./ui.js";
import { state } from "./state.js";
import { TEMPLATES } from "./templates.js";
import { placeholdersOf, fillTemplate, fmtUTC } from "./lib.js";

const SHORT = new Set(["date_utc", "analyst", "ticket_id", "severity", "status", "cve_id", "incident_id", "host", "user", "subject", "cvss", "epss", "in_kev"]);
const pretty = (k) => k.replace(/_/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());

const byName = (a, b) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true });

// Groups A–Z, and templates A–Z within each group, so the sidebar (and the default selection, list[0]) follow that order.
function allTemplates() {
  return [...TEMPLATES, ...store.get("customTemplates", []).map((t) => ({ ...t, group: "My templates", custom: true }))]
    .sort((a, b) => byName(a.group, b.group) || byName(a.title, b.title));
}

export function renderTemplates(parts) {
  const sub = parts[1];
  const list = allTemplates();
  const sidebar = h("nav", { class: "tpl-list card", "aria-label": "Templates" },
    h("a", { href: "#/templates/new", class: sub === "new" ? "active" : "" }, "＋ New template"));
  for (const g of [...new Set(list.map((t) => t.group))]) {
    sidebar.append(h("h3", {}, g));
    list.filter((t) => t.group === g).forEach((t) =>
      sidebar.append(h("a", { href: `#/templates/${t.id}`, class: (sub === t.id || (!sub && t === list[0])) ? "active" : "" }, t.title)));
  }
  let main;
  if (sub === "new" || sub === "edit") main = editorForm(sub === "edit" ? list.find((t) => t.id === parts[2] && t.custom) : null);
  else main = fillView(list.find((t) => t.id === sub) || list[0]);
  return h("div", {}, h("h1", {}, "Templates"),
    h("p", { class: "muted small" }, "Pick a template, fill in the fields and copy the result into your ticket, email or chat. Your analyst name is remembered on this device."),
    h("div", { class: "tpl-layout" }, sidebar, main));
}

function fillView(t) {
  const keys = placeholdersOf(t.body);
  const values = Object.create(null);   // no inherited keys such as "constructor"
  values.date_utc = fmtUTC(new Date().toISOString());
  values.analyst = store.get("analyst", "");
  if (state.prefill && state.prefill.id === t.id) { Object.assign(values, state.prefill.values); state.prefill = null; }
  const out = h("pre", { class: "out" });
  const render = () => { out.textContent = fillTemplate(t.body, values); };
  const inputs = keys.map((k) => {
    const el = SHORT.has(k) ? h("input", { type: "text" }) : h("textarea", { rows: "2" });
    el.value = values[k] || "";
    el.addEventListener("input", () => { values[k] = el.value; if (k === "analyst") store.set("analyst", el.value); render(); });
    return h("label", {}, pretty(k), el);
  });
  render();
  const bar = h("div", { class: "row" },
    copyBtn(() => out.textContent, "Copy"),
    h("button", { class: "btn", type: "button", onclick: () => download(`${t.id}-${new Date().toISOString().slice(0, 10)}.md`, out.textContent) }, "Download .md"),
    t.custom ? h("a", { class: "btn", href: `#/templates/edit/${t.id}` }, "Edit") : null,
    t.custom ? h("button", { class: "btn danger", type: "button", onclick: () => {
      if (!confirm(`Delete "${t.title}"?`)) return;
      store.set("customTemplates", store.get("customTemplates", []).filter((x) => x.id !== t.id));
      location.hash = "#/templates";
    } }, "Delete") : null);
  return h("section", { class: "card" },
    h("h2", {}, t.title), h("p", { class: "muted small" }, t.desc || ""), bar,
    h("div", { class: "tpl-editor" },
      h("div", { class: "fields", role: "group", "aria-label": "Template fields" }, inputs.length ? inputs : empty("This template has no {{placeholders}}.")),
      out));
}

function editorForm(existing) {
  const title = h("input", { type: "text", placeholder: "Template name", value: existing?.title || "" });
  const body = h("textarea", { rows: "18", class: "mono", placeholder: "Write your template. Use {{placeholder_name}} for fields to fill in later." });
  body.value = existing?.body || "# My template\n\n**Analyst:** {{analyst}}\n**Date (UTC):** {{date_utc}}\n\n## Notes\n{{notes}}\n";
  const msg = h("span", { class: "muted small" });
  const save = () => {
    if (!title.value.trim() || !body.value.trim()) { msg.textContent = "Add a name and some content first."; return; }
    const mine = store.get("customTemplates", []);
    const id = existing?.id || `custom-${Date.now()}`;
    const rec = { id, title: title.value.trim(), desc: "Custom template (saved in this browser)", body: body.value };
    store.set("customTemplates", existing ? mine.map((t) => (t.id === id ? rec : t)) : [...mine, rec]);
    location.hash = `#/templates/${id}`;
  };
  return h("section", { class: "card" },
    h("h2", {}, existing ? "Edit template" : "New template"),
    h("p", { class: "muted small" }, "Saved only in this browser. Use “Download” on a filled template to keep a copy elsewhere. Don't put secrets in templates."),
    h("div", { class: "row" }, title), body,
    h("div", { class: "row" }, h("button", { class: "btn primary", type: "button", onclick: save }, "Save template"), msg));
}
