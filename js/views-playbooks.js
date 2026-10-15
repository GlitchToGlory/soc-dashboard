import { h, copyBtn, download, store } from "./ui.js";
import { PLAYBOOKS } from "./playbooks.js";

const key = (id) => `playbook.${id}`;
// Listed A–Z by title (the steps inside each playbook keep their order).
const SORTED = [...PLAYBOOKS].sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: "base", numeric: true }));
const getDone = (id) => new Set(store.get(key(id), []));

export function renderPlaybooks(parts) {
  const sel = SORTED.find((p) => p.id === parts[1]) || SORTED[0];
  const side = h("nav", { class: "tpl-list card", "aria-label": "Playbooks" },
    h("h3", {}, "Playbooks"),
    SORTED.map((p) => {
      const total = p.phases.reduce((n, [, s]) => n + s.length, 0), done = getDone(p.id).size;
      return h("a", { href: `#/playbooks/${p.id}`, class: p.id === sel.id ? "active" : "" }, p.title, done ? h("span", { class: "small" }, `  ${done}/${total}`) : null);
    }));
  return h("div", {}, h("h1", {}, "Response playbooks"),
    h("p", { class: "muted small" }, "Working checklists for common incident types. Ticks are saved in this browser so you can pick up where you left off. These are starting points – adapt them to your organisation's runbooks and escalation paths."),
    h("div", { class: "tpl-layout" }, side, playbook(sel)));
}

function playbook(p) {
  const done = getDone(p.id);
  const progress = h("span", { class: "muted small" });
  const total = p.phases.reduce((n, [, s]) => n + s.length, 0);
  const upd = () => { progress.textContent = `${done.size} of ${total} steps done`; };
  const md = () => `# ${p.title} – checklist\n\n` + p.phases.map(([ph, steps]) => `## ${ph}\n` + steps.map((s) => `- [${done.has(s) ? "x" : " "}] ${s}`).join("\n")).join("\n\n");
  const phases = p.phases.map(([name, steps]) => h("div", { class: "pb-phase" },
    h("h3", {}, name),
    steps.map((s) => {
      const cb = h("input", { type: "checkbox" });
      cb.checked = done.has(s);
      cb.addEventListener("change", () => { cb.checked ? done.add(s) : done.delete(s); store.set(key(p.id), [...done]); upd(); });
      return h("label", { class: "pb-step" }, cb, h("span", {}, s));
    })));
  upd();
  return h("section", { class: "card" }, h("h2", {}, p.title), h("p", { class: "muted small" }, p.blurb),
    h("div", { class: "row" }, progress, copyBtn(md, "Copy as Markdown"),
      h("button", { class: "btn", type: "button", onclick: () => download(`${p.id}-checklist.md`, md()) }, "Download .md"),
      h("button", { class: "btn danger", type: "button", onclick: () => { if (!confirm("Clear all ticks for this playbook?")) return; store.set(key(p.id), []); window.dispatchEvent(new Event("hashchange")); } }, "Reset")),
    phases);
}
