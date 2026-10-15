// Small shared UI pieces for the "fetch it now" controls. Buttons start tasks; progress/results appear in the status bar (app.js).
import { h, select } from "./ui.js";
import { runTask, getSettings, saveSettings, DAY_CHOICES } from "./tasks.js";
import { TOPIC_LABELS } from "./live.js";
import { state } from "./state.js";
import { timeAgo } from "./lib.js";

export function taskButton(name, label, { primary = false, overrides, title } = {}) {
  const b = h("button", { class: `btn js-task${primary ? " primary" : ""}`, type: "button", title }, label);
  b.addEventListener("click", () => { runTask(name, overrides); });
  return b;
}

export const daysSelect = () => select(DAY_CHOICES.map((d) => [String(d), `Last ${d} day${d > 1 ? "s" : ""}`]), String(getSettings().days), (v) => saveSettings({ days: Number(v) }));
export const topicSelect = () => select(Object.entries(TOPIC_LABELS), getSettings().topic, (v) => saveSettings({ topic: v }));

export function epssCheck() {
  const i = h("input", { type: "checkbox" });
  i.checked = getSettings().epss;
  i.addEventListener("change", () => saveSettings({ epss: i.checked }));
  return h("label", { class: "check" }, i, "Add EPSS scores");
}

export function fetchedLine(key, label) {
  const ts = state.meta.fetched[key];
  if (!ts) return h("span", { class: "muted small" }, `${label}: not fetched yet`);
  const via = state.meta.via[key];
  return h("span", { class: "muted small" }, `${label}: fetched ${timeAgo(ts)}${via ? ` via ${via}` : ""}`);
}

export function getStarted() {
  return h("div", { class: "card" },
    h("h2", {}, "Nothing fetched yet"),
    h("p", {}, "This app never contacts anything in the background. Press ", h("strong", {}, "↻ Fetch all feeds"), " (top right) to fetch the CISA KEV catalogue, the latest CVEs and news headlines, or use the buttons on each page."),
    h("p", { class: "muted small" }, "If a fetch says it was blocked, open ", h("a", { href: "#/sources" }, "Sources → Test sources"), " to see which services your browser is allowed to read."));
}
