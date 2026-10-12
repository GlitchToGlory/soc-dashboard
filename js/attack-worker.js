// Module worker: parse + compact the raw ATT&CK download off the main thread. The input buffer is transferred in (not copied).
import { buildAttack, validateAttack } from "./attack-build.js";

self.onmessage = (e) => {
  try {
    const bundle = JSON.parse(new TextDecoder("utf-8").decode(e.data.buffer));
    const data = buildAttack(bundle);
    validateAttack(data);
    self.postMessage({ ok: true, data });
  } catch (err) {
    self.postMessage({ ok: false, error: String((err && err.message) || err).slice(0, 200) });
  }
};
