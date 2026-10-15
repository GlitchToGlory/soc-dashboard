// Module worker: parse + compact the raw ATT&CK download off the main thread. The download's pieces are transferred in (not copied)
// and decoded one at a time, each piece released as soon as it is decoded, so the raw bytes and the text are never both held in full.
import { buildAttack, validateAttack } from "./attack-build.js";

self.onmessage = (e) => {
  try {
    let pieces = (e.data && e.data.chunks) || [];
    e.data.chunks = null;
    const decoder = new TextDecoder("utf-8");
    const texts = new Array(pieces.length + 1);
    for (let i = 0; i < pieces.length; i++) { texts[i] = decoder.decode(pieces[i], { stream: true }); pieces[i] = null; }
    texts[pieces.length] = decoder.decode();
    pieces = null;
    let text = texts.join("");
    texts.length = 0;
    const bundle = JSON.parse(text);
    text = null;
    const data = buildAttack(bundle);
    validateAttack(data);
    self.postMessage({ ok: true, data });
  } catch (err) {
    self.postMessage({ ok: false, error: String((err && err.message) || err).slice(0, 200) });
  }
};
