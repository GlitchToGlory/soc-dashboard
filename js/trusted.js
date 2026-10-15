// Trusted Types policy. With `require-trusted-types-for 'script'` in the page's CSP, supporting browsers (Chrome, Edge, and others
// as they add it) refuse every HTML-injection sink (innerHTML, document.write, inline event-handler attributes...) and refuse to
// load a script URL that didn't come through a policy. The app uses no HTML sinks at all, and this policy approves exactly two
// script URLs: the service worker and the ATT&CK worker. Browsers without Trusted Types ignore all of this.
const ALLOWED = new Set([new URL("../sw.js", import.meta.url).href, new URL("./attack-worker.js", import.meta.url).href]);

const policy = globalThis.trustedTypes && globalThis.trustedTypes.createPolicy
  ? globalThis.trustedTypes.createPolicy("soc", {
      createScriptURL(u) {
        const href = new URL(String(u), document.baseURI).href;
        if (!ALLOWED.has(href)) throw new TypeError(`Blocked script URL: ${href.slice(0, 120)}`);
        return href;
      },
    })
  : null;

/** A script URL the browser will accept under the CSP (a plain string where Trusted Types isn't supported). */
export const scriptURL = (u) => (policy ? policy.createScriptURL(String(u)) : String(u));
