# Hunting: client-side & browser

Load this companion when recon flags a SPA, browser extension, embedded webview,
or any code rendering attacker-influenceable content in the DOM, handling
`postMessage`, opening WebSockets, or serving credentialed cross-origin
responses. These bugs live in code the server never executes (the fragment
after `#`, `window.name`, a `postMessage` payload) — server-side escaping and
`attack-classes.md`'s `xss` row don't see them.

## Core discipline

- Client-side taint needs a controllable SOURCE and an executing SINK on the
  client path. Name both; a source with no sink, or a sink fed only
  server-rendered trusted data, is not a finding.
- The impact must cross to a victim or cross an origin. XSS that only fires in
  the attacker's own DOM, or a "leak" of the attacker's own data, is not a
  finding — state whose session executes the payload or whose cross-origin data
  it steals.
- Framework auto-escaping is a real mitigation, not a checklist item to ignore.
  React/Vue/Angular escape interpolation by default; the finding is where the
  code opts OUT (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`,
  `$sce.trustAs*`). Escaped interpolation is not a finding.
- A missing header or attribute (`X-Frame-Options`, `frame-ancestors`,
  `rel=noopener`, `SameSite`) is only a finding with a concrete sensitive action
  behind it — a bare missing flag on a read-only page is a hardening note.

## Classes

**dom-xss**
- Sink/indicator: `innerHTML`/`outerHTML`, `document.write`, `eval`, `Function`,
  `setTimeout`/`setInterval` with a string arg, `element.src`/`href` set to a
  `javascript:` URI, jQuery `.html()`, or a framework escape hatch
  (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrustHtml`).
- Trace: start from the sink and walk backward to a client source —
  `location.hash`/`search`/`href`/`pathname`, `document.referrer`,
  `window.name`, `postMessage` data, `document.cookie`. Confirm no sanitization
  sits on the client path between source and sink.
- FP trap: a sink fed only server-rendered, already-escaped data is not a
  finding — server escaping is real, but it never sees fragment or `window.name`
  data, so verify which half of the path you're actually looking at.

**dom-clobbering**
- Sink/indicator: code reading `window.X`/`document.X` before checking whether
  it was set, where an injected `id`/`name` attribute can shadow that global.
- Trace: find a markup-injection sink that survives sanitization for `id`/`name`
  attributes (script stripped, attributes allowed); confirm the script later
  reads the same identifier as a global without a type/existence check.
- FP trap: clobbering requires an actual attribute-injection sink upstream —
  "the script reads `window.config`" alone is not exploitable without a place to
  inject the shadowing element.

**cswsh** (cross-site websocket hijack — CWE-1385)
- Sink/indicator: the WebSocket upgrade/handshake handler.
- Trace: confirm the handshake authenticates only via ambient cookies; check
  whether it validates `Origin` and requires a per-session token bound
  independently of the cookie.
- FP trap: an `Origin` check present anywhere in the handshake path (even a
  simple allowlist) defeats the basic form — verify it's actually absent or
  trivially bypassable (unanchored regex, `null` allowed) before reporting.

**prototype-pollution** (CWE-1321)
- Sink/indicator: a deep-merge/`lodash.set`-style path assignment, `obj[a][b]=v`
  with an attacker-controlled segment, or a nested-object-building query parser.
- Trace: confirm the attacker-controlled key (`__proto__`, `constructor.prototype`)
  reaches a RECURSIVE write that lands on `Object.prototype`, then find a gadget
  that reads the polluted property to a security-relevant effect (an options
  object checked with `opts.isAdmin`, a template default, a sink that
  concatenates a polluted path).
- FP trap: a plain `JSON.parse` or shallow `Object.assign` does NOT pollute —
  require the recursive/nested sink. Pollution with no reachable gadget is not
  exploitable; both halves are mandatory.

**open-redirect-client**
- Sink/indicator: a navigation built from a client source —
  `location = params.get('next')`, `location.hash` fed into `location.href`, a
  router redirect.
- Trace: confirm no allowlist on the destination, including `javascript:`/
  `data:` schemes that upgrade the redirect into XSS. This is distinct from the
  base `open-redirect` class — the sink is in JS, so the server never sees the
  value.
- FP trap: a redirect restricted to same-origin relative paths, or one that
  passes through a router's own scheme allowlist, is not this bug — verify the
  actual destination construction, not just that a parameter feeds a redirect.

## Validation rules

1. **Confirm both halves of the client path.** Cite the source AND the executing
   sink, and show untrusted data reaching the sink unsanitized on that path.
2. **For prototype pollution, prove the recursive write AND the gadget.** Either
   half missing means no finding.
3. **For messaging/CORS/WebSocket, show the origin check is absent or weak** —
   cite the handler and the specific missing or bypassable check, and that the
   data drives a security-relevant action or a credentialed cross-origin read.
4. **For UI-redress, require the sensitive action behind the missing guard.**
   Check whether framebusting, `frame-ancestors`, or the browser's `noopener`
   default for `target="_blank"` already defeats it before reporting.
5. **Return only findings that pass gates 1–4** with the client source→sink path
   and whose session it fires in — otherwise it's a hardening note.
