# CWE-class extension — ssrf

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Allowlist destination hosts/schemes at the point the request is built; resolve and
re-validate the final address (block link-local/internal ranges) — never trust a
URL string that passed an earlier check but is re-parsed later.

## Discrimination requirement
An outbound request to a fixed, hardcoded destination is not SSRF regardless of how the
request body is built. The DESTINATION — host/port/scheme — must be attacker-influenced,
not just the request payload.

## Class boundary
**IS:** the server itself makes an attacker-steerable network request (HTTP client,
socket, DNS lookup, or a subprocess shell-out to `curl`/`wget` with an attacker-controlled
URL argument).
**IS NOT:**
- A client-side redirect (`Location` header, `next=` param) with no server-side fetch of
  that URL → `cls: open-redirect`, not ssrf.
- A `subprocess`/shell-out call where the ATTACKER controls shell metacharacters or the
  binary invoked, not just a URL argument to a fixed binary → `cls: cmdi`.
- A request to an attacker-influenced PATH on an otherwise-fixed, allowlisted host → not a
  finding at all unless the path traversal escapes the intended API surface (then trace it
  as `cls: path-traversal` if it reaches a file sink, or note it as informational).

## Proof tuple (required evidence)

A confirmable SSRF needs all three, each with a `file:line`:
1. **Server-side request built from input** — a fetch/HTTP-client call whose destination (host, path, or redirect target) incorporates user-controllable data.
2. **No allowlist/SSRF guard on every path** — missing or bypassable validation on the destination before the request fires.
3. **Attacker-controlled destination** — an attacker can steer the resolved address to an internal/unintended target.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
