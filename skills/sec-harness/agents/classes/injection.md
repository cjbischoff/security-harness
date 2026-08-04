# CWE-class extension — injection

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Parameterized query / argument-vector exec / contextual output encoding.

## Discrimination requirement
Replay the SAST/PoC payload verbatim against the fixed code; the fix is only FULL if the
same payload no longer reaches the sink (pre=fail/post=pass).

## Class boundary
**IS:** untrusted data reaching a query/command/interpreter sink where it is parsed as
CODE or CONTROL SYNTAX for that interpreter (SQL, shell, argument vector).
**IS NOT:**
- A template engine rendering user input inside `{{ }}`/`<%= %>` syntax → that is
  `cls: ssti`, even though the payload also looks like "code injection."
- An XML parser expanding an attacker-supplied entity → `cls: xxe`.
- A deserializer instantiating attacker-controlled objects/gadget chains (`pickle`,
  `yaml.load`, `readObject`) → `cls: deserialization` if that key is in scope for this
  repo, otherwise keep as `injection` but say so in the message — do not conflate with a
  query/command sink.
- Output reaching a browser/DOM without execution in this process → `cls: xss`.
- The DESTINATION of an outbound request being attacker-influenced (not its payload) →
  `cls: ssrf`.

## Proof tuple (required evidence)

A confirmable injection needs all three, each with a `file:line`:
1. **Attacker-controlled source** — external input reaches the sink (not a constant/allowlisted value).
2. **Control/sanitizer bypass** — no parameterization/escaping on the path, OR a named `sanitize`/`validate` that does not cover this sink's grammar.
3. **Reachable dangerous sink** — the concrete sink executes (e.g. `execute`/`executemany`/`executescript`), reachable from an entrypoint.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
