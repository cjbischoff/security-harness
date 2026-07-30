# Hunting: business logic

Load this companion for any application with distinct workflows, roles, or
stateful operations — nearly everything. Standard scanners can't find these;
they require reading the workflow, not the syntax. `attack-classes.md`'s
`authz` row asks "is the check present and correct for this call"; this file
asks "is the WORKFLOW itself exploitable even when every individual check is
correct."

## Core discipline

- A business-logic bug is a correct-looking sequence of individually-valid
  calls that reaches an invalid state. Don't stop at "is there a permission
  check" — trace the full state machine and ask what sequence the code never
  anticipated.
- Every state-changing operation needs its authorization traced to the
  SPECIFIC resource and the SPECIFIC business rule, not just "is the user
  logged in" or "is the user allowed to call this endpoint at all."
- Concurrency bugs need a real non-atomic check-then-act window, not just two
  requests hitting the same code. Name the read and the write and show nothing
  serializes them.
- A feature used exactly as designed can still be a vulnerability if the design
  itself leaks data or grants inference beyond the caller's access level —
  these are bugs in the design, not the code, and require the same rigor as any
  other finding.

## Classes

**state-machine / race / numeric** (CWE-840/841)
- Sink/indicator: any endpoint that transitions a resource between states
  (order status, approval flow, subscription lifecycle) or mutates a quantity
  (balance, count, price).
- Trace: can a step be skipped, reversed, or replayed? What happens on partial
  failure mid-flow — is step 1 rolled back if step 2 fails? For races: find the
  check (read) and the act (write) and confirm nothing (lock, transaction,
  unique constraint) serializes them across two concurrent callers. For
  numeric: can the value go negative, zero, overflow, or lose precision through
  a string↔number coercion?
- FP trap: a race "in theory" with no evidence the check and act are actually
  separated by an await/IO boundary is not a finding — cite the exact gap
  (what runs between the read and the write) or it's speculation, not a bug.

**feature-abuse** (export-as-exfil / search-as-oracle / enumeration)
- Sink/indicator: export/backup/report generation, search/filter/sort endpoints,
  and any flow with distinguishable success/failure responses (login, password
  reset, invite, registration).
- Trace (export-as-exfil): does the export path apply the same per-record
  permission check the UI does, or does it pull broader scope (all revisions,
  soft-deleted rows, other users' rows) because it's a separate code path?
  Trace (search-as-oracle): does a query/filter/sort parameter reveal existence,
  status, or a hidden field's value through result presence, ordering, or
  count, to a caller who can't read that field directly? Trace (enumeration):
  do error messages, status codes, timing, or response size differ between
  "doesn't exist" and "exists but you can't access it"?
- FP trap: a difference that exists but reveals nothing beyond what the caller
  already knows (e.g., distinguishing "invalid format" from "not found" for a
  self-owned resource) is not an oracle — the leak must cross a privilege
  boundary the caller doesn't already have.

**chained** (second-order / trust-boundary)
- Sink/indicator: any point where component A validates/produces data and
  component B consumes it under a different context — a stored field later used
  as a path segment, a JSON-path key, a template, or a regex.
- Trace: map what a low-privilege user CAN do, then look for combinations
  (info disclosure of an ID + no rate limit on the ID space; an open redirect
  feeding an OAuth callback; a benign self-XSS combined with CSRF to escalate
  it). For second-order: does data safe in its write context (HTML-escaped
  string) become dangerous when read in a different context (parsed as a URL,
  a regex, a template)?
- FP trap: naming two features that COULD interact is not a chain — you must
  show the concrete sequence of calls/state that produces the escalated impact,
  with each step's precondition actually satisfied by the previous step's
  output.

## Validation rules

1. **Construct the concrete sequence.** Exact calls/inputs in order, the state
   after each step, and the state that shouldn't be reachable. A described
   "could potentially" sequence without each step's precondition verified
   against the actual code is not a finding.
2. **For races, name the read and the write and the missing serialization.**
   Cite the absence of a lock/transaction/unique-constraint across the two
   concurrent paths — not just that the operation "isn't atomic" in the
   abstract.
3. **For feature-abuse, show the leaked boundary.** State exactly what the
   caller learns or exports that their normal access level doesn't already
   grant them, citing the code path that omits the per-item/per-field check the
   equivalent UI path applies.
4. **For chained/second-order, verify every link, not just the first and
   last.** Each intermediate step's output must actually satisfy the next
   step's precondition in the real code — a plausible-sounding chain with an
   unverified middle link is not confirmed.
5. **Check whether another layer already prevents the sequence** (a unique
   constraint, an idempotency key, a state guard elsewhere in the same
   transaction) before reporting — if so, it's a hardening note.
6. **Return only findings that pass gates 1–5** with the exact sequence and the
   resulting invalid/escalated state — or say the workflow held.
