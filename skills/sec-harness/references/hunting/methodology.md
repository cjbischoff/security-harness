# Hunting methodology

Twelve generic attacker-mindset heuristics. Domain-agnostic — apply alongside
whichever `hunting/*.md` companion(s) recon selected, and alongside the base
`attack-classes.md`. These are angles of attack, not attack classes: use them
to generate candidates within a class, not as a substitute for one.

1. **Sad-path bias.** The happy path is defended; the sad path usually isn't.
   Audit error handlers, fallback branches, catch blocks, default cases,
   timeout paths, retry logic, and cleanup routines with the same rigor as the
   success path. Example: a payment webhook handler that validates the
   signature on success but the retry/timeout branch re-processes a cached
   unvalidated payload.

2. **Boundary conditions.** Test empty, maximum-length, null vs. undefined vs.
   missing, zero, negative, off-by-one, and exact-threshold-moment inputs.
   Example: a rate limiter that resets "at the top of the minute" — request at
   `:00.001` after 99 requests at `:59.999` doubles the effective limit.

3. **Implicit inter-component trust.** Find where one component assumes another
   already validated something, and check whether that assumption is actually
   true on every call path. Example: the DB layer assumes the API layer
   sanitized a field, but an internal admin script writes to the same table
   directly, bypassing the API entirely.

4. **Operation-ordering.** Call steps out of their intended sequence: step 3
   before step 1, delete during create, the callback before the request starts,
   replay a completed flow. Example: hitting a webhook confirmation endpoint
   for an order that was never actually created, if the handler doesn't check
   the order exists first.

5. **TOCTOU / concurrency.** Two requests to the same resource, or a
   check-then-act gap wide enough for a second caller to land between the check
   and the act. Example: two simultaneous "redeem coupon" requests both read
   "not yet used," both proceed to redeem, because the read and the write aren't
   in the same transaction.

6. **Parser/validator disagreement.** Find two components that parse the same
   input differently — a schema validator vs. the database, a router vs. the
   application code, a `Content-Type` header vs. the actual body, a filename
   extension vs. MIME type vs. magic bytes. Example: an upload validator checks
   the extension `.jpg`, but the storage layer serves the file with a
   content-sniffed type, letting an SVG-with-`.jpg`-extension execute as
   `image/svg+xml`.

7. **Round-trip integrity.** Store data, then retrieve it, and check it's
   unchanged. Encoding drift, double-escaping, path re-resolution, and lost
   type information all live here. Example: a value stored HTML-escaped gets
   read back into a context that expects raw text and double-escapes it —
   or worse, a context that expects HTML and the escaping vanishes.

8. **Config-as-attack-surface.** What happens when config is missing, default,
   or overridden by an environment variable or feature flag? What's the
   security posture during first-run/setup before config completes? Example: a
   feature flag meant to gate a beta feature also silently disables the input
   validation that shipped alongside it, if the flag check wraps both.

9. **Privilege-tracing.** For every state-changing operation, trace back to the
   permission check: is it checking the RIGHT permission against the RIGHT
   resource, and is there a parallel path to the same state change that checks
   differently or not at all? Example: a bulk "archive" endpoint checks the
   caller can archive at least one item in the batch, not each item
   individually.

10. **Information leakage.** Error messages revealing internal paths or stack
    traces, timing differences that reveal record existence, response-size
    differences, version-disclosing headers, forgotten debug endpoints.
    Example: a login endpoint returns in 40ms for "user not found" and 380ms
    for "wrong password" because the password hash only runs in the second
    case — timing oracle for username enumeration.

11. **Security-default overrides.** A safe default that a user-supplied
    parameter, header, or config value can flip. Example: a report-export
    endpoint defaults to the caller's own tenant but accepts an optional
    `tenant_id` parameter with no cross-tenant check, because the parameter was
    added for an internal admin tool and never scoped.

12. **Unverified-claims-drive-trust.** Anywhere self-declared identity,
    capability, or metadata influences an access/trust decision without
    independent verification. Example: a request header `X-User-Role: admin`
    set by an internal gateway is trusted by the backend with no check that the
    request actually came through that gateway.

## Discovery convergence

Applying these heuristics is open-ended — investigate runs as a bounded saturation
loop instead of a fixed number of passes. Each discovery wave's candidate
fingerprints fold into `kb/discovery-ledger.json`; the loop stops when
`terminal_reason` is set — `saturated` (K=2 consecutive waves added no new
fingerprints) or `capped` (max_waves=5), whichever comes first. Saturation is a
recall floor, not a substitute for the adversarial coverage gate, which still runs
after the loop ends.
