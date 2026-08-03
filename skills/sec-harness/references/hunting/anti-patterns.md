# Auditor anti-patterns

Ten failure modes that produce false positives, missed findings, or wasted
review cycles. Check your own output against this list before it leaves the
investigate/critic/validate stage — each one has burned a real finding in a
prior run.

1. **Needing the word "potentially."** If a sentence needs "potentially,"
   "may be," "could possibly," or "it's conceivable that," the research isn't
   done. Go read the code that would turn "potentially" into "confirmed" or
   "ruled out" — don't ship the hedge.

2. **Exploits built on an unverified runtime/parser assumption.** "This should
   overflow because the buffer looks small" or "this framework probably
   doesn't escape this" without checking the actual library version, the
   actual compiled behavior, or the actual spec is not evidence. Verify against
   the real implementation or mark it unverifiable.

3. **Reporting deviation-from-checklist as a finding.** "This doesn't use
   parameterized queries" or "this doesn't set `SameSite`" is not itself a
   finding — it's an indicator. The finding requires the deviation to actually
   be reachable and exploitable. A style mismatch with a security checklist,
   with no traced impact, is noise.

4. **Skipping business logic for scanner-shaped bugs.** SQLi/XSS/path-traversal
   are easy to describe and satisfying to find, so they crowd out the harder,
   higher-value business-logic and chained-attack classes that scanners can't
   see at all. If every finding in a report is scanner-shaped, the business
   logic pass didn't happen.

5. **Defense-in-depth absence reported as a finding.** "There's no WAF rule for
   this" or "there's no additional layer beyond the framework's own escaping"
   is not a finding when the primary control already closes the gap. Defense
   in depth is a hardening recommendation, not a vulnerability.

6. **Overstated confidence.** Calling a lead a "confirmed critical" because the
   shape matches a known CVE pattern, without tracing the actual reachability
   and impact in THIS codebase. Confidence must track evidence, not pattern
   familiarity.

7. **Stopping at the first caller.** Confirming a sink is guarded because the
   first call site you found checks it, without exhausting every other caller.
   A guard on one path and none on a sibling path is still exploitable through
   the sibling.

8. **Trusting a name or a comment as proof.** A function called
   `sanitizeInput` or a comment saying `// validated upstream` is a claim, not
   evidence — read the function or trace the upstream call before crediting it.

9. **Conflating "the model said no" with "the code prevents it."** For AI/LLM
   targets, a refusal from the model in one test is not a control — the code
   must actually gate the capability. Non-determinism means the next prompt
   might succeed; the absence of a code-level gate is the finding regardless of
   what any single model response showed.

10. **Reporting a CVE-shaped pattern without confirming it's reachable here.**
    Recognizing "this looks like CVE-2023-XXXX's pattern" is a lead, not a
    finding, until you've confirmed the same preconditions (input reachability,
    version, configuration) actually hold in this codebase — the same library
    used defensively, patched, or in an unreachable code path is not the same
    bug.

11. **Instance collapse.** Under-reporting a family of sibling bugs — same CWE,
    distinct concrete sinks/routes — as one representative finding. "Every
    handler in this router has the same missing check" is five findings, not
    one with an example. Expand every concrete instance into its own
    candidate; let dedupe merge only exact `(file,line,cls)` collisions, never
    a human summary of "the pattern."
