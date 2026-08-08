# sec-harness run observations — AEM 4-repo campaign (2026-08-07)

Live log of inefficiencies + inaccuracies observed while running full agentic campaigns
against: aem-analytics (product module), aem-event-service + tanium-aem-analytics-service
(eng/go services), aem-analytics-infra (Gen2 Azure). Append per campaign. Severity:
🔴 correctness (wrong result / silent coverage loss) · 🟠 accuracy/doc drift · 🟡 efficiency.

## Doc / API drift (would mislead an operator following SKILL.md verbatim)

- 🟠 **`begin_pass` signature.** SKILL.md shows `begin_pass(<WS>, <sha>)` implying a path
  string; it requires a `Workspace` object (`begin_pass(Workspace(Path(ws)), sha)`) and
  raises `AttributeError: 'str' object has no attribute 'state_path'` otherwise. Same for
  every helper that takes `ws` — all need `Workspace(Path(...))`, not a str.
- 🟠 **`demote_noise` / `reconcile_plan` import path.** SKILL.md Phase 5 implies
  `from sec_harness.prefilter import ...`; they live in `sec_harness.partition`
  (`merge_custom_check_classes` in `sec_harness.custom_checks`). ImportError if followed literally.
- 🟠 **`memory` CLI ignores `--workspace`.** `python -m sec_harness.cli memory --target T --workspace W`
  errors `unrecognized arguments: --workspace`. `memory` only reads the default sidecar, so a
  custom-workspace run can't use the `--learn` / status path. (Learnings had to be written to the
  workspace `learnings/` dir by hand.)

## Correctness bugs (silent wrong result if trusted blindly)

- 🔴 **Phase-gate ref parser vs recon evidence format.** `recon.md` instructs writing
  `attack_surface_evidence` as `"file:line — <prose>"`. `phase_gate._parse_ref` /
  `run_phase_checks` only accept a bare `file:line`, so EVERY `surf-<class>` claim was
  deterministically **rejected** (refs "don't resolve"). Applied blindly, this drops the entire
  attack surface → gutted investigation. The file:line prefixes DO resolve; only the trailing
  prose breaks parsing. Fix options: (a) `_parse_ref` should take the leading `path:line` token
  and ignore trailing text; or (b) recon should emit refs and descriptions in separate fields.
  Workaround used: orchestrator cleaned refs before `run_phase_checks`.
- 🔴 **`calibrate` never scores `needs-deployment-testing`.** `calibrate` sets `risk_score`
  only on `confirmed`. For modules whose findings are all out-of-repo-enforced (product-module
  solution repo), everything lands `needs-deployment-testing` with `risk_score=None`, so
  `redteam` render has nothing to prioritize on (default `--min-risk 7` excludes them silently).
  Had to hand-score by severity band. `promote_runtime_dependent` + `calibrate` should assign a
  provisional risk to `needs-deployment-testing` findings too.
- 🟠 **`repo_slug` collides across monorepo sub-services.** Slug hashes the git *origin* URL, so
  `internal/aemeventservice` and `internal/aemanalytics` produce the identical slug
  `go-9530ad70`. Only saved from collision because `memory_root(target)` roots the sidecar under
  the (distinct) subdir. Under `$SEC_HARNESS_HOME` (shared external base) both services would
  write to the same folder and clobber each other. Slug identity should include the target subpath
  when it differs from the repo root.

- 🔴 **Monorepo subdir target vs repo-root-relative refs.** Campaign 2 target = `internal/aemeventservice`,
  but recon emitted entrypoint/subsystem paths repo-root-relative (`internal/aemeventservice/...`) and
  some refs (`cmd/aem-event-service`, `pkg/aemeventservice/*.proto`) live *outside* the subdir entirely.
  `run_phase_checks(claims, target=subdir)` rejected 20/26 claims (paths don't resolve under the subdir;
  the proto/cmd refs can never resolve there). Resolving against the **monorepo root** → 0 rejects.
  Fix: `phase_gate` ref resolution base must be the git repo root, not the scan-scope subdir, for
  monorepo sub-service scans (or recon must emit subdir-relative paths AND the harness must accept
  out-of-scope context refs). This affects every eng/go sub-service audit. Same base mismatch will hit
  prefilter/investigate path handling — watch dedupe fingerprints + finding `file` fields.
- 🔴 **Inconsistent path base BETWEEN agents in one campaign.** Same campaign 2: recon emitted
  repo-root-relative refs (`internal/aemeventservice/processor/events.go`); the architecture agent
  emitted service-subdir-relative refs (`processor/events.go`, `server.go:55`) and some bare
  filenames (`responder.go:303`). `phase_gate` has no canonical resolution base, so the orchestrator
  had to guess a different base per phase (repo-root for recon, service-dir for architecture) to get
  refs to resolve. There must be ONE declared base (e.g. a `repo_root` + `scan_scope` recorded in
  state) that every agent cites against and every gate resolves against. Bare filenames
  (`responder.go` when both `responder/` and `v2/responder/` exist) are ambiguous and should be
  rejected by the prompt contract, not the parser.

- 🟠 **Finding `file` field base also inconsistent.** CTL-0002 (authn agent) wrote
  `file: internal/aemeventservice/server.go` (repo-root-relative) while the authz agent wrote
  service-relative (`v2/responder/responder.go`). Inconsistent finding `file` bases break dedupe
  fingerprinting (enclosing-symbol lookup + `(file,line,cls)` collision key) and produce mixed
  paths in `report.md`. Same root cause as the phase-gate base issue — needs one declared base.
- 🟠 **`runtime_test` written as a string.** The authn investigate agent set `runtime_test` to a
  prose string; schema expects `object|null`. `findings_gate` surfaced it but exited 0 (warning,
  not fail) — a malformed load-bearing field slipping past the gate as a warning is risky; consider
  making schema-type violations fail the gate.
- 🟡 **Same candidate routed to two investigate agents.** `math/rand` C-0006/C-0007 were handed to
  BOTH the `crypto` and `security-other` agents (parallel) — double work + a write-race on the same
  finding file (both rejected consistently here, so no corruption, but the last-writer-wins race is
  the ISSUE-017 class). Candidate→class routing should be a partition, not overlapping sets.
- 🟡 **Cross-class near-duplicates not merged.** AUTHZ-0003 and BIZ-0004 both key on
  `v2/responder/responder.go:295` (modelVersion) under different `cls`; dedupe keys on
  `(file,line,cls)` so they survive as two findings. A same-(file,line) different-cls pair should at
  least be cross-linked so the report doesn't double-count one root cause.

- 🔴 **Monorepo base breaks `verify` patch-apply.** The patch agent wrote a diff with repo-root
  path (`--- a/internal/aemeventservice/server.go`), but `verify --target internal/aemeventservice`
  copies the service dir as root, so `git apply` can't match the prefixed path → `fixed 0`,
  `verification: static-only` (the patch is sound and passed `git apply --check` against the
  monorepo root, just not against the subdir copy). Confirms the base mismatch propagates all the
  way to patch verification. One canonical `repo_root` would fix gate + dedupe + verify at once.

## Reporting gaps

- 🔴 **`report.md` renders confirmed/fixed only.** For a product-module solution repo whose real
  findings are all `needs-deployment-testing` (enforcement out-of-repo), `report.md` shows only
  the low dev-dependency CVEs → reads as a near-clean bill while the redteam-plan carries the
  actual authz risk. `report.md` should include a `needs-deployment-testing` section (or a
  pointer + count) so the main report doesn't understate the audit.

- 🔴 **Judge/validate severity cap not written to the `severity` field.** Judge returned
  `severity-inflated` and validate agreed "medium (judge-capped)" for the CE-spoof cluster, but both
  only stated it in their return text — the finding's `severity` field stayed `high`. Downstream
  severity→risk scoring then pulled 7 (high) instead of 5. A `severity-inflated`/`downgrade` verdict
  must mechanically rewrite the `severity` field (or calibrate must read `judge_verdict` and cap),
  else the cap is cosmetic. Orchestrator corrected the 4 findings by hand.

- 🟠 **`severity: informational` not in the `Severity` enum, but `report.md` renders an "info"
  bucket.** Setting a finding to `informational` (a natural disposition for by-design/low-value
  observations) makes `models` reject it as unparseable — `reconcile_plan` logged
  `'informational' is not a valid Severity` and SKIPPED the finding. Either add `informational` to
  the enum (report already has the bucket) or drop the report bucket. Orchestrator set CTL-0001 to
  `low` as the floor.

## Efficiency

- 🟡 **Phase cost not scaled to repo size.** aem-analytics is 4 security-relevant files; it still
  ran full recon+architecture+threat-model each with a per-phase opus adversary (architecture
  emitted 22 gate claims). Gates DID catch real defects (see wins), but consider a repo-size /
  file-count heuristic that collapses architecture+threat-model for tiny repos.
- 🟡 **Deps class needs no LLM but isn't auto-confirmed.** 3 SCA `deps` candidates carried valid
  `sca:osv:*` receipts yet stayed `candidate` (no investigate agent routes `deps`); orchestrator
  had to promote + reachability-annotate them by hand. A deterministic deps→confirmed promotion
  (with reachability heuristic: lockfile-only/devDependency → low) would remove manual steps.

## Token-saving + parallelization methods (validated in campaign 3, ~8 agents vs ~20 in campaign 2 for comparable rigor)

- **Declare ONE canonical path base up front** (service-relative for a monorepo sub-service) and tell
  every agent to cite against it → **0 gate re-seeds** (campaign 2 spent ~6 tool calls re-seeding gates
  after base mismatches). Single biggest saver; also fixes the correctness bug.
- **Reuse the opus context-adversary's output as the architecture/threat-model.** When the context
  phase already enumerates components, trust boundaries, and leads with adversary-verified citations,
  the orchestrator authors `architecture.md` + `THREAT_MODEL.md` directly instead of spawning 2 agents
  + their 2 opus adversaries. Saves ~3-4 agents. Tradeoff: less independent challenge of arch/TM —
  safe ONLY because (a) context was opus-validated, (b) every finding still passes opus validate,
  (c) surface stays conservative. Restore full phase-adversaries when the codebase has many live findings.
- **Gate by exception:** run the cheap deterministic `phase_gate` ref-check always; spawn the opus
  phase-adversary only when a phase adds *material new* claims beyond already-validated context.
- **Settle pre-reviewed candidates deterministically:** apply the context-adversary's verdict to CTL-*
  terminal states in code (no re-validation agent).
- **Skip the dedicated agent for a class with one already-reviewed low finding** (crypto here); triage a
  lone benign SAST candidate (math/rand) by folding it into an adjacent agent's remit.
- **One opus validate over only the un-validated raw finding(s)**; skip critic/judge when the raw set is
  tiny and pre-vetted. Skip redteam-adversary when the plan has ≤2 already-validated items.
- **Parallelize investigate**: all classes in one message (fan-out); here 3 agents at once.
- **Deterministic-first still does the heavy lifting**: git-history mining (AA-714 seed) pointed the
  decompression hunt precisely; SAST/codeql pre-narrowed the surface so agents didn't wander.

## Wins (adversarial layers earning their cost — keep)

- ✅ recon phase-adversary caught an over-anchored `secrets` surface (dev RFC-1918 IP treated as a
  credential) and an out-of-repo `business-logic` lead stated as in-repo fact.
- ✅ architecture phase-adversary caught a real line-range error (cited range `123-156` included
  the exception line 133) and 5 in-repo→out-of-repo overclaims.
- ✅ context-adversary (campaign 2) INVALIDATED a "mTLS+JWT bound to cert" PRESENT control that
  had no inbound code (distributor.go:107 is outbound creds) → raised CTL-0002, the root enabler
  of the CE-spoof finding. High-value catch.
- ✅ redteam-adversary caught a payload that claimed 3 privileges were TaaS-grantable when only
  1 is `unrestrictedInTaas`, and merged a redundant finding (BIZ-0001 → AUTHZ-0001).

## Corrections (2026-08-07, verified in source)

- 🔴 **gate warns-not-fails on schema-type violation — WITHDRAWN**: a `| tail; echo $?` pipe masked the real exit; `finding.schema.json:39-41` types `runtime_test`/`reachability` and `findings_gate.main` returns exit 1 on a violation. No code change needed.
- 🟠 **`severity: informational` rejected by enum — as-designed**: `Severity.INFO='info'` exists; `informational` is a *status* value an agent wrongly put in `severity`. Fixed by prompt guard (Plan 2 T4), not an enum change.
- 🔴 **`calibrate` never scores needs-deployment-testing — confirmed real**, fixed in Plan 2 T1.
- 🔴 **judge severity-cap not applied — confirmed real**, fixed in Plan 2 T2 (lower-only).
- 🟡 **deps not auto-promoted — confirmed real**, fixed in Plan 2 T3. `promote_runtime_dependent` was already auto-called (ISSUE-027 done).
- 🟡 **same candidate routed to two agents — operator error, not a code bug**: `partition` assigns one `cls` per candidate; the double-dispatch was a hand-authored orchestration mistake. Guarded by the SKILL one-candidate-one-agent rule (Plan 2 T4).
