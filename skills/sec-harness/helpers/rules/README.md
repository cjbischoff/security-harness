# Vendored SAST rules

## Semgrep
Vendored (not fetched at scan time) so scans need no network. Layout:
`rules/semgrep/<language>/**.yaml`. Vendor or refresh with:

    git clone --depth 1 https://github.com/semgrep/semgrep-rules \
      skills/sec-harness/helpers/rules/semgrep

Recon selects the `<language>` subdirs that match the target. `rules/smoke.yaml`
is the offline smoke-test ruleset used by the deterministic test fixture only.

## CodeQL
Uses the standard query suites from the CodeQL bundle (default:
`security-extended`) — no custom rules authored. Ensure packs are present:

    codeql pack download codeql/go-queries codeql/python-queries
