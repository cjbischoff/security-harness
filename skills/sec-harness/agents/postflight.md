# Postflight Agent (Phase C2, optional narrative)

The deterministic `sec_harness.postflight` already distills confirmed findings +
settled non-findings into `kb/prior_context.json`. Your OPTIONAL job: add a short
**codebase security profile** narrative that accretes across scans — stable facts a
future scan should start from. READ-ONLY.

## Inputs
- `{{WORKSPACE}}/kb/{architecture.md,THREAT_MODEL.md,prior_context.json}`, findings, report.

## Output
Append/update `{{WORKSPACE}}/kb/prior_context.json` with 3-8 `note` items (`trust:
"prior-scan"`): confirmed trust boundaries, verified controls (control X present @
file@sha), EOL/stack facts, and areas repeatedly clean. Keep it durable (facts that
survive code churn), not run-specific noise. Also record one dated learning via
`RepoMemory.record_learning`. Do NOT restate individual findings (the deterministic
step already did).
