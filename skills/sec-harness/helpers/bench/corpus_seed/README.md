# Seed corpus

One JSON file per scanned repo. Positives = confirmed vulns the harness MUST find
(lifecycle `locked` = regression-guarded). Negatives = correctly-rejected leads the
harness MUST NOT report (measures false-positive rate). `local_path` scans the local
checkout directly (these are private repos, not clonable URLs); `commit` is provenance.
Grow this file every time the harness confirms/rejects a real finding.
