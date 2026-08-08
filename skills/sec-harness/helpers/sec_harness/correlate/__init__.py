"""Read-only multi-repo correlation layer (Spec B).

Joins N per-repo sec-harness scans of one product into a cross-repo view. B-Plan 1 provides
the manifest, workspace, read-only ingest, and the two deterministic findings-joins
(shared-dependency, same-class recurrence). Re-thresholding, source-reading edges, and the
combined artifacts are B-Plan 2/3.
"""

from __future__ import annotations
