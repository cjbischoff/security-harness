"""CLI: correlate N per-repo scans of one product into a cross-repo edge graph."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sec_harness.correlate.edges import (
    same_class_recurrence_edges,
    shared_dependency_edges,
    write_edges,
)
from sec_harness.correlate.ingest import ingest
from sec_harness.correlate.manifest import load_manifest
from sec_harness.correlate.workspace import CorrelationWorkspace


def main(argv: list[str] | None = None) -> int:
    """Run the deterministic correlation core (B-Plan 1).

    Args:
        argv: Optional argument vector.

    Returns:
        0 on success.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-correlate")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    cw = CorrelationWorkspace(Path(args.out))
    cw.ensure()
    cw.manifest_path.write_text(Path(args.manifest).read_text())  # copy manifest into the workspace
    ings = ingest(manifest)
    edges = shared_dependency_edges(ings) + same_class_recurrence_edges(ings)
    write_edges(cw.edges_path, edges)
    print(json.dumps({"edges": len(edges), "members": len(manifest.members)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
