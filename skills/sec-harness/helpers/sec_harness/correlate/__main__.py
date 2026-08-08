"""Entrypoint for python -m sec_harness.correlate."""

from __future__ import annotations

import sys

from sec_harness.correlate.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
