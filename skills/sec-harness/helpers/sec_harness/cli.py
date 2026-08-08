"""CLI entry point orchestrating the deterministic scan pipeline."""

from __future__ import annotations

import argparse
import json

from sec_harness.campaign import record_stage
from sec_harness.models import Finding
from sec_harness.normalize import normalize
from sec_harness.repo_memory import RepoMemory, repo_slug
from sec_harness.report import to_markdown
from sec_harness.sarif import to_sarif
from sec_harness.sast import run_semgrep
from sec_harness.scanscope import resolve as _resolve_scope
from sec_harness.scanscope import write_scope
from sec_harness.workspace import Workspace, load_paths, write_findings


def write_scan_scope(ws, target, *, sha: str = "", runner=None):
    """Resolve + persist the canonical ScanScope for a scan (called at pass start).

    Args:
        ws: Campaign workspace.
        target: The scan target path.
        sha: Pinned git SHA for the pass.
        runner: Injectable subprocess runner (tests); defaults to subprocess.run.

    Returns:
        The persisted :class:`sec_harness.scanscope.ScanScope`.
    """
    import subprocess
    _raw = runner or subprocess.run

    def r(cmd, **kwargs):
        # ponytail: adapt list→str so test fakes using `"show-toplevel" in cmd`
        # (substring check) work correctly; subprocess.run accepts both forms.
        return _raw(" ".join(cmd) if (runner and isinstance(cmd, list)) else cmd, **kwargs)

    scope = _resolve_scope(target, sha=sha, runner=r)
    scope.slug = repo_slug(target, runner=r)
    write_scope(ws, scope)
    return scope


def run_scan(
    target: str, ws: Workspace, config: str, *, sha: str | None = None
) -> list[Finding]:
    """Run the deterministic scan pipeline and write outputs.

    Steps: run semgrep -> normalize -> stamp discovery SHA -> persist findings ->
    emit SARIF + Markdown + findings.json -> record the prefilter stage. Pass
    lifecycle (``begin_pass``) is owned by the campaign supervisor, not this
    function, so a prefilter run never advances the pass counter.

    Args:
        target: Path to the codebase to scan.
        ws: Workspace to hold the KB and reports.
        config: Path to the semgrep rules file.
        sha: Git SHA to stamp onto each finding's ``discovery_sha``.

    Returns:
        The normalized findings.
    """
    ws.ensure()

    findings = normalize(run_semgrep(target, config))
    for f in findings:
        f.discovery_sha = sha
    write_findings(ws, findings)

    ws.sarif_path.write_text(json.dumps(to_sarif(findings), indent=2))
    ws.report_path.write_text(to_markdown(findings))
    ws.findings_json_path.write_text(json.dumps([f.to_dict() for f in findings], indent=2))
    record_stage(ws, "prefilter")
    return findings


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv``).

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(prog="sec-harness")
    sub = parser.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="Run the deterministic scan pipeline.")
    scan.add_argument("--target", required=True)
    scan.add_argument("--workspace", default=None,
                      help="Override the workspace; default is the in-repo per-repo "
                           "memory folder (<target>/.sec-harness/<slug>/, or "
                           "$SEC_HARNESS_HOME/<slug>/ if set).")
    scan.add_argument("--config", required=True)
    scan.add_argument("--sha", default=None)
    scan.add_argument("--reports-dir", default=None)
    scan.add_argument("--findings-dir", default=None)
    scan.add_argument("--kb-dir", default=None)
    scan.add_argument("--paths-config", default=None)

    mem = sub.add_parser("memory", help="Show/append the per-repo scan memory.")
    mem.add_argument("--target", required=True)
    mem.add_argument("--learn", default=None, help="Append a dated learning.")
    mem.add_argument("--tag", default="", help="Optional tag for the learning.")
    args = parser.parse_args(argv)

    if args.cmd == "scan":
        memory = None
        if args.workspace:
            ws = load_paths(
                workspace=args.workspace, paths_config=args.paths_config,
                reports_dir=args.reports_dir, findings_dir=args.findings_dir,
                kb_dir=args.kb_dir,
            )
        else:
            memory = RepoMemory.for_target(args.target)
            memory.ensure(target=args.target)
            ws = memory.workspace
        write_scan_scope(ws, args.target, sha=args.sha or "")
        findings = run_scan(args.target, ws, args.config, sha=args.sha)
        if memory is not None:
            memory.update_status()
        print(f"{len(findings)} findings; reports in {ws.reports}")
        return 0

    if args.cmd == "memory":
        memory = RepoMemory.for_target(args.target)
        memory.ensure(target=args.target)
        if args.learn:
            path = memory.record_learning(args.learn, tag=args.tag)
            print(f"learning recorded: {path}")
            return 0
        st = memory.run_status()
        state = "FINISHED" if st["finished"] else (
            f"RESUME at {st['next_phase']}" if st["resumable"] else "not started")
        print(f"memory: {memory.root}")
        print(f"status: {state} (pass {st['pass_number']} @ {st['active_sha']})")
        print(f"stages done: {', '.join(st['stages_done']) or '(none)'}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
