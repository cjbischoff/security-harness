"""Benchmark corpus: labelled positives + negatives per (repo, commit).

Positives = vulnerabilities the harness MUST find. Negatives = code it MUST NOT
report (this session's correctly-rejected leads). Every entry is pinned to an exact
commit and tagged by ``source`` so synthetic recall is never blended into the
headline number, and carries a ``lifecycle`` so a confirmed finding can be *locked*
into a regression assertion (Layer B).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

KINDS = ("positive", "negative")
SOURCES = ("real-confirmed", "dep-cve", "synthetic", "public-app")
# open: not yet resolved; locked: a confirmed finding pinned as a regression assertion
# (must keep being detected); accepted-risk: documented, intentionally not tested;
# fixed: remediated (should no longer be present).
LIFECYCLES = ("open", "locked", "accepted-risk", "fixed")


@dataclass
class CorpusEntry:
    """One labelled ground-truth item."""

    finding_id: str
    kind: str            # positive | negative
    source: str          # real-confirmed | dep-cve | synthetic | public-app
    cls: str             # attack-class key
    repo_url: str        # https://github.com/{org}/{repo}
    commit: str          # exact SHA containing (or lacking, for negatives) the bug
    file: str
    line: int
    description: str
    fingerprint: str = ""            # optional stable fingerprint for exact match
    lifecycle: str = "open"
    package: str = ""                # for dep-cve: name@version
    cve: str = ""                    # for dep-cve
    local_path: str = ""             # optional: scan this local checkout instead of cloning

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty if valid)."""
        errs = []
        if self.kind not in KINDS:
            errs.append(f"{self.finding_id}: bad kind {self.kind!r}")
        if self.source not in SOURCES:
            errs.append(f"{self.finding_id}: bad source {self.source!r}")
        if self.lifecycle not in LIFECYCLES:
            errs.append(f"{self.finding_id}: bad lifecycle {self.lifecycle!r}")
        # a target is either a clonable https repo OR a local checkout path
        if not self.local_path and not self.repo_url.startswith("https://"):
            errs.append(f"{self.finding_id}: need local_path or an https repo_url")
        if not self.local_path and not self.commit:
            errs.append(f"{self.finding_id}: missing commit (required for clone targets)")
        if self.kind == "positive" and not (self.file or self.package):
            errs.append(f"{self.finding_id}: positive needs a file or package")
        return errs

    @property
    def repo_key(self) -> tuple[str, str]:
        """The (target, commit) this entry is scanned under (local_path wins)."""
        return (self.local_path or self.repo_url, self.commit)

    @classmethod
    def from_dict(cls, d: dict) -> CorpusEntry:
        """Build from a JSON dict, tolerating extra keys."""
        known = {f: d[f] for f in cls.__dataclass_fields__ if f in d}
        return cls(**known)


@dataclass
class Corpus:
    """A loaded corpus: all entries across all repo files."""

    entries: list[CorpusEntry] = field(default_factory=list)

    def validate(self) -> list[str]:
        """Validate every entry + global uniqueness of finding_id."""
        errs: list[str] = []
        seen: set[str] = set()
        for e in self.entries:
            errs += e.validate()
            if e.finding_id in seen:
                errs.append(f"duplicate finding_id {e.finding_id}")
            seen.add(e.finding_id)
        return errs

    def positives(self) -> list[CorpusEntry]:
        return [e for e in self.entries if e.kind == "positive"]

    def negatives(self) -> list[CorpusEntry]:
        return [e for e in self.entries if e.kind == "negative"]

    def locked(self) -> list[CorpusEntry]:
        return [e for e in self.entries if e.lifecycle == "locked"]

    def by_repo(self) -> dict[tuple[str, str], list[CorpusEntry]]:
        """Group entries by (repo_url, commit) — one scan per group."""
        groups: dict[tuple[str, str], list[CorpusEntry]] = {}
        for e in self.entries:
            groups.setdefault(e.repo_key, []).append(e)
        return groups


def load_corpus(corpus_dir: str | Path) -> Corpus:
    """Load every ``*.json`` file in a corpus directory into one Corpus.

    Each file is a JSON array of entry dicts (one file per repo, by convention).

    Args:
        corpus_dir: Directory of corpus JSON files.

    Returns:
        The merged, unvalidated :class:`Corpus` (call ``.validate()``).
    """
    base = Path(corpus_dir)
    entries: list[CorpusEntry] = []
    for p in sorted(base.glob("*.json")):
        data = json.loads(p.read_text())
        for d in data:
            entries.append(CorpusEntry.from_dict(d))
    return Corpus(entries=entries)
