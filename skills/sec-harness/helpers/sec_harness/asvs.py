"""OWASP ASVS 5.0 loader (F1).

Loads a requirement catalog (`references/asvs/asvs_5.0.0.json`) and indexes it by id /
chapter / CWE so the rule-matcher can attach citable control IDs to findings and inject
requirement text into guided prompts. Ships a curated seed (the requirements our attack
classes map to); the full catalog can be vendored later — the loader works on either.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AsvsRequirement:
    """One ASVS 5.0 requirement."""

    id: str                      # e.g. "1.2.5"
    description: str
    level: int = 1
    chapter: str = ""            # e.g. "V1"
    chapter_name: str = ""
    cwe: list[str] = field(default_factory=list)      # ["CWE-78"]
    keywords: list[str] = field(default_factory=list)

    @property
    def full_id(self) -> str:
        """Version-prefixed id for stable cross-version references."""
        return f"v5.0.0-{self.id}"


@dataclass
class AsvsCatalog:
    """Indexed ASVS requirements."""

    requirements: list[AsvsRequirement] = field(default_factory=list)

    def __post_init__(self):
        self._by_id = {r.id: r for r in self.requirements}
        self._by_cwe: dict[str, list[AsvsRequirement]] = {}
        for r in self.requirements:
            for c in r.cwe:
                self._by_cwe.setdefault(c, []).append(r)

    def get(self, req_id: str) -> AsvsRequirement | None:
        return self._by_id.get(req_id)

    def by_cwe(self, cwe: str) -> list[AsvsRequirement]:
        return self._by_cwe.get(cwe, [])

    def format_for_prompt(self, ids: list[str]) -> str:
        """Render selected requirements as injectable prompt lines."""
        out = []
        for rid in ids:
            r = self._by_id.get(rid)
            if r:
                cwe = f" ({', '.join(r.cwe)})" if r.cwe else ""
                out.append(f"- {r.full_id}: {r.description}{cwe}")
        return "\n".join(out)

    @classmethod
    def load(cls, path: str | Path) -> AsvsCatalog:
        """Load from a JSON catalog file (``{version, requirements: [...]}``)."""
        data = json.loads(Path(path).read_text())
        reqs = [AsvsRequirement(**{k: v for k, v in r.items()
                                   if k in AsvsRequirement.__dataclass_fields__})
                for r in data.get("requirements", [])]
        return cls(requirements=reqs)


def default_catalog_path() -> Path:
    """Path to the shipped ASVS seed catalog (under skills/sec-harness/references)."""
    return Path(__file__).resolve().parents[2] / "references" / "asvs" / "asvs_5.0.0.json"
