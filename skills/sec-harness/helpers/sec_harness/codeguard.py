"""CodeGuard-style secure-coding knowledge loader (F1).

Loads `references/codeguard/*.md` — one file per domain, YAML-ish frontmatter
(`description`, `languages`, `always_apply`) + a markdown body of guidance. The
rule-matcher attaches rule IDs to findings; guided prompts inject the (token-lean)
body. Custom frontmatter parser (no PyYAML dependency), mirroring Cisco's loader.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CodeguardRule:
    """One CodeGuard knowledge file."""

    rule_id: str
    description: str = ""
    languages: list[str] = field(default_factory=list)
    always_apply: bool = False
    body: str = ""

    def format_for_prompt(self, max_chars: int = 1500) -> str:
        """Bullet/numbered lines of the body, truncated — token-lean for prompts."""
        picked = [ln for ln in self.body.splitlines()
                  if ln.strip().startswith(("-", "*", "1.", "2.", "3.", "#"))]
        text = "\n".join(picked) if picked else self.body
        return text[:max_chars]


_FM = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Parse leading ``--- ... ---`` frontmatter; return (fields, body)."""
    m = _FM.match(text)
    if not m:
        return {}, text
    fm, body = {}, m.group(2)
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if v.startswith("[") and v.endswith("]"):
            fm[k] = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
        elif v.lower() in ("true", "false"):
            fm[k] = v.lower() == "true"
        else:
            fm[k] = v.strip("'\"")
    return fm, body


def load_rule(path: str | Path) -> CodeguardRule:
    """Load one CodeGuard markdown file."""
    p = Path(path)
    fm, body = _parse_frontmatter(p.read_text())
    return CodeguardRule(
        rule_id=fm.get("rule_id", p.stem),
        description=fm.get("description", ""),
        languages=fm.get("languages", []),
        always_apply=bool(fm.get("always_apply", False)),
        body=body.strip(),
    )


def load_rules(codeguard_dir: str | Path) -> dict[str, CodeguardRule]:
    """Load every ``*.md`` in a directory into ``{rule_id: CodeguardRule}``."""
    base = Path(codeguard_dir)
    rules: dict[str, CodeguardRule] = {}
    for p in sorted(base.glob("*.md")):
        r = load_rule(p)
        rules[r.rule_id] = r
    return rules


def default_codeguard_dir() -> Path:
    """Path to the shipped CodeGuard knowledge dir (under skills/sec-harness/references)."""
    return Path(__file__).resolve().parents[2] / "references" / "codeguard"
