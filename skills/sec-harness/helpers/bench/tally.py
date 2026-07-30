"""Tally judge results into a scorecard: precision/recall by source & class, plus
Layer-B regressions (a locked finding that stopped being detected = hard failure).

Synthetic recall is reported as its own row and never folded into the headline, so a
corpus padded with easy seeded bugs can't flatter the score.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def _metrics(results) -> dict:
    """Compute tp/fn/fp/tn + precision/recall for a set of JudgeResults."""
    tp = sum(1 for r in results if r.kind == "positive" and r.detected)
    fn = sum(1 for r in results if r.kind == "positive" and not r.detected)
    fp = sum(1 for r in results if r.kind == "negative" and r.detected)  # wrongly flagged
    tn = sum(1 for r in results if r.kind == "negative" and not r.detected)
    recall = tp / (tp + fn) if (tp + fn) else None
    precision = tp / (tp + fp) if (tp + fp) else None
    fp_rate = fp / (fp + tn) if (fp + tn) else None
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": recall, "precision": precision, "fp_rate": fp_rate}


@dataclass
class Scorecard:
    """The benchmark result."""

    overall: dict
    by_source: dict
    by_class: dict
    regressions: list = field(default_factory=list)   # locked positives now missed
    missed: list = field(default_factory=list)         # all missed positives (for analyze-misses)
    false_positives: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall": self.overall,
            "by_source": self.by_source,
            "by_class": self.by_class,
            "regressions": self.regressions,
            "missed": self.missed,
            "false_positives": self.false_positives,
            "regressed": bool(self.regressions),
        }

    def to_markdown(self) -> str:
        def pct(x):
            return "-" if x is None else f"{x * 100:.0f}%"
        o = self.overall
        lines = ["# sec-harness benchmark scorecard", "",
                 "## Headline (real-confirmed only)",
                 "",
                 (f"- Recall: **{pct(self._real.get('recall'))}** "
                  f"({self._real.get('tp',0)}/{self._real.get('tp',0)+self._real.get('fn',0)})"),
                 (f"- Precision: **{pct(self._real.get('precision'))}**  |  "
                  f"FP-rate: {pct(self._real.get('fp_rate'))}"),
                 "",
                 "## Overall (all sources)", "",
                 (f"- Recall {pct(o['recall'])} | Precision {pct(o['precision'])} | "
                  f"FP-rate {pct(o['fp_rate'])} | tp={o['tp']} fn={o['fn']} fp={o['fp']} tn={o['tn']}"),
                 "", "## By source", "",
                 "| source | recall | precision | fp-rate | tp | fn | fp | tn |",
                 "|--------|--------|-----------|---------|----|----|----|----|"]
        for src, m in sorted(self.by_source.items()):
            lines.append(f"| {src} | {pct(m['recall'])} | {pct(m['precision'])} | "
                         f"{pct(m['fp_rate'])} | {m['tp']} | {m['fn']} | {m['fp']} | {m['tn']} |")
        lines += ["", "## By class", "",
                  "| class | recall | fp-rate | tp | fn | fp |",
                  "|-------|--------|---------|----|----|----|"]
        for cls, m in sorted(self.by_class.items()):
            lines.append(f"| {cls} | {pct(m['recall'])} | {pct(m['fp_rate'])} | "
                         f"{m['tp']} | {m['fn']} | {m['fp']} |")
        if self.regressions:
            lines += ["", "## ❌ REGRESSIONS (locked findings no longer detected)", ""]
            lines += [f"- {fid}" for fid in self.regressions]
        if self.false_positives:
            lines += ["", "## False positives (flagged a known-negative)", ""]
            lines += [f"- {fid}" for fid in self.false_positives]
        return "\n".join(lines) + "\n"

    _real: dict = field(default_factory=dict)


def tally(results, corpus) -> Scorecard:
    """Aggregate judge results into a :class:`Scorecard`.

    Args:
        results: List of :class:`bench.judge.JudgeResult`.
        corpus: The :class:`bench.corpus.Corpus` (for lifecycle/regression checks).

    Returns:
        A :class:`Scorecard`. ``.regressions`` lists locked positives now missed —
        a hard failure gate for CI/tuning ratchets.
    """
    overall = _metrics(results)
    by_source: dict = {}
    for src in {r.source for r in results}:
        by_source[src] = _metrics([r for r in results if r.source == src])
    by_class: dict = {}
    for cls in {r.cls for r in results}:
        by_class[cls] = _metrics([r for r in results if r.cls == cls])

    locked_ids = {e.finding_id for e in corpus.locked()}
    regressions = [r.finding_id for r in results
                   if r.finding_id in locked_ids and r.kind == "positive" and not r.detected]
    missed = [r.finding_id for r in results if r.kind == "positive" and not r.detected]
    fps = [r.finding_id for r in results if r.kind == "negative" and r.detected]

    sc = Scorecard(overall=overall, by_source=by_source, by_class=by_class,
                   regressions=regressions, missed=missed, false_positives=fps)
    sc._real = _metrics([r for r in results if r.source == "real-confirmed"]) or {}
    return sc
