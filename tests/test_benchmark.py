"""The labelled corpus as a regression gate: full recall, zero false
positives on benign projects, and every registered rule exercised."""

from __future__ import annotations

from pathlib import Path

from benchmarks.run import evaluate


def test_corpus_metrics(tmp_path: Path) -> None:
    m = evaluate(tmp_path)
    missed = {r.case.name: sorted(r.missed) for r in m.results if r.missed}
    fps = {r.case.name: sorted(r.unexpected) for r in m.results if r.unexpected}
    assert not missed, f"recall regression: {missed}"
    assert not fps, f"false positives on benign cases: {fps}"
    assert not m.uncovered_rules, f"rules with no corpus case: {sorted(m.uncovered_rules)}"
