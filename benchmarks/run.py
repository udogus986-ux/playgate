"""Run the labelled corpus and report detection metrics.

    python -m benchmarks.run            # print the table
    python -m benchmarks.run --write    # also refresh benchmarks/RESULTS.md

Metrics:
  recall          expected findings detected / expected findings, over vulnerable cases
  false positives findings raised on benign (well-configured) cases
  rule coverage   rules that fired on at least one case / all registered rules
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from playgate import __version__
from playgate.collect import build_context
from playgate.rules import all_rules
from playgate.scan import scan

from .corpus import Case, cases


@dataclass
class CaseResult:
    case: Case
    found: set[str]
    missed: set[str]
    unexpected: set[str]  # only meaningful for benign cases


@dataclass
class Metrics:
    results: list[CaseResult]
    rules_fired: set[str]
    rules_total: set[str]

    @property
    def expected(self) -> int:
        return sum(len(r.case.expect) for r in self.results if not r.case.benign)

    @property
    def detected(self) -> int:
        return sum(len(r.case.expect) - len(r.missed) for r in self.results if not r.case.benign)

    @property
    def recall(self) -> float:
        return self.detected / self.expected if self.expected else 1.0

    @property
    def false_positives(self) -> int:
        return sum(len(r.unexpected) for r in self.results if r.case.benign)

    @property
    def uncovered_rules(self) -> set[str]:
        return self.rules_total - self.rules_fired


def evaluate(workdir: Path) -> Metrics:
    results: list[CaseResult] = []
    fired: set[str] = set()
    rules = all_rules()
    for case in cases():
        target = case.materialise(workdir)
        found = {f.id for f in scan(target).findings}
        if case.benign:
            results.append(CaseResult(case, found, set(), found))
        else:
            results.append(CaseResult(case, found, case.expect - found, set()))
        # Rule coverage: run each rule alone against this case's context.
        ctx = build_context(target)
        for name, func in rules:
            if name in fired:
                continue
            try:
                if any(True for _ in func(ctx)):
                    fired.add(name)
            except Exception:  # noqa: BLE001 - coverage probe only
                pass
    return Metrics(results, fired, {name for name, _ in rules})


def render(m: Metrics) -> str:
    lines = [
        f"# playgate benchmark — v{__version__}",
        "",
        "Synthetic corpus modelled on the vulnerability classes of well-known intentionally-insecure",
        "apps. Written alongside the rules, so these numbers are a **regression guarantee**, not an",
        "independent accuracy claim — see README for the external benchmark procedure.",
        "",
        f"- **Recall:** {m.detected}/{m.expected} expected findings detected ({m.recall:.0%})",
        f"- **False positives on benign projects:** {m.false_positives}",
        f"- **Rule coverage:** {len(m.rules_fired)}/{len(m.rules_total)} rules exercised",
        "",
        "| Case | Modelled on | Expected | Detected | Result |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in m.results:
        if r.case.benign:
            ok = not r.unexpected
            detail = "clean" if ok else "FP: " + ", ".join(sorted(r.unexpected))
            lines.append(f"| {r.case.name} | {r.case.inspired_by} | 0 (benign) | {len(r.unexpected)} | "
                         f"{'✓' if ok else '✗'} {detail} |")
        else:
            n = len(r.case.expect)
            got = n - len(r.missed)
            detail = "" if not r.missed else " missed: " + ", ".join(sorted(r.missed))
            lines.append(f"| {r.case.name} | {r.case.inspired_by} | {n} | {got} | "
                         f"{'✓' if not r.missed else '✗'}{detail} |")
    if m.uncovered_rules:
        lines += ["", "Rules not exercised: " + ", ".join(sorted(m.uncovered_rules))]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.run")
    parser.add_argument("--write", action="store_true", help="refresh benchmarks/RESULTS.md")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as tmp:
        m = evaluate(Path(tmp))
    text = render(m)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    print(text)
    if args.write:
        (Path(__file__).parent / "RESULTS.md").write_text(text, encoding="utf-8")
    return 0 if (m.recall == 1.0 and m.false_positives == 0 and not m.uncovered_rules) else 1


if __name__ == "__main__":
    raise SystemExit(main())
