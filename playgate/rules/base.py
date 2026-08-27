"""Rule registry.

A rule is a function that takes a ScanContext and yields Findings. Rules must
be side-effect free and must never raise on odd input — a rule that throws is
caught by the runner and reported as a note, so one bad rule cannot sink a scan.
"""

from __future__ import annotations

from typing import Callable, Iterable, Iterator

from ..models import Finding, ScanContext

Rule = Callable[[ScanContext], Iterable[Finding]]

_REGISTRY: list[tuple[str, Rule]] = []


def rule(name: str) -> Callable[[Rule], Rule]:
    def decorator(func: Rule) -> Rule:
        _REGISTRY.append((name, func))
        return func

    return decorator


def all_rules() -> list[tuple[str, Rule]]:
    return list(_REGISTRY)


def run_all(ctx: ScanContext) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    for name, func in all_rules():
        try:
            findings.extend(func(ctx))
        except Exception as exc:  # noqa: BLE001 - a broken rule must not stop the scan
            errors.append(f"rule {name} failed: {type(exc).__name__}: {exc}")
    return findings, errors


def iter_matches(text: str, pattern) -> Iterator:
    """Yield regex matches, tolerating catastrophic input sizes."""
    if len(text) > 4_000_000:
        text = text[:4_000_000]
    yield from pattern.finditer(text)
