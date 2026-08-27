"""Scan orchestration."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from .collect import build_context
from .models import Finding, Report, Severity
from .rules import run_all
from .rules.policy import deadline_note


def _ignore_matches(finding: Finding, spec: str) -> bool:
    """A suppression spec is ``RULE-ID`` or ``RULE-ID:<path-substring>``."""
    spec = spec.strip()
    if not spec:
        return False
    rule_id, _, scope = spec.partition(":")
    if finding.id != rule_id.strip():
        return False
    scope = scope.strip()
    if not scope:
        return True
    where = finding.location.render().replace("\\", "/")
    return scope.replace("\\", "/") in where


def _apply_ignore(findings: list[Finding], ignore: list[str]) -> tuple[list[Finding], int]:
    if not ignore:
        return findings, 0
    kept = [f for f in findings if not any(_ignore_matches(f, spec) for spec in ignore)]
    return kept, len(findings) - len(kept)


def scan(
    target: Path,
    listing_path: Path | None = None,
    min_severity: Severity = Severity.INFO,
    baseline: set[str] | None = None,
    today: date | None = None,
) -> Report:
    ctx = build_context(target, listing_path=listing_path)
    findings, errors = run_all(ctx)

    notes = list(ctx.notes) + errors
    inputs: list[str] = []
    for manifest in ctx.manifests:
        if manifest.source_path:
            inputs.append(manifest.source_path)
    if ctx.build.source_path:
        inputs.append(ctx.build.source_path)
    if ctx.listing and ctx.listing.source_path:
        inputs.append(ctx.listing.source_path)
    if not ctx.manifests and ctx.kind.value != "unknown":
        notes.append("No AndroidManifest.xml was parsed — manifest rules did not run.")

    # Suppress findings the developer has consciously accepted (playgate.toml ignore).
    ignore = ctx.listing.ignore if ctx.listing else []
    findings, suppressed = _apply_ignore(findings, ignore)
    if suppressed:
        notes.append(f"{suppressed} finding(s) suppressed by the ignore list in playgate.toml.")

    # Baseline: drop anything already present in a prior report, so CI only
    # fails on findings introduced since.
    if baseline is not None:
        before = len(findings)
        findings = [f for f in findings if f.fingerprint() not in baseline]
        skipped = before - len(findings)
        if skipped:
            notes.append(f"{skipped} pre-existing finding(s) hidden by --baseline; showing new only.")

    stale = deadline_note(today or date.today())
    if stale:
        notes.append(stale)

    kept = [f for f in findings if f.severity >= min_severity]
    return Report(
        root=str(ctx.root),
        kind=ctx.kind,
        findings=kept,
        notes=notes,
        inputs=sorted(set(inputs)),
    )


def load_baseline(path: Path) -> set[str]:
    """Read finding fingerprints from a prior JSON report for --baseline."""
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read baseline {path.name}: {exc}") from exc
    prints: set[str] = set()
    for f in data.get("findings", []):
        fp = f.get("fingerprint")
        if fp:
            prints.add(fp)
            continue
        # Older report without an explicit fingerprint: re-derive it. The stored
        # location renders as "path:line"; strip the trailing line to get the path.
        raw = f.get("location") or ""
        path_part = "" if raw in {"", "-"} else raw
        if ":" in path_part:
            head, tail = path_part.rsplit(":", 1)
            if tail.isdigit():
                path_part = head
        prints.add(f"{f.get('id', '')}|{path_part}|{f.get('title', '')}")
    return prints
