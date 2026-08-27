"""Render a Report as terminal text, Markdown or JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__
from .models import Category, Finding, Report, Severity
from .standards import SCOPE, standards_for

ANSI = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[90m"

BAND_BLURB = {
    "CRITICAL": "At least one issue here blocks the upload or risks removal. Fix before submitting.",
    "HIGH": "Likely to be rejected or to require a declaration you have not filed yet.",
    "MEDIUM": "Nothing blocking, but reviewers commonly push back on these.",
    "LOW": "Minor policy hygiene.",
    "NONE": "No policy issues detected from the inputs provided.",
}


def _fmt_findings_text(findings: list[Finding], color: bool) -> list[str]:
    lines: list[str] = []
    for f in findings:
        tag = f"[{f.severity.name}]"
        if color:
            tag = f"{ANSI[f.severity]}{tag}{RESET}"
        head = f"  {tag} {f.title}"
        if color:
            head = f"  {tag} {BOLD}{f.title}{RESET}"
        lines.append(head)
        lines.append(f"      where : {f.location.render()}")
        if f.evidence:
            lines.append(f"      found : {f.evidence}")
        lines.append(f"      why   : {f.why}")
        lines.append(f"      fix   : {f.fix}")
        std = standards_for(f.id)
        if std:
            std_line = f"      std   : {' · '.join(std.labels())}"
            lines.append(f"{DIM}{std_line}{RESET}" if color else std_line)
        if f.refs:
            ref_line = f"      ref   : {f.refs[0]}"
            lines.append(f"{DIM}{ref_line}{RESET}" if color else ref_line)
        lines.append("")
    return lines


def to_text(report: Report, color: bool = True) -> str:
    counts = report.counts()
    band = report.rejection_band()
    lines = [
        "",
        f"playgate — {report.root}",
        f"project type: {report.kind}",
        "",
    ]
    summary = "  ".join(
        f"{name}:{counts[name]}" for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    lines.append(f"findings: {summary}")
    lines.append(f"play rejection risk: {band} ({report.rejection_score()}/100)")
    lines.append(f"  {BAND_BLURB[band]}")
    lines.append("")

    security = report.by_category(Category.SECURITY)
    policy = report.by_category(Category.POLICY)

    if security:
        lines.append(f"{BOLD}SECURITY{RESET}" if color else "SECURITY")
        lines.append("-" * 60)
        lines.extend(_fmt_findings_text(security, color))
    if policy:
        lines.append(f"{BOLD}GOOGLE PLAY POLICY{RESET}" if color else "GOOGLE PLAY POLICY")
        lines.append("-" * 60)
        lines.extend(_fmt_findings_text(policy, color))
    if not security and not policy:
        lines.append("No findings.")
        lines.append("")

    if report.inputs:
        lines.append("inputs read: " + ", ".join(report.inputs))
    for note in report.notes:
        lines.append(f"note: {note}")
    lines.append("")
    scope = (
        "standards: findings map to OWASP MASVS · MASTG · Mobile Top 10 (2024) · CWE. "
        "Not a certified / DAST / SCA scan; a clean report is 'not tested', not 'secure'."
    )
    lines.append(f"{DIM}{scope}{RESET}" if color else scope)
    lines.append("")
    return "\n".join(lines)


def _md_findings(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    for f in findings:
        lines.append(f"### `{f.severity.name}` {f.title}")
        lines.append("")
        lines.append(f"- **Where:** `{f.location.render()}`")
        if f.evidence:
            lines.append(f"- **Found:** `{f.evidence}`")
        lines.append(f"- **Why it matters:** {f.why}")
        lines.append(f"- **Fix:** {f.fix}")
        std = standards_for(f.id)
        if std:
            lines.append("- **Standards:** " + " · ".join(std.labels()))
        if f.refs:
            lines.append("- **Reference:** " + ", ".join(f"<{r}>" for r in f.refs))
        lines.append("")
    return lines


def to_markdown(report: Report) -> str:
    counts = report.counts()
    band = report.rejection_band()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# playgate report",
        "",
        f"**Target:** `{report.root}`  ",
        f"**Project type:** {report.kind}  ",
        f"**Generated:** {stamp}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {name} | {counts[name]} |")
    lines += [
        "",
        f"**Play rejection risk: {band}** ({report.rejection_score()}/100) — {BAND_BLURB[band]}",
        "",
        "> This score is a weighted sum of the policy findings below, capped at 100. It ranks "
        "work; it is not a probability, and a clean report is not an approval.",
        "",
    ]

    security = report.by_category(Category.SECURITY)
    policy = report.by_category(Category.POLICY)

    if policy:
        lines += ["## Google Play policy", ""]
        lines += _md_findings(policy)
    if security:
        lines += ["## Security", ""]
        lines += _md_findings(security)
    if not policy and not security:
        lines += ["No findings.", ""]

    if report.inputs:
        lines += ["## Inputs read", ""]
        lines += [f"- `{i}`" for i in report.inputs]
        lines.append("")
    if report.notes:
        lines += ["## Notes", ""]
        lines += [f"- {n}" for n in report.notes]
        lines.append("")

    lines += [
        "---",
        "",
        "## Standards & scope",
        "",
        "Findings map onto " + ", ".join(SCOPE["maps_to"]) + ". "
        f"Output format: {SCOPE['output_format']}.",
        "",
        "What this report is **not**:",
        "",
    ]
    lines += [f"- {item}" for item in SCOPE["not"]]
    lines.append("")
    return "\n".join(lines)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(report: Report) -> str:
    """SARIF 2.1.0 — uploadable to GitHub code scanning and other tools."""
    findings = report.sorted_findings()

    rules_by_id: dict[str, Finding] = {}
    for f in findings:
        rules_by_id.setdefault(f.id, f)
    rules = []
    for fid, f in sorted(rules_by_id.items()):
        std = standards_for(fid)
        props: dict = {
            "category": f.category.value,
            "security-severity": _security_severity(f.severity),
            "tags": (std.sarif_tags() if std else ["security"]),
        }
        if std:
            if std.cwe:
                props["cwe"] = [f"CWE-{n}" for n in std.cwe]
            if std.masvs:
                props["masvs"] = list(std.masvs)
            if std.owasp_mobile:
                props["owaspMobileTop10"] = std.owasp_mobile
        rule = {
            "id": fid,
            "name": f.id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.why},
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            "properties": props,
        }
        if f.refs:
            rule["helpUri"] = f.refs[0]
        rules.append(rule)

    results = []
    for f in findings:
        region: dict = {}
        uri = f.location.path
        if f.location.line:
            region["startLine"] = f.location.line
        location_block = []
        if uri:
            physical = {"artifactLocation": {"uri": uri.replace("\\", "/")}}
            if region:
                physical["region"] = region
            location_block = [{"physicalLocation": physical}]
        result = {
            "ruleId": f.id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}. {f.why} Fix: {f.fix}"},
            "partialFingerprints": {"playgate/v1": f.fingerprint()},
            "properties": {"severity": f.severity.name, "category": f.category.value},
        }
        if location_block:
            result["locations"] = location_block
        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "playgate",
                        "version": __version__,
                        "informationUri": "https://github.com/udogus986-ux/playgate",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _security_severity(severity: Severity) -> str:
    # GitHub reads this 0-10 number to colour the alert.
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "2.0",
        Severity.INFO: "0.0",
    }[severity]


def _finding_json(f: Finding) -> dict:
    data = f.to_dict()
    std = standards_for(f.id)
    if std is not None:
        data["standards"] = std.to_dict()
    return data


def to_json(report: Report) -> str:
    payload = {
        "root": report.root,
        "kind": report.kind.value,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "counts": report.counts(),
        "rejection_score": report.rejection_score(),
        "rejection_band": report.rejection_band(),
        "standards": SCOPE,
        "inputs": report.inputs,
        "notes": report.notes,
        "findings": [_finding_json(f) for f in report.sorted_findings()],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
