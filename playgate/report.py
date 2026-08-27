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


_PASS, _FAIL, _INFO, _NA = "PASS", "FAIL", "NEEDS-INFO", "N/A"
_MARK = {_PASS: "✓", _FAIL: "✗", _INFO: "?", _NA: "—"}


def _gate(present: set[str], block: set[str], *, needs: frozenset = frozenset()) -> str:
    if present & block:
        return _FAIL
    if present & needs:
        return _INFO
    return _PASS


def _play_gates(report: Report) -> list[tuple[str, list[tuple[str, str, str]]]]:
    present = {f.id for f in report.findings}
    sec_high = {f.id for f in report.findings
                if f.category is Category.SECURITY and f.severity >= Severity.HIGH}
    has_listing = "PLY-NO-LISTING" not in present
    perm = {i for i in present if i.startswith("PLY-PERM-")}

    def listing_gate(block: set[str]) -> str:
        if not has_listing:
            return _INFO
        return _FAIL if present & block else _PASS

    return [
        ("Build & bundle  (Play Console › Production › App bundle)", [
            ("Targets Android 16 / API 36", _gate(present, {"PLY-TARGET-API"}, needs=frozenset({"PLY-TARGET-UNKNOWN"})),
             "raise targetSdk; upload is refused below it"),
            ("Release build is not debuggable", _gate(present, {"AND-DEBUGGABLE", "BLD-DEBUGGABLE"}),
             "Play rejects debuggable uploads"),
            ("64-bit (ARM64) native code", _gate(present, {"UNI-NO-ARM64"}),
             "required when the app ships native libraries"),
            ("R8 shrinking/obfuscation on", _gate(present, {"BLD-NO-MINIFY"}),
             "recommended, not blocking"),
        ]),
        ("App content  (Play Console › Policy › App content)", [
            ("Privacy policy URL", listing_gate({"PLY-PRIVACY-POLICY"}),
             "App content › Privacy policy"),
            ("Data Safety matches the manifest", listing_gate({"PLY-DATA-SAFETY-GAP"}),
             "App content › Data safety"),
            ("Account deletion route", listing_gate({"PLY-ACCOUNT-DELETION"}),
             "App content › Data deletion"),
            ("Advertising ID handled", listing_gate({"PLY-ADID-MISSING", "PLY-ADID-CHILDREN"}),
             "App content › Advertising ID"),
            ("Restricted permissions declared", _FAIL if perm else _PASS,
             "App content › Sensitive app permissions"),
        ]),
        ("Store listing  (Play Console › Grow › Store presence)", [
            ("Title / description within limits",
             listing_gate({"PLY-TITLE-LENGTH", "PLY-SHORT-DESCRIPTION-LENGTH", "PLY-FULL-DESCRIPTION-LENGTH"}),
             "Main store listing"),
            ("No promo/keyword-stuffing text",
             listing_gate({"PLY-PROMO-TERMS", "PLY-KEYWORD-STUFFING", "PLY-TITLE-EMOJI", "PLY-TITLE-CAPS"}),
             "Main store listing"),
        ]),
        ("Monetisation  (Play Console › Monetise)", [
            ("Play Billing for digital goods", listing_gate({"PLY-BILLING"}),
             "Products › In-app products / Subscriptions"),
        ]),
        ("Testing & release  (Play Console › Test and release)", [
            ("Closed test done (new personal accounts)", listing_gate({"PLY-CLOSED-TESTING"}),
             "Testing › Closed testing — 12 testers × 14 days"),
        ]),
        ("Security (pre-release hygiene)", [
            ("No hard-coded secrets in the build",
             _FAIL if {i for i in sec_high if i.startswith("SEC-")} else _PASS,
             "rotate and move server-side"),
            ("TLS validation intact, no cleartext",
             _gate(present, {"CODE-TLS-TRUSTALL", "CODE-TLS-VERIFY-TRUE", "AND-CLEARTEXT", "AND-NETSEC-CLEARTEXT"}),
             "insecure comms"),
            ("Exported components guarded", _gate(present, {"AND-EXPORTED-OPEN", "AND-EXPORTED-UNSET"}),
             "any app can reach them otherwise"),
        ]),
    ]


def to_release_checklist(report: Report, color: bool = False) -> str:
    """A Play submission dry-run: every real upload gate as PASS / FAIL / NEEDS-INFO."""
    gates = _play_gates(report)
    fails = sum(1 for _, items in gates for _, status, _ in items if status == _FAIL)
    infos = sum(1 for _, items in gates for _, status, _ in items if status == _INFO)

    if fails:
        verdict, blurb = "NO-GO", f"{fails} blocking item(s) to fix before you submit."
    elif infos:
        verdict, blurb = "READY*", f"No blockers, but {infos} item(s) need a playgate.toml to confirm."
    else:
        verdict, blurb = "READY", "Every gate playgate can see is clear. Google still reviews what a tool cannot."

    lines = [
        "",
        f"playgate release readiness — {report.root}",
        f"project type: {report.kind}",
        "",
        f"VERDICT: {verdict}   {blurb}",
        "",
    ]
    for phase, items in gates:
        lines.append(f"{BOLD}{phase}{RESET}" if color else phase)
        lines.append("-" * 60)
        for name, status, detail in items:
            row = f"  [{_MARK[status]}] {status:10} {name}"
            if color and status == _FAIL:
                row = f"{ANSI[Severity.HIGH]}{row}{RESET}"
            lines.append(row)
            if status in (_FAIL, _INFO):
                lines.append(f"          → {detail}")
        lines.append("")
    lines.append(
        "Legend: PASS clear · FAIL blocks submission · NEEDS-INFO give a playgate.toml. "
        "A clean checklist is a pre-flight, not Google's decision."
    )
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
