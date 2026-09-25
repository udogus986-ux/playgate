"""playgate command line interface."""

from __future__ import annotations

import argparse
import dataclasses
import os
import sys
from pathlib import Path

from . import __version__
from .models import Severity
from .report import to_json, to_markdown, to_release_checklist, to_sarif, to_text
from .rules import all_rules
from .scan import load_baseline, scan

TEMPLATE = '''# playgate listing declaration
#
# playgate cannot read Play Console, so describe your store entry here. Every
# field is optional; the checks that depend on a missing field are skipped.

title = "My App"
short_description = "One line, 80 characters maximum."
full_description = """
What the app does. Keep it factual: no ranking claims, no price or promotion
text, no keyword repetition.
"""

privacy_policy_url = "https://example.com/privacy"

# Accounts
account_creation = false          # does the app let users create an account?
in_app_account_deletion = false   # is there a delete-account screen in the app?
account_deletion_url = ""         # public https page to request deletion

# Monetisation
uses_ads = false
sells_digital_goods = false       # coins, subscriptions, unlocks, ad removal
uses_play_billing = false

# Audience
target_audience_children = false
content_rating = ""               # e.g. "Everyone", "Teen"

# Data Safety form: list the categories you declared in Play Console.
# Recognised values: location, contacts, photos_videos, audio, calendar,
# app_activity, health_fitness, advertising_id, personal_info, financial_info
data_safety_declared = []

# Release context
developer_account_type = "personal"   # personal | organization
first_release = false                 # first production release from this account

# Consciously-accepted findings. Each entry is a rule id, optionally scoped to a
# path substring so it only silences that one place. Run `playgate rules` for ids.
#   ignore = ["CODE-HTTP-URL:src/debug", "SEC-GENERIC:app/BuildConfig.kt"]
ignore = []
'''


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="playgate",
        description=(
            "Audit an Android project or package for security issues and "
            "Google Play rejection risk."
        ),
    )
    parser.add_argument("--version", action="version", version=f"playgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a project directory, .apk or .aab")
    scan_p.add_argument("target", nargs="?", default=".", help="path to scan (default: .)")
    scan_p.add_argument(
        "--listing", type=Path, default=None,
        help="path to a playgate.toml/.json listing file (default: auto-detect)",
    )
    scan_p.add_argument(
        "--format", choices=("text", "md", "json", "sarif", "html"), default="text",
        help="output format (sarif uploads to GitHub code scanning)",
    )
    scan_p.add_argument("-o", "--output", type=Path, default=None, help="write to a file")
    scan_p.add_argument(
        "--baseline", type=Path, default=None,
        help="a prior JSON report; hide findings already in it, show only new ones",
    )
    scan_p.add_argument(
        "--min-severity", choices=[s.name.lower() for s in Severity], default="info",
        help="hide findings below this severity",
    )
    scan_p.add_argument(
        "--fail-on", choices=[s.name.lower() for s in Severity] + ["never"], default="high",
        help="exit 1 when a finding at or above this severity exists (default: high)",
    )
    scan_p.add_argument("--no-color", action="store_true", help="disable ANSI colour")

    rel_p = sub.add_parser(
        "release", help="Google Play submission dry-run: every upload gate as PASS/FAIL",
    )
    rel_p.add_argument("target", nargs="?", default=".", help="path to scan (default: .)")
    rel_p.add_argument("--listing", type=Path, default=None, help="path to a playgate.toml/.json")
    rel_p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    rel_p.add_argument("--store", choices=("auto", "play", "appstore", "all"), default="auto",
                       help="which store to check (default: whichever the project ships to)")

    fix_p = sub.add_parser("fix", help="propose (or --apply) fixes for mechanical findings")
    fix_p.add_argument("target", nargs="?", default=".", help="project directory (default: .)")
    fix_p.add_argument("--apply", action="store_true", help="write the changes (default: show a diff)")
    fix_p.add_argument("--only", default="", help="comma-separated finding ids to fix, e.g. AND-BACKUP")
    fix_p.add_argument("--listing", type=Path, default=None, help="path to a playgate.toml/.json")

    init_p = sub.add_parser("init", help="write a template playgate.toml")
    init_p.add_argument("directory", nargs="?", default=".", help="where to write it")
    init_p.add_argument("--force", action="store_true", help="overwrite an existing file")

    sub.add_parser("rules", help="list every registered rule")
    sub.add_parser("standards", help="show how findings map to CWE / MASVS / OWASP Mobile Top 10")

    pol_p = sub.add_parser("policy", help="show the Google Play policy data version and freshness")
    pol_p.add_argument("--check", action="store_true",
                       help="exit 1 if the policy data is past its review horizon (for CI)")

    ui_p = sub.add_parser("ui", help="open the local web interface in a browser")
    ui_p.add_argument("--port", type=int, default=8765, help="port to listen on (default: 8765)")
    ui_p.add_argument("--no-browser", action="store_true", help="do not open a browser tab")

    sub.add_parser(
        "mcp",
        help="run as an MCP server on stdio (connect Claude Desktop or another agent host)",
    )

    return parser


def _use_utf8_streams() -> None:
    # Reports can carry arbitrary Unicode (emoji in a listing title, em-dashes,
    # non-ASCII paths). A Windows console defaults to cp1252 and raises on those,
    # which is fatal for the packaged .exe. Encode output as UTF-8, replacing
    # anything the terminal genuinely cannot render rather than crashing.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # pragma: no cover - non-reconfigurable stream
            pass


def _enable_ansi() -> None:
    if os.name == "nt":  # pragma: no cover - Windows console quirk
        os.system("")  # a no-op shell call flips the console into VT mode


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser()
    if not target.exists():
        print(f"playgate: no such path: {target}", file=sys.stderr)
        return 2

    baseline: set[str] | None = None
    if args.baseline is not None:
        try:
            baseline = load_baseline(args.baseline)
        except ValueError as exc:
            print(f"playgate: {exc}", file=sys.stderr)
            return 2

    try:
        report = scan(target, listing_path=args.listing, baseline=baseline)
    except (ValueError, RuntimeError) as exc:
        print(f"playgate: {exc}", file=sys.stderr)
        return 2

    # --min-severity only trims the *display*; --fail-on judges the full scan,
    # so hiding a finding can never change the exit code.
    min_severity = Severity.parse(args.min_severity)
    shown = report
    if min_severity > Severity.INFO:
        shown = dataclasses.replace(
            report, findings=[f for f in report.findings if f.severity >= min_severity]
        )

    if args.format == "json":
        rendered = to_json(shown)
    elif args.format == "sarif":
        rendered = to_sarif(shown)
    elif args.format == "html":
        from .html_report import to_html

        rendered = to_html(shown)
    elif args.format == "md":
        rendered = to_markdown(shown)
    else:
        color = sys.stdout.isatty() and not args.no_color and args.output is None
        if color:
            _enable_ansi()
        rendered = to_text(shown, color=color)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"playgate: wrote {args.output}")
    else:
        print(rendered)

    if args.fail_on == "never":
        return 0
    threshold = Severity.parse(args.fail_on)
    return 1 if any(f.severity >= threshold for f in report.findings) else 0


def _cmd_release(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser()
    if not target.exists():
        print(f"playgate: no such path: {target}", file=sys.stderr)
        return 2
    try:
        report = scan(target, listing_path=args.listing)
    except (ValueError, RuntimeError) as exc:
        print(f"playgate: {exc}", file=sys.stderr)
        return 2
    color = sys.stdout.isatty() and not args.no_color
    if color:
        _enable_ansi()
    print(to_release_checklist(report, color=color, store=args.store))
    # Exit 1 when any gate blocks submission, so it fits a release pipeline.
    from .report import release_blocked

    return 1 if release_blocked(report, args.store) else 0


def _cmd_fix(args: argparse.Namespace) -> int:
    from . import fix

    target = Path(args.target).expanduser()
    if not target.is_dir():
        print("playgate: fix works on a project directory, not a compiled package", file=sys.stderr)
        return 2
    try:
        report = scan(target, listing_path=args.listing)
    except (ValueError, RuntimeError) as exc:
        print(f"playgate: {exc}", file=sys.stderr)
        return 2
    only = {x.strip() for x in args.only.split(",") if x.strip()} or None
    edits, skipped = fix.plan(report, only)
    if not edits:
        print("playgate: nothing to fix automatically.")
        for f in skipped:
            print(f"  could not place a fix for {f.id} at {f.location.render()} — fix by hand")
        return 0
    for edit in edits:
        print(edit.diff())
    print("changes:")
    for edit in edits:
        for fid, note in edit.applied:
            print(f"  {edit.relpath}: [{fid}] {note}")
    for f in skipped:
        print(f"  skipped {f.id} at {f.location.render()} — fix by hand")
    if not args.apply:
        print("\nDry run. Re-run with --apply to write these changes.")
        return 0
    fix.apply(edits)
    after = scan(target, listing_path=args.listing)
    remaining = {f.fingerprint() for f in after.findings}
    fixed = [f for f in report.findings if f.id in fix.FIXERS and f.fingerprint() not in remaining]
    print(f"\nwrote {len(edits)} file(s); {len(fixed)} finding(s) resolved. Review with `git diff`.")
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    directory = Path(args.directory).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "playgate.toml"
    if path.exists() and not args.force:
        print(f"playgate: {path} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    path.write_text(TEMPLATE, encoding="utf-8")
    print(f"playgate: wrote {path} — fill it in, then run `playgate scan`.")
    return 0


def _cmd_rules(_: argparse.Namespace) -> int:
    for name, func in sorted(all_rules()):
        doc = (func.__doc__ or "").strip().splitlines()
        print(f"{name:34} {doc[0] if doc else ''}")
    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    from datetime import date

    from .rules.policy import POLICY, deadline_note

    ta = POLICY["target_api"]
    print(f"policy data version : {POLICY['version']}")
    print(f"reviewed on         : {POLICY['reviewed_on']}")
    print(f"valid until         : {POLICY['reviewed_until']}")
    print(f"target API          : {ta['standard']} (discoverability floor {ta['discoverability']})")
    print(f"deadline            : {ta['deadline']}")
    print("\nchangelog:")
    for entry in POLICY.get("changelog", []):
        print(f"  {entry['date']}  {entry['change']}")
    stale = deadline_note(date.today())
    if stale:
        print(f"\nSTALE: {stale}")
        return 1 if args.check else 0
    print("\nstatus: fresh")
    return 0


def _cmd_standards(_: argparse.Namespace) -> int:
    from .standards import SCOPE, STANDARDS_MAP, standards_for

    print("Finding → security standard mapping\n")
    for fid in sorted(STANDARDS_MAP):
        std = standards_for(fid)
        print(f"  {fid:26} {' · '.join(std.labels()) if std else ''}")
    print("\n  SEC-*<provider>            OWASP M1 · MASVS-STORAGE · CWE-798  (default)")
    print("\nMaps to: " + ", ".join(SCOPE["maps_to"]))
    print("Output:  " + SCOPE["output_format"])
    print("\nNot:")
    for item in SCOPE["not"]:
        print(f"  - {item}")
    return 0


def _cmd_ui(args: argparse.Namespace) -> int:
    from .webui import serve  # imported lazily; scan/init/rules never need it

    return serve(port=args.port, open_browser=not args.no_browser)


def _cmd_mcp(_: argparse.Namespace) -> int:
    from .mcp import serve  # imported lazily

    return serve()


def main(argv: list[str] | None = None) -> int:
    _use_utf8_streams()
    parser = _build_parser()
    args = parser.parse_args(argv)
    handler = {
        "scan": _cmd_scan,
        "release": _cmd_release,
        "fix": _cmd_fix,
        "init": _cmd_init,
        "rules": _cmd_rules,
        "standards": _cmd_standards,
        "policy": _cmd_policy,
        "ui": _cmd_ui,
        "mcp": _cmd_mcp,
    }[args.command]
    return handler(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
