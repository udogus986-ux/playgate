"""playgate command line interface."""

from __future__ import annotations

import argparse
import dataclasses
import os
import sys
from pathlib import Path

from . import __version__
from .models import Severity
from .report import to_json, to_markdown, to_sarif, to_text
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
        "--format", choices=("text", "md", "json", "sarif"), default="text",
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

    init_p = sub.add_parser("init", help="write a template playgate.toml")
    init_p.add_argument("directory", nargs="?", default=".", help="where to write it")
    init_p.add_argument("--force", action="store_true", help="overwrite an existing file")

    sub.add_parser("rules", help="list every registered rule")

    ui_p = sub.add_parser("ui", help="open the local web interface in a browser")
    ui_p.add_argument("--port", type=int, default=8765, help="port to listen on (default: 8765)")
    ui_p.add_argument("--no-browser", action="store_true", help="do not open a browser tab")

    sub.add_parser(
        "mcp",
        help="run as an MCP server on stdio (connect Claude Desktop or another agent host)",
    )

    return parser


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


def _cmd_ui(args: argparse.Namespace) -> int:
    from .webui import serve  # imported lazily; scan/init/rules never need it

    return serve(port=args.port, open_browser=not args.no_browser)


def _cmd_mcp(_: argparse.Namespace) -> int:
    from .mcp import serve  # imported lazily

    return serve()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handler = {
        "scan": _cmd_scan,
        "init": _cmd_init,
        "rules": _cmd_rules,
        "ui": _cmd_ui,
        "mcp": _cmd_mcp,
    }[args.command]
    return handler(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
