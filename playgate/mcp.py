"""A Model Context Protocol server: ``playgate mcp``.

This is the bridge that turns playgate into a *dynamic agent* without adding an
API key or a network dependency. playgate stays a deterministic set of tools;
the reasoning is supplied by whatever MCP-capable client connects to it —
Claude Desktop, an IDE agent, or any other host that speaks MCP. The user's
existing subscription is the agent's brain; playgate is its hands.

Transport is newline-delimited JSON-RPC 2.0 over stdio, implemented with the
standard library only. Nothing is written to stdout except protocol messages;
diagnostics go to stderr.

Tools exposed:
  playgate_scan          run the scanner over a path (project dir, .apk, .aab)
  playgate_detect        report the project kind and whether a listing exists
  playgate_list_rules    enumerate every deterministic check
  playgate_init_listing  write the playgate.toml template
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import __version__
from .collect import LISTING_FILENAMES, detect_kind
from .models import Severity
from .report import to_json, to_markdown
from .rules import all_rules
from .scan import scan

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "playgate_scan",
        "description": (
            "Audit an Android project directory, .apk or .aab for security issues and Google "
            "Play rejection risk. Returns structured findings, each with evidence, why it "
            "matters and a concrete fix, plus a rejection-risk score. Every finding's `evidence` "
            "is a literal quote — verify it against the source before repeating it."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to a project folder, .apk or .aab."},
                "listing_path": {
                    "type": "string",
                    "description": "Optional path to a playgate.toml/.json listing file.",
                },
                "min_severity": {
                    "type": "string",
                    "enum": [s.name.lower() for s in Severity],
                    "description": "Hide findings below this severity (default: info).",
                },
                "format": {
                    "type": "string",
                    "enum": ["json", "markdown"],
                    "description": "json (default) for structured reasoning, markdown for a report.",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "playgate_detect",
        "description": (
            "Identify the project at a path — gradle, unity, godot, react-native, flutter, apk "
            "or unknown — and report whether a playgate.toml listing file is present. Use this "
            "first to decide whether store-side policy checks can run."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "playgate_list_rules",
        "description": "List every registered deterministic check with its one-line description.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "playgate_init_listing",
        "description": (
            "Write a commented playgate.toml template into a directory so store-side policy "
            "checks (privacy policy, account deletion, Data Safety, billing, listing text) can "
            "run. Refuses to overwrite unless force is true."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "force": {"type": "boolean"},
            },
            "required": ["path"],
        },
    },
]


# --------------------------------------------------------------------------
# Tool implementations
# --------------------------------------------------------------------------

def _tool_scan(args: dict) -> str:
    raw = str(args.get("path") or "").strip()
    if not raw:
        raise ValueError("path is required")
    target = Path(raw).expanduser()
    if not target.exists():
        raise ValueError(f"no such path: {target}")
    listing = args.get("listing_path")
    min_sev = Severity.parse(args["min_severity"]) if args.get("min_severity") else Severity.INFO
    report = scan(
        target,
        listing_path=Path(listing) if listing else None,
        min_severity=min_sev,
    )
    if args.get("format") == "markdown":
        return to_markdown(report)
    return to_json(report)


def _tool_detect(args: dict) -> str:
    raw = str(args.get("path") or "").strip()
    if not raw:
        raise ValueError("path is required")
    path = Path(raw).expanduser()
    if not path.exists():
        raise ValueError(f"no such path: {path}")
    base = path if path.is_dir() else path.parent
    return json.dumps(
        {
            "path": str(path),
            "kind": detect_kind(path).value,
            "has_listing": any((base / n).exists() for n in LISTING_FILENAMES),
        },
        indent=2,
    )


def _tool_list_rules(_args: dict) -> str:
    rules = []
    for name, func in sorted(all_rules()):
        doc = (func.__doc__ or "").strip().splitlines()
        rules.append({"name": name, "description": doc[0] if doc else ""})
    return json.dumps(rules, indent=2)


def _tool_init_listing(args: dict) -> str:
    from .cli import TEMPLATE

    raw = str(args.get("path") or "").strip()
    if not raw:
        raise ValueError("path is required")
    directory = Path(raw).expanduser()
    if directory.is_file():
        directory = directory.parent
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "playgate.toml"
    if target.exists() and not args.get("force"):
        raise ValueError(f"{target} already exists (pass force: true to overwrite)")
    target.write_text(TEMPLATE, encoding="utf-8")
    return json.dumps({"written": str(target)}, indent=2)


TOOL_IMPL = {
    "playgate_scan": _tool_scan,
    "playgate_detect": _tool_detect,
    "playgate_list_rules": _tool_list_rules,
    "playgate_init_listing": _tool_init_listing,
}


# --------------------------------------------------------------------------
# JSON-RPC plumbing
# --------------------------------------------------------------------------

def _log(msg: str) -> None:
    print(f"playgate-mcp: {msg}", file=sys.stderr, flush=True)


def _result(rpc_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _error(rpc_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def handle(message: dict) -> dict | None:
    """Return a response dict, or None for notifications (no id)."""
    method = message.get("method")
    rpc_id = message.get("id")
    params = message.get("params") or {}

    if method == "initialize":
        client_version = params.get("protocolVersion") or PROTOCOL_VERSION
        return _result(rpc_id, {
            "protocolVersion": client_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "playgate", "version": __version__},
            "instructions": (
                "playgate audits Android projects and packages for security issues and Google "
                "Play rejection risk. Call playgate_detect first, then playgate_scan. Treat each "
                "finding's evidence as a quote to verify, and never promise Play approval — the "
                "rule set is fixed and finite."
            ),
        })

    if method in {"notifications/initialized", "initialized"}:
        return None  # notification

    if method == "ping":
        return _result(rpc_id, {})

    if method == "tools/list":
        return _result(rpc_id, {"tools": TOOLS})

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        impl = TOOL_IMPL.get(name)
        if impl is None:
            return _error(rpc_id, -32602, f"unknown tool: {name}")
        try:
            text = impl(args)
        except (ValueError, RuntimeError) as exc:
            return _result(rpc_id, {
                "content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True,
            })
        except Exception as exc:  # noqa: BLE001 - never crash the server on one call
            _log(f"tool {name} raised {type(exc).__name__}: {exc}")
            return _result(rpc_id, {
                "content": [{"type": "text", "text": f"internal error: {type(exc).__name__}: {exc}"}],
                "isError": True,
            })
        return _result(rpc_id, {"content": [{"type": "text", "text": text}]})

    if rpc_id is None:
        return None  # unknown notification — ignore
    return _error(rpc_id, -32601, f"method not found: {method}")


def serve(stdin=None, stdout=None) -> int:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    if stdout is None:
        # MCP clients read stdout as UTF-8; Windows consoles default to cp1252,
        # which would corrupt the em-dashes in our descriptions.
        try:
            sys.stdout.reconfigure(encoding="utf-8", newline="\n")
        except (AttributeError, ValueError):  # pragma: no cover - non-reconfigurable stream
            pass
        stdout = sys.stdout
    if stdin is None:
        try:
            sys.stdin.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):  # pragma: no cover
            pass
        stdin = sys.stdin
    _log(f"v{__version__} ready on stdio")
    for line in stdin:
        # Strip a UTF-8 BOM some hosts prepend (e.g. PowerShell piping) before
        # whitespace, so the first message still parses as JSON.
        line = line.lstrip("﻿").strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        if not isinstance(message, dict):
            continue
        response = handle(message)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0
