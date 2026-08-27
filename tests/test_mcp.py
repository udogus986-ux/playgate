"""The MCP server: JSON-RPC handshake and tool calls."""

from __future__ import annotations

import io
import json
from pathlib import Path

from playgate.mcp import handle, serve

from .conftest import write


def test_initialize_handshake() -> None:
    resp = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2024-11-05"}})
    assert resp["result"]["serverInfo"]["name"] == "playgate"
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert "tools" in resp["result"]["capabilities"]


def test_initialized_notification_has_no_response() -> None:
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_tools_list_exposes_scan() -> None:
    resp = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert {"playgate_scan", "playgate_detect", "playgate_list_rules", "playgate_init_listing"} <= names
    scan_tool = next(t for t in resp["result"]["tools"] if t["name"] == "playgate_scan")
    assert scan_tool["inputSchema"]["required"] == ["path"]


def test_scan_tool_returns_findings(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 30 } }\n")
    resp = handle({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "playgate_scan", "arguments": {"path": str(root)}},
    })
    assert resp["result"].get("isError") is not True
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert any(f["id"] == "PLY-TARGET-API" for f in payload["findings"])


def test_scan_tool_bad_path_is_reported_not_crashed() -> None:
    resp = handle({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "playgate_scan", "arguments": {"path": "Z:/nope/xyz"}},
    })
    assert resp["result"]["isError"] is True
    assert "no such path" in resp["result"]["content"][0]["text"]


def test_detect_tool(tmp_path: Path) -> None:
    write(tmp_path / "project.godot", 'config_version=5\n')
    resp = handle({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "playgate_detect", "arguments": {"path": str(tmp_path)}},
    })
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["kind"] == "godot"


def test_unknown_tool_is_an_error() -> None:
    resp = handle({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {"name": "nope", "arguments": {}},
    })
    assert "error" in resp
    assert resp["error"]["code"] == -32602


def test_unknown_method_is_method_not_found() -> None:
    resp = handle({"jsonrpc": "2.0", "id": 7, "method": "does/not/exist"})
    assert resp["error"]["code"] == -32601


def test_serve_processes_a_stream(tmp_path: Path) -> None:
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]
    stdin = io.StringIO("\n".join(lines) + "\n")
    stdout = io.StringIO()
    assert serve(stdin=stdin, stdout=stdout) == 0
    responses = [json.loads(x) for x in stdout.getvalue().splitlines() if x.strip()]
    # initialize + tools/list answered; the notification produced nothing.
    assert len(responses) == 2
    assert responses[0]["id"] == 1
    assert responses[1]["id"] == 2


def test_serve_survives_a_garbage_line() -> None:
    stdin = io.StringIO("not json\n" + json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}) + "\n")
    stdout = io.StringIO()
    serve(stdin=stdin, stdout=stdout)
    responses = [json.loads(x) for x in stdout.getvalue().splitlines() if x.strip()]
    assert any(r.get("error", {}).get("code") == -32700 for r in responses)
    assert any(r.get("id") == 9 for r in responses)
