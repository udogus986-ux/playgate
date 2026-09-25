"""Dynamic test plan generation (`playgate probe`)."""

from __future__ import annotations

import json

from playgate.cli import main
from playgate.collect import build_context
from playgate.mcp import handle
from playgate.probe import build_plan

MANIFEST = """
<application>
  <activity android:name=".Main" android:exported="true">
    <intent-filter>
      <action android:name="android.intent.action.MAIN"/>
      <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
  </activity>
  <activity android:name=".Link" android:exported="true">
    <intent-filter android:autoVerify="true">
      <action android:name="android.intent.action.VIEW"/>
      <category android:name="android.intent.category.BROWSABLE"/>
      <data android:scheme="https" android:host="app.example.com" android:pathPrefix="/reset"/>
    </intent-filter>
  </activity>
  <service android:name=".Hidden" android:exported="false"/>
  <receiver android:name="com.test.Guarded" android:exported="true" android:permission="com.test.PRIV"/>
  <provider android:name=".Data" android:authorities="com.test.data" android:exported="true"/>
</application>
"""


def test_plan_covers_exported_surfaces(gradle_project) -> None:
    plan = build_plan(build_context(gradle_project(manifest_body=MANIFEST)))
    by_kind = {}
    for p in plan:
        by_kind.setdefault(p.kind, []).append(p)
    assert {p.component for p in by_kind["activity"]} == {"com.test.Main", "com.test.Link"}
    assert "service" not in by_kind  # not exported → nothing to probe
    assert by_kind["receiver"][0].guarded_by == "com.test.PRIV"
    assert "content://com.test.data/" in by_kind["provider"][0].command
    assert "https://app.example.com/reset" in by_kind["deeplink"][0].command


def test_probe_cli_json(gradle_project, capsys) -> None:
    assert main(["probe", str(gradle_project(manifest_body=MANIFEST)), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert all(p["command"].startswith("adb shell ") for p in data)


def test_probe_mcp_tool(gradle_project) -> None:
    root = gradle_project(manifest_body=MANIFEST)
    resp = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "playgate_probe_plan", "arguments": {"path": str(root)}}})
    plan = json.loads(resp["result"]["content"][0]["text"])
    assert any(p["kind"] == "provider" for p in plan)
