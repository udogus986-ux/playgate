from __future__ import annotations

import json
from pathlib import Path

from playgate.cli import main
from playgate.models import Severity
from playgate.report import to_markdown, to_text
from playgate.scan import scan


def test_init_then_scan(tmp_path: Path, capsys) -> None:
    assert main(["init", str(tmp_path)]) == 0
    assert (tmp_path / "playgate.toml").exists()
    # Running init twice must not silently overwrite.
    assert main(["init", str(tmp_path)]) == 2
    assert main(["init", str(tmp_path), "--force"]) == 0
    capsys.readouterr()


def test_template_is_valid_toml_and_parses(tmp_path: Path) -> None:
    main(["init", str(tmp_path)])
    from playgate.collect import load_listing

    listing = load_listing(tmp_path / "playgate.toml")
    assert listing is not None
    assert listing.title == "My App"
    assert listing.data_safety_declared == []


def test_missing_path_exits_2(capsys) -> None:
    assert main(["scan", "/no/such/place"]) == 2
    assert "no such path" in capsys.readouterr().err


def test_json_output_is_wellformed(gradle_project, tmp_path: Path, capsys) -> None:
    root = gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n")
    out = tmp_path / "r.json"
    main(["scan", str(root), "--format", "json", "-o", str(out)])
    capsys.readouterr()
    data = json.loads(out.read_text())
    assert data["rejection_band"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert any(f["id"] == "PLY-TARGET-API" for f in data["findings"])
    assert data["findings"][0]["severity"] == "CRITICAL"


def test_fail_on_threshold(gradle_project, capsys) -> None:
    clean = gradle_project(manifest_body='<application android:allowBackup="false"/>')
    assert main(["scan", str(clean), "--fail-on", "high", "--no-color"]) == 0
    dirty = gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n")
    assert main(["scan", str(dirty), "--fail-on", "high", "--no-color"]) == 1
    assert main(["scan", str(dirty), "--fail-on", "never", "--no-color"]) == 0
    capsys.readouterr()


def test_min_severity_filters(gradle_project) -> None:
    root = gradle_project(gradle="android { defaultConfig { targetSdk 30\n minSdk 16 } }\n")
    everything = scan(root)
    high_only = scan(root, min_severity=Severity.HIGH)
    assert len(high_only.findings) < len(everything.findings)
    assert all(f.severity >= Severity.HIGH for f in high_only.findings)


def test_renderers_do_not_crash_on_empty_report(gradle_project) -> None:
    report = scan(gradle_project(), min_severity=Severity.CRITICAL)
    assert report.findings == []
    assert "No findings." in to_text(report, color=False)
    assert "No findings." in to_markdown(report)
    assert report.rejection_band() == "NONE"


def test_rules_command_lists_rules(capsys) -> None:
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "policy.target_api" in out
    assert "manifest.exported" in out
