"""Google Play release-readiness dry-run."""

from __future__ import annotations

from pathlib import Path

from playgate.cli import main
from playgate.report import to_release_checklist
from playgate.scan import scan

from .conftest import write


def test_blocking_project_is_no_go(gradle_project) -> None:
    root = gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n")
    out = to_release_checklist(scan(root))
    assert "NO-GO" in out
    assert "FAIL" in out
    assert "Targets Android 16" in out


def test_release_command_exit_codes(gradle_project, capsys) -> None:
    blocking = gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n")
    assert main(["release", str(blocking), "--no-color"]) == 1
    capsys.readouterr()


def test_clean_project_needs_info_without_listing(gradle_project) -> None:
    # A well-built project with no playgate.toml: no blockers, but listing gates
    # cannot be confirmed → READY* with NEEDS-INFO.
    root = gradle_project(manifest_body='<application android:allowBackup="false"/>')
    out = to_release_checklist(scan(root))
    assert "NO-GO" not in out
    assert "NEEDS-INFO" in out


def test_fully_clean_project_is_ready(tmp_path: Path) -> None:
    # targetSdk 36, backup off, and a complete listing → every gate PASS.
    root = tmp_path / "p"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle",
          "android { defaultConfig { targetSdk 36 }\n  buildTypes { release { minifyEnabled true } } }\n")
    write(root / "app" / "src" / "main" / "AndroidManifest.xml",
          '<?xml version="1.0"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
          'package="com.x">\n<application android:allowBackup="false"/>\n</manifest>\n')
    write(root / "playgate.toml",
          'title = "Notes"\nprivacy_policy_url = "https://x.example/p"\n'
          "account_creation = false\nsells_digital_goods = false\n")
    out = to_release_checklist(scan(root))
    assert "VERDICT: READY" in out
    assert "NO-GO" not in out
    assert "[✗]" not in out  # no gate row is a fail (the word FAIL still appears in the legend)
