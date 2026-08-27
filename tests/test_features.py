"""SARIF, ignore, baseline, new secret patterns, RN/Flutter, deadline note."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from playgate.cli import main
from playgate.collect import detect_kind
from playgate.models import ProjectKind, Severity
from playgate.report import to_sarif
from playgate.rules.policy import deadline_note
from playgate.scan import scan

from .conftest import ids, write


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------

def test_sarif_is_wellformed(gradle_project) -> None:
    root = gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n")
    doc = json.loads(to_sarif(scan(root)))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "playgate"
    assert any(r["id"] == "PLY-TARGET-API" for r in run["tool"]["driver"]["rules"])
    result = next(r for r in run["results"] if r["ruleId"] == "PLY-TARGET-API")
    assert result["level"] == "error"
    assert result["partialFingerprints"]["playgate/v1"]


def test_sarif_format_via_cli(gradle_project, tmp_path: Path, capsys) -> None:
    root = gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n")
    out = tmp_path / "r.sarif"
    assert main(["scan", str(root), "--format", "sarif", "-o", str(out), "--fail-on", "never"]) == 0
    capsys.readouterr()
    json.loads(out.read_text())  # parses


# --------------------------------------------------------------------------
# ignore / suppression
# --------------------------------------------------------------------------

def test_ignore_suppresses_by_rule_id(gradle_project) -> None:
    root = gradle_project(
        gradle="android { defaultConfig { targetSdk 30 } }\n",
        extra={"playgate.toml": 'privacy_policy_url = "https://x/p"\nignore = ["PLY-TARGET-API"]\n'},
    )
    assert "PLY-TARGET-API" not in ids(scan(root))


def test_ignore_is_path_scoped(gradle_project) -> None:
    root = gradle_project(
        extra={
            "app/src/main/java/A.kt": 'val v = TrustAllCerts()\n',
            "app/src/main/java/B.kt": 'val v = TrustAllCerts()\n',
            "playgate.toml": 'privacy_policy_url = "https://x/p"\nignore = ["CODE-TLS-TRUSTALL:A.kt"]\n',
        },
    )
    hits = [f for f in scan(root).findings if f.id == "CODE-TLS-TRUSTALL"]
    assert len(hits) == 1
    assert "B.kt" in hits[0].location.render()


def test_ignore_does_not_change_unrelated_findings(gradle_project) -> None:
    root = gradle_project(
        gradle="android { defaultConfig { targetSdk 30 } }\n",
        extra={"playgate.toml": 'privacy_policy_url = "https://x/p"\nignore = ["NOPE-DOES-NOT-EXIST"]\n'},
    )
    assert "PLY-TARGET-API" in ids(scan(root))


# --------------------------------------------------------------------------
# baseline / diff
# --------------------------------------------------------------------------

def test_baseline_hides_known_findings(gradle_project, tmp_path: Path, capsys) -> None:
    root = gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n")
    base = tmp_path / "base.json"
    main(["scan", str(root), "--format", "json", "-o", str(base), "--fail-on", "never"])
    capsys.readouterr()
    # Re-scanning against its own report should surface nothing new.
    from playgate.scan import load_baseline

    fingerprints = load_baseline(base)
    report = scan(root, baseline=fingerprints)
    assert report.findings == []
    assert any("baseline" in n for n in report.notes)


def test_baseline_shows_only_new_findings(gradle_project, tmp_path: Path, capsys) -> None:
    root = gradle_project(gradle="android { defaultConfig { targetSdk 36 } }\n")
    base = tmp_path / "base.json"
    main(["scan", str(root), "--format", "json", "-o", str(base), "--fail-on", "never"])
    capsys.readouterr()
    # Introduce a regression.
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 30 } }\n")
    from playgate.scan import load_baseline

    report = scan(root, baseline=load_baseline(base))
    assert "PLY-TARGET-API" in ids(report)


# --------------------------------------------------------------------------
# new secret patterns + private-IP http exception
# --------------------------------------------------------------------------

def test_sendgrid_key_is_critical(gradle_project) -> None:
    key = "SG." + "a" * 22 + "." + "b" * 43
    root = gradle_project(extra={"app/src/main/java/A.kt": f'val k = "{key}"\n'})
    finding = next(f for f in scan(root).findings if f.id == "SEC-SENDGRID")
    assert finding.severity is Severity.CRITICAL


def test_firebase_db_url_is_low_with_rules_advice(gradle_project) -> None:
    root = gradle_project(
        extra={"app/src/main/java/A.kt": 'val db = "https://demo-app.firebaseio.com"\n'}
    )
    finding = next(f for f in scan(root).findings if f.id == "SEC-FIREBASE-DB")
    assert finding.severity is Severity.LOW
    assert "rules" in finding.fix.lower()


def test_supabase_url_is_flagged_with_rls_advice(gradle_project) -> None:
    root = gradle_project(
        extra={"app/src/main/java/A.kt": 'val url = "https://abcdefghijklmnop.supabase.co"\n'}
    )
    finding = next(f for f in scan(root).findings if f.id == "SEC-SUPABASE-URL")
    assert finding.severity is Severity.LOW
    assert "RLS" in finding.why


def test_private_ip_http_is_ignored(gradle_project) -> None:
    root = gradle_project(
        extra={"app/src/main/java/A.kt": 'val a = "http://192.168.1.5:8080"\nval b = "http://10.0.0.2/x"\n'}
    )
    assert "CODE-HTTP-URL" not in ids(scan(root))


def test_public_http_is_still_flagged(gradle_project) -> None:
    root = gradle_project(
        extra={"app/src/main/java/A.kt": 'val a = "http://api.example.com/v1"\n'}
    )
    assert "CODE-HTTP-URL" in ids(scan(root))


# --------------------------------------------------------------------------
# React Native / Flutter detection
# --------------------------------------------------------------------------

def test_react_native_detected(tmp_path: Path) -> None:
    root = tmp_path / "rn"
    write(root / "package.json", '{"dependencies": {"react-native": "0.74.0"}}')
    write(root / "android" / "app" / "build.gradle", "android { defaultConfig { targetSdk 30 } }\n")
    assert detect_kind(root) is ProjectKind.REACT_NATIVE
    assert "PLY-TARGET-API" in ids(scan(root))


def test_flutter_detected(tmp_path: Path) -> None:
    root = tmp_path / "fl"
    write(root / "pubspec.yaml", "name: demo\nflutter:\n  uses-material-design: true\n")
    write(root / "android" / "app" / "build.gradle", "android { defaultConfig { targetSdk 30 } }\n")
    assert detect_kind(root) is ProjectKind.FLUTTER
    assert "PLY-TARGET-API" in ids(scan(root))


# --------------------------------------------------------------------------
# policy deadline note
# --------------------------------------------------------------------------

def test_deadline_note_quiet_before_horizon() -> None:
    assert deadline_note(date(2026, 8, 27)) is None


def test_deadline_note_fires_after_horizon() -> None:
    note = deadline_note(date(2027, 1, 1))
    assert note is not None
    assert "rule set" in note


def test_deadline_note_appears_in_scan(gradle_project) -> None:
    report = scan(gradle_project(), today=date(2027, 6, 1))
    assert any("rule set was last reviewed" in n for n in report.notes)
