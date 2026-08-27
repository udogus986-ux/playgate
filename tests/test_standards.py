"""Standards mapping: CWE / MASVS / OWASP Mobile Top 10 in findings and SARIF."""

from __future__ import annotations

import json

from playgate.cli import main
from playgate.report import to_json, to_markdown, to_sarif
from playgate.scan import scan
from playgate.standards import standards_for


def test_known_mappings() -> None:
    assert standards_for("CODE-TLS-TRUSTALL").cwe == (295,)
    assert standards_for("CODE-WEAK-CIPHER").owasp_mobile == "M10"
    assert "MASVS-STORAGE" in standards_for("SEC-SIGNING").masvs


def test_sec_prefix_fallback() -> None:
    # Any provider secret not listed explicitly still maps to hard-coded creds.
    std = standards_for("SEC-STRIPE-LIVE")
    assert std is not None
    assert std.cwe == (798,)
    assert std.owasp_mobile == "M1"


def test_unmapped_returns_none() -> None:
    assert standards_for("PLY-TITLE-LENGTH") is None


def test_json_carries_standards(gradle_project) -> None:
    root = gradle_project(
        gradle="android { defaultConfig { targetSdk 30 } }\n",
        extra={"app/src/main/java/A.kt": "val v = TrustAllCerts()\n"},
    )
    doc = json.loads(to_json(scan(root)))
    assert doc["standards"]["maps_to"]  # top-level scope block
    assert any("Not DAST" in n for n in doc["standards"]["not"])
    tls = next(f for f in doc["findings"] if f["id"] == "CODE-TLS-TRUSTALL")
    assert tls["standards"]["cwe"] == ["CWE-295"]
    assert tls["standards"]["owasp_mobile_top10_2024"] == "M5"


def test_sarif_has_cwe_tags(gradle_project) -> None:
    root = gradle_project(extra={"app/src/main/java/A.kt": "val v = TrustAllCerts()\n"})
    doc = json.loads(to_sarif(scan(root)))
    rule = next(
        r for r in doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "CODE-TLS-TRUSTALL"
    )
    assert "external/cwe/cwe-295" in rule["properties"]["tags"]
    assert rule["properties"]["cwe"] == ["CWE-295"]


def test_markdown_shows_standards_and_scope(gradle_project) -> None:
    root = gradle_project(extra={"app/src/main/java/A.kt": "val v = TrustAllCerts()\n"})
    md = to_markdown(scan(root))
    assert "CWE-295" in md
    assert "Standards & scope" in md
    assert "not" in md.lower()


def test_standards_command(capsys) -> None:
    assert main(["standards"]) == 0
    out = capsys.readouterr().out
    assert "CODE-TLS-TRUSTALL" in out
    assert "CWE-295" in out
    assert "MASVS" in out
