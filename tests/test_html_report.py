"""Single-file HTML report — and that scanned content can't inject script."""

from __future__ import annotations

import json
import re

from playgate.cli import main
from playgate.html_report import to_html
from playgate.scan import scan


def _payload(html: str) -> dict:
    m = re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S)
    assert m
    return json.loads(m.group(1))


def test_html_embeds_valid_data(gradle_project) -> None:
    html = to_html(scan(gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n")))
    data = _payload(html)
    assert any(f["id"] == "PLY-TARGET-API" for f in data["findings"])
    assert data["release"][0]["verdict"] == "NO-GO"
    assert data["scope"]["maps_to"]


def test_hostile_evidence_cannot_break_out(gradle_project) -> None:
    evil = 'val x = "http://evil.example/</script><img src=x onerror=alert(1)><!--"\n'
    html = to_html(scan(gradle_project(extra={"app/src/main/java/E.kt": evil})))
    # Exactly the two script blocks of the template close — none injected.
    assert html.count("</script>") == 2
    assert "<img src=x" not in html
    assert "<!--" not in html
    # …and the evidence still round-trips intact through the JSON.
    data = _payload(html)
    assert any("onerror=alert(1)" in (f.get("evidence") or "") for f in data["findings"])


def test_html_format_via_cli(gradle_project, tmp_path, capsys) -> None:
    out = tmp_path / "r.html"
    assert main(["scan", str(gradle_project()), "--format", "html", "-o", str(out), "--fail-on", "never"]) == 0
    capsys.readouterr()
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
