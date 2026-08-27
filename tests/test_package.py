"""Scanning a compiled package."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from playgate.models import ProjectKind, Severity
from playgate.scan import scan

from .axml_fixture import build_manifest_axml
from .conftest import ids

STRIPE_KEY = "sk_live_" + "9Qw3Er7Ty2Ui5Op1As4Df"


def make_apk(path: Path, *, manifest: bytes | None = None, dex_secret: bool = True) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest if manifest is not None else build_manifest_axml())
        zf.writestr("classes.dex", b"dex\n035\x00" + (STRIPE_KEY.encode() if dex_secret else b"x" * 40))
        zf.writestr("assets/config.json", '{"endpoint": "http://api.example.com"}')
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82fake-signature-block")
        zf.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 32)
    return path


def test_apk_manifest_rules_run(tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "app.apk")
    report = scan(apk)
    assert report.kind is ProjectKind.APK
    found = ids(report)
    # The fixture manifest is debuggable, has an open service and a restricted permission.
    assert "AND-DEBUGGABLE" in found
    assert "AND-EXPORTED-OPEN" in found
    assert "PLY-PERM-QUERY_ALL_PACKAGES" in found
    # targetSdk 33 comes from <uses-sdk> in the binary manifest.
    assert "PLY-TARGET-API" in found


def test_secrets_are_found_in_compiled_code(tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "app.apk")
    finding = next(f for f in scan(apk).findings if f.id == "SEC-STRIPE-LIVE")
    assert finding.severity is Severity.CRITICAL
    assert "classes.dex" in finding.location.render()


def test_signature_is_reported_in_notes(tmp_path: Path) -> None:
    report = scan(make_apk(tmp_path / "app.apk"))
    assert any("v1 (JAR) signature" in n for n in report.notes)


def test_unsigned_package_is_noted(tmp_path: Path) -> None:
    path = tmp_path / "unsigned.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", build_manifest_axml())
    assert any("unsigned build" in n for n in scan(path).notes)


def test_protobuf_manifest_degrades_with_a_note(tmp_path: Path) -> None:
    path = tmp_path / "app.aab"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("base/manifest/AndroidManifest.xml", b"\x0a\x08manifest\x12\x04prot")
    report = scan(path)
    assert any("bundletool" in n for n in report.notes)
    assert any("manifest rules did not run" in n for n in report.notes)


def test_corrupt_package_raises_a_clear_error(tmp_path: Path) -> None:
    path = tmp_path / "broken.apk"
    path.write_bytes(b"this is not a zip file")
    with pytest.raises(ValueError, match="not a readable apk"):
        scan(path)
