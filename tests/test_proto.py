"""Protobuf (.aab) manifest decoding."""

from __future__ import annotations

import zipfile
from pathlib import Path

from playgate.collect import parse_manifest_xml
from playgate.models import ProjectKind, Severity
from playgate.proto import ProtoError, decode, looks_like_proto_manifest
from playgate.scan import scan

from .conftest import ids
from .proto_fixture import build_manifest_proto


def test_decode_produces_parseable_xml() -> None:
    xml = decode(build_manifest_proto())
    assert xml.lstrip().startswith("<manifest")
    manifest = parse_manifest_xml(xml)
    assert manifest is not None
    assert manifest.package == "com.demo.aab"
    assert manifest.uses_sdk["targetSdkVersion"] == "33"
    assert manifest.uses_sdk["minSdkVersion"] == "24"
    assert manifest.has_permission("QUERY_ALL_PACKAGES")
    assert manifest.application_attrs.get("android:debuggable") == "true"
    service = next(c for c in manifest.components if c.kind == "service")
    assert service.exported is True


def test_looks_like_proto_manifest() -> None:
    assert looks_like_proto_manifest(build_manifest_proto())
    assert not looks_like_proto_manifest(b"<manifest")
    assert not looks_like_proto_manifest(b"")


def test_garbage_is_rejected() -> None:
    try:
        decode(b"\x0a\x05hello")  # a node whose element is not a <manifest>
    except ProtoError:
        return
    raise AssertionError("expected ProtoError")


def make_aab(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("base/manifest/AndroidManifest.xml", build_manifest_proto())
        zf.writestr("base/dex/classes.dex", b"dex\n035\x00padding")
    return path


def test_aab_is_scanned_end_to_end(tmp_path: Path) -> None:
    report = scan(make_aab(tmp_path / "app.aab"))
    assert report.kind is ProjectKind.APK
    found = ids(report)
    assert "AND-DEBUGGABLE" in found
    assert "AND-EXPORTED-OPEN" in found
    assert "PLY-PERM-QUERY_ALL_PACKAGES" in found
    assert "PLY-TARGET-API" in found
    target = next(f for f in report.findings if f.id == "PLY-TARGET-API")
    assert target.severity is Severity.CRITICAL  # targetSdk 33 < discoverability floor
