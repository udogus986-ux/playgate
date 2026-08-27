from xml.etree import ElementTree as ET

import pytest

from playgate.axml import AXMLError, decode, looks_like_axml
from playgate.collect import parse_manifest_xml

from .axml_fixture import build_manifest_axml


@pytest.mark.parametrize("utf8", [False, True])
def test_decode_roundtrip(utf8: bool) -> None:
    xml = decode(build_manifest_axml(utf8=utf8))
    root = ET.fromstring(xml)
    assert root.tag == "manifest"
    assert root.get("package") == "com.fixture.app"


@pytest.mark.parametrize("utf8", [False, True])
def test_manifest_parses_from_binary(utf8: bool) -> None:
    manifest = parse_manifest_xml(decode(build_manifest_axml(utf8=utf8)))
    assert manifest is not None
    assert manifest.package == "com.fixture.app"
    assert manifest.permissions == ["android.permission.QUERY_ALL_PACKAGES"]
    assert manifest.uses_sdk == {"minSdkVersion": "24", "targetSdkVersion": "33"}
    assert manifest.application_attrs["android:debuggable"] == "true"

    services = [c for c in manifest.components if c.kind == "service"]
    assert len(services) == 1
    assert services[0].name == "com.fixture.app.Sync"
    assert services[0].exported is True


def test_looks_like_axml_rejects_text() -> None:
    assert not looks_like_axml(b"<?xml version='1.0'?><manifest/>")
    assert not looks_like_axml(b"")
    assert looks_like_axml(build_manifest_axml())


def test_decode_rejects_non_axml() -> None:
    with pytest.raises(AXMLError):
        decode(b"not a binary xml document at all")


def test_truncated_input_does_not_hang() -> None:
    data = build_manifest_axml()
    # Cut mid-chunk: the decoder should stop cleanly at the damaged boundary.
    truncated = data[: len(data) - 12]
    try:
        result = decode(truncated)
    except AXMLError:
        return
    assert isinstance(result, str)
