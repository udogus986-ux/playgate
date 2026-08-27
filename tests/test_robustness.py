"""Adversarial-input robustness.

playgate parses artifacts it did not build — an .apk/.aab is untrusted input. A
security tool must degrade gracefully on hostile input: never crash the scan,
never hang (ReDoS / unbounded loops), never OOM. These tests feed malformed and
adversarial data and assert a clean failure within a time bound.
"""

from __future__ import annotations

import struct
import time
import zipfile
from pathlib import Path

import pytest

from playgate.axml import AXMLError, decode as decode_axml
from playgate.proto import ProtoError, decode as decode_proto
from playgate.scan import scan
from playgate.models import Severity

from .conftest import write

TIME_BUDGET = 8.0  # seconds; catastrophic backtracking / loops blow well past this


def _timed(fn, *args):
    start = time.perf_counter()
    try:
        fn(*args)
    finally:
        elapsed = time.perf_counter() - start
    assert elapsed < TIME_BUDGET, f"took {elapsed:.1f}s (budget {TIME_BUDGET}s)"


# --------------------------------------------------------------------------
# Binary XML decoder
# --------------------------------------------------------------------------

def test_axml_truncated_header() -> None:
    with pytest.raises(AXMLError):
        decode_axml(b"\x03\x00\x08\x00")  # RES_XML header, nothing after


def test_axml_garbage_with_magic() -> None:
    blob = b"\x03\x00\x08\x00" + b"\xff" * 64
    with pytest.raises(AXMLError):
        decode_axml(blob)


def test_axml_huge_string_count_does_not_hang_or_oom() -> None:
    # A string pool whose count claims ~4 billion entries must not be trusted:
    # the decoder must bound it against the actual data, not loop 4e9 times.
    pool_body = struct.pack("<IIIII", 0xFFFFFFFF, 0, 0, 40, 0)   # count=4e9, strings_start=40
    pool_body += b"\x00" * 20                                     # padding up to strings_start
    pool = struct.pack("<HHI", 0x0001, 28, 8 + len(pool_body)) + pool_body
    header = struct.pack("<HHI", 0x0003, 8, 8 + len(pool))
    blob = header + pool
    _timed(_try_axml, blob)  # must return quickly, not loop 4e9 times


def _try_axml(blob: bytes) -> None:
    try:
        decode_axml(blob)
    except AXMLError:
        pass  # the only acceptable failure


def test_axml_random_bytes_never_crash_uncaught() -> None:
    for seed in range(20):
        blob = b"\x03\x00\x08\x00" + bytes((seed * 37 + i * 13) & 0xFF for i in range(200))
        try:
            decode_axml(blob)
        except AXMLError:
            pass  # the only acceptable exception


# --------------------------------------------------------------------------
# Protobuf (.aab) decoder
# --------------------------------------------------------------------------

def test_proto_deep_nesting_does_not_recurse_to_death() -> None:
    # Build a deeply nested XmlNode → XmlElement → child → … chain.
    def _len(field, payload):
        def _varint(n):
            out = bytearray()
            while True:
                b = n & 0x7F
                n >>= 7
                if n:
                    out.append(b | 0x80)
                else:
                    out.append(b)
                    return bytes(out)
        return _varint((field << 3) | 2) + _varint(len(payload)) + payload

    blob = _len(3, b"manifest")  # innermost element name
    for _ in range(5000):
        element = _len(3, b"x") + _len(5, _len(1, blob))  # element{name, child=node{element}}
        blob = element
    doc = _len(1, blob)  # wrap as a node
    _timed(_try_proto, doc)


def _try_proto(blob: bytes) -> None:
    try:
        decode_proto(blob)
    except ProtoError:
        pass


def test_proto_huge_length_field() -> None:
    # A length-delimited field claiming more bytes than exist must be refused.
    blob = b"\x0a\xff\xff\xff\x7f"  # field 1, wire 2, length ~268M, no data
    with pytest.raises(ProtoError):
        decode_proto(blob)


def test_proto_random_bytes_never_crash_uncaught() -> None:
    for seed in range(20):
        blob = bytes((seed * 41 + i * 7) & 0xFF for i in range(200))
        try:
            decode_proto(blob)
        except ProtoError:
            pass


# --------------------------------------------------------------------------
# Regex rules — no catastrophic backtracking on adversarial source
# --------------------------------------------------------------------------

def test_regex_rules_bounded_on_adversarial_source(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 36 } }\n")
    # Strings crafted to stress the WebView/TLS/secret regexes.
    adversarial = (
        "HostnameVerifier " + "{" * 5000 + "\n"
        + "storePassword " + "a" * 20000 + "\n"
        + 'val k = "' + "A" * 50000 + '"\n'
        + "Cipher.getInstance(" + '"AES/' * 5000 + '")\n'
    )
    write(root / "app" / "src" / "main" / "java" / "Evil.kt", adversarial)
    _timed(lambda p: scan(p), root)


# --------------------------------------------------------------------------
# Package (zip) handling
# --------------------------------------------------------------------------

def test_corrupt_zip_raises_clean_error(tmp_path: Path) -> None:
    p = tmp_path / "x.apk"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 50)  # looks like a zip, isn't
    with pytest.raises(ValueError):
        scan(p)


def test_apk_member_with_traversal_name_is_safe(tmp_path: Path) -> None:
    # A zip entry named with .. must not cause any write outside memory.
    p = tmp_path / "x.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../../../evil.json", '{"a": 1}')
        zf.writestr("assets/../../../../etc/passwd.txt", "root:x:0:0")
    report = scan(p)  # must complete without touching the filesystem outside
    assert report.kind.value == "apk"


def test_empty_and_tiny_packages(tmp_path: Path) -> None:
    p = tmp_path / "empty.apk"
    with zipfile.ZipFile(p, "w"):
        pass
    report = scan(p)  # no crash on an empty zip
    assert any("No AndroidManifest" in n for n in report.notes)
