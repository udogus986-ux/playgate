"""DEX method-table analysis for compiled packages."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from playgate.dex import DexError, analyze, method_refs
from playgate.scan import scan

from .axml_fixture import build_manifest_axml
from .conftest import ids
from .dex_fixture import build_dex

WEBVIEW = ("Landroid/webkit/WebView;", "addJavascriptInterface")
CIPHER = ("Ljavax/crypto/Cipher;", "getInstance")
DIGEST = ("Ljava/security/MessageDigest;", "getInstance")
LOADER = ("Ldalvik/system/DexClassLoader;", "<init>")


def test_method_refs_decoded() -> None:
    refs = method_refs(build_dex([WEBVIEW, LOADER]))
    assert "Landroid/webkit/WebView;->addJavascriptInterface" in refs
    assert "Ldalvik/system/DexClassLoader;-><init>" in refs


def test_weak_crypto_strings() -> None:
    _, crypto = analyze(build_dex([CIPHER], extra_strings=("AES/ECB/PKCS5Padding", "MD5", "hello world")))
    assert crypto == {"AES/ECB/PKCS5Padding", "MD5"}


def test_forged_sizes_are_rejected() -> None:
    blob = bytearray(build_dex([WEBVIEW]))
    struct.pack_into("<I", blob, 0x58, 0x7FFFFFFF)  # absurd method count
    with pytest.raises(DexError):
        method_refs(bytes(blob))


def test_out_of_range_index_is_rejected() -> None:
    blob = bytearray(build_dex([WEBVIEW]))
    method_off = struct.unpack_from("<I", blob, 0x5C)[0]
    struct.pack_into("<H", blob, method_off, 999)  # class_idx past type table
    with pytest.raises(DexError):
        method_refs(bytes(blob))


def _apk(tmp_path: Path, dex: bytes) -> Path:
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", build_manifest_axml())
        zf.writestr("classes.dex", dex)
    return path


def test_apk_api_findings(tmp_path: Path) -> None:
    dex = build_dex([WEBVIEW, LOADER, CIPHER, DIGEST], extra_strings=("AES", "SHA-1"))
    found = ids(scan(_apk(tmp_path, dex)))
    assert {"DEX-WEBVIEW-JSBRIDGE", "DEX-DYNAMIC-CODE", "DEX-WEAK-CIPHER", "DEX-WEAK-HASH"} <= found


def test_strong_crypto_is_quiet(tmp_path: Path) -> None:
    dex = build_dex([CIPHER, DIGEST], extra_strings=("AES/GCM/NoPadding", "SHA-256"))
    found = ids(scan(_apk(tmp_path, dex)))
    assert "DEX-WEAK-CIPHER" not in found
    assert "DEX-WEAK-HASH" not in found


def test_corrupt_dex_degrades_to_note(tmp_path: Path) -> None:
    blob = bytearray(build_dex([WEBVIEW]))
    struct.pack_into("<I", blob, 0x58, 0x7FFFFFFF)
    report = scan(_apk(tmp_path, bytes(blob)))
    assert any("method table unreadable" in n for n in report.notes)
