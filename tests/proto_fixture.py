"""Build a protobuf ``AndroidManifest.xml`` the way an .aab stores it.

Mirrors ``axml_fixture.py``: a tiny encoder for aapt2's ``XmlNode`` schema, so
the proto decoder can be tested without shipping a real bundle.
"""

from __future__ import annotations

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _len_field(field: int, payload: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(payload)) + payload


def _str_field(field: int, text: str) -> bytes:
    return _len_field(field, text.encode("utf-8"))


def _varint_field(field: int, n: int) -> bytes:
    return _tag(field, 0) + _varint(n)


def namespace(prefix: str, uri: str) -> bytes:
    return _str_field(1, prefix) + _str_field(2, uri)


def attr_str(ns: str, name: str, value: str) -> bytes:
    return _str_field(1, ns) + _str_field(2, name) + _str_field(3, value)


def _item_int(n: int) -> bytes:
    primitive = _varint_field(6, n)          # Primitive { int_decimal_value = 6 }
    return _len_field(7, primitive)           # Item { prim = 7 }


def _item_bool(value: bool) -> bytes:
    primitive = _varint_field(8, 1 if value else 0)   # Primitive { boolean_value = 8 }
    return _len_field(7, primitive)


def attr_int(ns: str, name: str, n: int) -> bytes:
    return _str_field(1, ns) + _str_field(2, name) + _len_field(6, _item_int(n))


def attr_bool(ns: str, name: str, value: bool) -> bytes:
    return _str_field(1, ns) + _str_field(2, name) + _len_field(6, _item_bool(value))


def element(name: str, *, namespaces=(), attrs=(), children=()) -> bytes:
    body = b""
    for ns in namespaces:
        body += _len_field(1, ns)
    body += _str_field(3, name)
    for a in attrs:
        body += _len_field(4, a)
    for child in children:
        body += _len_field(5, child)
    return body


def node(element_bytes: bytes) -> bytes:
    """Wrap an element as an XmlNode ( element = field 1 )."""
    return _len_field(1, element_bytes)


def build_manifest_proto() -> bytes:
    service = element(
        "service",
        attrs=[
            attr_str(ANDROID_NS, "name", ".SyncService"),
            attr_bool(ANDROID_NS, "exported", True),
        ],
    )
    application = element(
        "application",
        attrs=[attr_bool(ANDROID_NS, "debuggable", True)],
        children=[node(service)],
    )
    uses_perm = element(
        "uses-permission",
        attrs=[attr_str(ANDROID_NS, "name", "android.permission.QUERY_ALL_PACKAGES")],
    )
    uses_sdk = element(
        "uses-sdk",
        attrs=[
            attr_int(ANDROID_NS, "minSdkVersion", 24),
            attr_int(ANDROID_NS, "targetSdkVersion", 33),
        ],
    )
    manifest = element(
        "manifest",
        namespaces=[namespace("android", ANDROID_NS)],
        attrs=[attr_str("", "package", "com.demo.aab")],
        children=[node(uses_perm), node(uses_sdk), node(application)],
    )
    return node(manifest)
