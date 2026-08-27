"""Decode an Android App Bundle's protobuf ``AndroidManifest.xml``.

An `.aab` stores its manifest as protobuf using aapt2's ``XmlNode`` schema
(``Resources.proto`` in AOSP), not the binary-XML that an `.apk` uses. Rather
than shell out to ``bundletool``, this reads the wire format directly and emits
the same XML-string shape as :mod:`playgate.axml`, so one manifest parser
serves source projects, apks and bundles alike.

Only the messages a manifest needs are interpreted:

    XmlNode      { XmlElement element = 1; string text = 2; }
    XmlElement   { repeated XmlNamespace namespace_declaration = 1;
                   string namespace_uri = 2; string name = 3;
                   repeated XmlAttribute attribute = 4;
                   repeated XmlNode child = 5; }
    XmlNamespace { string prefix = 1; string uri = 2; }
    XmlAttribute { string namespace_uri = 1; string name = 2; string value = 3;
                   uint32 resource_id = 5; Item compiled_item = 6; }
    Item         { Reference ref = 1; String str = 2; ...; Primitive prim = 7; }
    Primitive    { float float_value = 3; int32 int_decimal_value = 6;
                   uint32 int_hexadecimal_value = 7; bool boolean_value = 8; }
"""

from __future__ import annotations

import struct
from xml.sax.saxutils import quoteattr

WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LEN = 2
WIRE_32BIT = 5

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class ProtoError(ValueError):
    """Raised when the bytes are not a decodable protobuf manifest."""


def looks_like_proto_manifest(data: bytes) -> bool:
    """A cheap gate: a proto ``XmlNode`` starts with the ``element`` field.

    Field 1, wire type 2 → key byte 0x0A. Source XML starts with ``<`` (0x3C)
    and binary XML with the RES_XML chunk header, so this is unambiguous enough
    to try a decode.
    """
    return len(data) >= 2 and data[0] == 0x0A


def _read_varint(data: bytes, i: int) -> tuple[int, int]:
    result = 0
    shift = 0
    n = len(data)
    while i < n:
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7
        if shift > 70:
            raise ProtoError("varint too long")
    raise ProtoError("truncated varint")


def _parse_fields(data: bytes) -> dict[int, list[tuple[int, object]]]:
    """Split a message into ``{field_number: [(wire_type, value), ...]}``."""
    out: dict[int, list[tuple[int, object]]] = {}
    i = 0
    n = len(data)
    while i < n:
        key, i = _read_varint(data, i)
        field = key >> 3
        wire = key & 0x07
        if wire == WIRE_VARINT:
            val, i = _read_varint(data, i)
        elif wire == WIRE_LEN:
            length, i = _read_varint(data, i)
            if i + length > n:
                raise ProtoError("length-delimited field runs past end")
            val = data[i : i + length]
            i += length
        elif wire == WIRE_32BIT:
            val = data[i : i + 4]
            i += 4
        elif wire == WIRE_64BIT:
            val = data[i : i + 8]
            i += 8
        else:
            raise ProtoError(f"unsupported wire type {wire}")
        out.setdefault(field, []).append((wire, val))
    return out


def _last(fields: dict, num: int):
    vals = fields.get(num)
    return vals[-1] if vals else None


def _str(fields: dict, num: int) -> str | None:
    item = _last(fields, num)
    if item is None:
        return None
    wire, val = item
    if wire == WIRE_LEN and isinstance(val, (bytes, bytearray)):
        return bytes(val).decode("utf-8", errors="replace")
    return None


def _to_signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def _decode_primitive(blob: bytes) -> str | None:
    f = _parse_fields(blob)
    if 6 in f:  # int_decimal_value (int32)
        return str(_to_signed32(f[6][-1][1]))
    if 7 in f:  # int_hexadecimal_value (uint32)
        return str(f[7][-1][1] & 0xFFFFFFFF)
    if 8 in f:  # boolean_value
        return "true" if f[8][-1][1] else "false"
    if 3 in f:  # float_value (32-bit)
        wire, val = f[3][-1]
        if wire == WIRE_32BIT and isinstance(val, (bytes, bytearray)) and len(val) == 4:
            return repr(struct.unpack("<f", bytes(val))[0])
    return None


def _decode_item(blob: bytes) -> str | None:
    f = _parse_fields(blob)
    prim = _last(f, 7)
    if prim and prim[0] == WIRE_LEN:
        got = _decode_primitive(bytes(prim[1]))
        if got is not None:
            return got
    string = _last(f, 2)  # String { string value = 1 }
    if string and string[0] == WIRE_LEN:
        s = _str(_parse_fields(bytes(string[1])), 1)
        if s is not None:
            return s
    ref = _last(f, 1)  # Reference { uint32 id = 1; string name = 2 }
    if ref and ref[0] == WIRE_LEN:
        rf = _parse_fields(bytes(ref[1]))
        name = _str(rf, 2)
        if name:
            return "@" + name
        if 1 in rf:
            return "@0x%08x" % (rf[1][-1][1] & 0xFFFFFFFF)
    return None


def _attr_value(af: dict) -> str:
    value = _str(af, 3)
    if value:
        return value
    compiled = _last(af, 6)
    if compiled and compiled[0] == WIRE_LEN:
        got = _decode_item(bytes(compiled[1]))
        if got is not None:
            return got
    return value or ""


def _decode_element(blob: bytes, namespaces: dict[str, str], out: list[str], depth: int) -> None:
    f = _parse_fields(blob)

    local_ns: dict[str, str] = {}
    for _wire, val in f.get(1, []):  # namespace_declaration
        nf = _parse_fields(bytes(val))
        uri = _str(nf, 2) or ""
        prefix = _str(nf, 1) or ""
        if uri:
            local_ns[uri] = prefix
    namespaces = {**namespaces, **local_ns}

    name = _str(f, 3) or "unknown"
    parts = [f"<{name}"]
    for uri, prefix in local_ns.items():
        parts.append(f' xmlns:{prefix or "ns"}={quoteattr(uri)}')

    for _wire, val in f.get(4, []):  # attribute
        af = _parse_fields(bytes(val))
        a_ns = _str(af, 1) or ""
        a_name = _str(af, 2) or "unknown-attr"
        prefix = namespaces.get(a_ns, "")
        qualified = f"{prefix}:{a_name}" if prefix else a_name
        parts.append(f" {qualified}={quoteattr(_attr_value(af))}")

    children = f.get(5, [])
    if not children:
        parts.append(">")
        out.append("  " * depth + "".join(parts))
        out.append("  " * depth + f"</{name}>")
        return

    parts.append(">")
    out.append("  " * depth + "".join(parts))
    for _wire, child in children:
        _decode_node(bytes(child), namespaces, out, depth + 1)
    out.append("  " * depth + f"</{name}>")


def _decode_node(blob: bytes, namespaces: dict[str, str], out: list[str], depth: int) -> None:
    f = _parse_fields(blob)
    element = _last(f, 1)
    if element and element[0] == WIRE_LEN:
        _decode_element(bytes(element[1]), namespaces, out, depth)
        return
    text = _str(f, 2)
    if text and text.strip():
        from xml.sax.saxutils import escape

        out.append("  " * depth + escape(text.strip()))


def decode(data: bytes) -> str:
    """Decode a protobuf ``XmlNode`` document into an XML text string."""
    if not data:
        raise ProtoError("empty document")
    out: list[str] = []
    try:
        _decode_node(data, {}, out, 0)
    except (IndexError, struct.error) as exc:
        raise ProtoError(f"malformed protobuf: {exc}") from exc
    if not out or not out[0].lstrip().startswith("<manifest"):
        raise ProtoError("no <manifest> element decoded")
    return "\n".join(out)
