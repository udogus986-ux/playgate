"""Minimal decoder for Android's binary XML (AXML) format.

Only what an AndroidManifest needs: the string pool, element start/end and
attributes. The output is a plain XML string, so the same manifest parser can
be used for source projects and for compiled packages.

Format reference: ResourceTypes.h in the AOSP framework. Chunks are
``uint16 type, uint16 headerSize, uint32 size`` followed by type-specific data.
"""

from __future__ import annotations

import struct
from xml.sax.saxutils import escape, quoteattr

RES_NULL = 0x0000
RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

UTF8_FLAG = 1 << 8

# Res_value data types we care about.
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

NO_ENTRY = 0xFFFFFFFF


class AXMLError(ValueError):
    """Raised when the input is not decodable binary XML."""


def looks_like_axml(data: bytes) -> bool:
    if len(data) < 8:
        return False
    chunk_type, header_size = struct.unpack_from("<HH", data, 0)
    return chunk_type == RES_XML and header_size == 8


class StringPool:
    def __init__(self, data: bytes, offset: int) -> None:
        chunk_type, header_size, size = struct.unpack_from("<HHI", data, offset)
        if chunk_type != RES_STRING_POOL:
            raise AXMLError(f"expected string pool, got chunk type 0x{chunk_type:04x}")
        (count, style_count, flags, strings_start, _styles_start) = struct.unpack_from(
            "<IIIII", data, offset + 8
        )
        self.count = count
        self.is_utf8 = bool(flags & UTF8_FLAG)
        self._strings: list[str] = []

        offsets_at = offset + header_size
        base = offset + strings_start
        if base > len(data):
            raise AXMLError("string pool data starts past end of file")
        # Never trust the declared count: a crafted pool can claim billions of
        # entries to force a 4e9-iteration loop / OOM. Bound it by the bytes
        # actually available for the offset table (each offset is 4 bytes).
        max_count = max(0, (base - offsets_at) // 4)
        if count > max_count:
            count = max_count
        for i in range(count):
            try:
                (rel,) = struct.unpack_from("<I", data, offsets_at + 4 * i)
                self._strings.append(self._read(data, base + rel))
            except (struct.error, IndexError, UnicodeDecodeError):
                self._strings.append("")
        self.end = offset + size

    def _read(self, data: bytes, at: int) -> str:
        if self.is_utf8:
            at, _utf16_len = _decode_len8(data, at)
            at, byte_len = _decode_len8(data, at)
            return data[at : at + byte_len].decode("utf-8", errors="replace")
        at, char_len = _decode_len16(data, at)
        raw = data[at : at + char_len * 2]
        return raw.decode("utf-16-le", errors="replace")

    def get(self, index: int) -> str:
        if index == NO_ENTRY or index < 0 or index >= len(self._strings):
            return ""
        return self._strings[index]


def _decode_len8(data: bytes, at: int) -> tuple[int, int]:
    value = data[at]
    at += 1
    if value & 0x80:
        value = ((value & 0x7F) << 8) | data[at]
        at += 1
    return at, value


def _decode_len16(data: bytes, at: int) -> tuple[int, int]:
    (value,) = struct.unpack_from("<H", data, at)
    at += 2
    if value & 0x8000:
        (low,) = struct.unpack_from("<H", data, at)
        at += 2
        value = ((value & 0x7FFF) << 16) | low
    return at, value


def _format_value(pool: StringPool, raw_index: int, data_type: int, value: int) -> str:
    if raw_index != NO_ENTRY:
        text = pool.get(raw_index)
        if text:
            return text
    if data_type == TYPE_STRING:
        return pool.get(value)
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if value else "false"
    if data_type == TYPE_INT_HEX:
        return f"0x{value:08x}"
    if data_type == TYPE_REFERENCE:
        return f"@0x{value:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{value:08x}"
    if data_type == TYPE_FLOAT:
        (as_float,) = struct.unpack("<f", struct.pack("<I", value))
        return repr(as_float)
    if data_type == TYPE_NULL:
        return ""
    # Signed decimals show up for things like versionCode.
    if value >= 0x80000000:
        return str(value - 0x100000000)
    return str(value)


def decode(data: bytes) -> str:
    """Decode binary XML into an XML text document.

    Namespace prefixes seen in the document are emitted as ``xmlns:`` on the
    root element so the result parses with a standard XML parser.
    """
    if not looks_like_axml(data):
        raise AXMLError("not an AXML document")
    try:
        return _decode(data)
    except (struct.error, IndexError, RecursionError, MemoryError) as exc:
        raise AXMLError(f"malformed AXML: {exc}") from exc


def _decode(data: bytes) -> str:
    _type, header_size, _size = struct.unpack_from("<HHI", data, 0)
    offset = header_size
    pool: StringPool | None = None
    namespaces: dict[str, str] = {}  # uri -> prefix
    out: list[str] = []
    depth = 0
    pending_root_ns = True

    end = len(data)
    while offset + 8 <= end:
        chunk_type, chunk_header, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_size <= 0 or offset + chunk_size > end:
            break

        if chunk_type == RES_STRING_POOL:
            pool = StringPool(data, offset)
        elif chunk_type == RES_XML_RESOURCE_MAP:
            pass
        elif chunk_type == RES_XML_START_NAMESPACE:
            if pool is not None:
                prefix_idx, uri_idx = struct.unpack_from("<II", data, offset + chunk_header)
                namespaces[pool.get(uri_idx)] = pool.get(prefix_idx)
        elif chunk_type == RES_XML_END_NAMESPACE:
            pass
        elif chunk_type == RES_XML_START_ELEMENT:
            if pool is None:
                raise AXMLError("start element before string pool")
            body = offset + chunk_header
            _ns_idx, name_idx = struct.unpack_from("<II", data, body)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, body + 8)
            name = pool.get(name_idx) or "unknown"
            parts = [f"<{name}"]
            if pending_root_ns:
                for uri, prefix in namespaces.items():
                    if uri:
                        parts.append(f' xmlns:{prefix or "ns"}={quoteattr(uri)}')
                pending_root_ns = False
            attrs_at = body + attr_start
            for i in range(attr_count):
                at = attrs_at + i * attr_size
                (a_ns, a_name, a_raw) = struct.unpack_from("<III", data, at)
                (_size16, _res0, a_type, a_value) = struct.unpack_from("<HBBI", data, at + 12)
                attr_name = pool.get(a_name)
                if not attr_name:
                    # Obfuscated packages drop attribute names and keep only
                    # resource ids. Surface it rather than guessing wrong.
                    attr_name = "unknown-attr"
                prefix = namespaces.get(pool.get(a_ns), "")
                qualified = f"{prefix}:{attr_name}" if prefix else attr_name
                value = _format_value(pool, a_raw, a_type, a_value)
                parts.append(f" {qualified}={quoteattr(value)}")
            parts.append(">")
            out.append("  " * depth + "".join(parts))
            depth += 1
        elif chunk_type == RES_XML_END_ELEMENT:
            if pool is None:
                raise AXMLError("end element before string pool")
            body = offset + chunk_header
            _ns_idx, name_idx = struct.unpack_from("<II", data, body)
            depth = max(0, depth - 1)
            out.append("  " * depth + f"</{pool.get(name_idx) or 'unknown'}>")
        elif chunk_type == RES_XML_CDATA:
            if pool is not None:
                body = offset + chunk_header
                (text_idx,) = struct.unpack_from("<I", data, body)
                text = pool.get(text_idx).strip()
                if text:
                    out.append("  " * depth + escape(text))

        offset += chunk_size

    if not out:
        raise AXMLError("no elements decoded")
    return "\n".join(out)
