"""Build a minimal DEX with just the tables playgate reads (strings, types,
method ids), so DEX analysis is tested without shipping a real APK."""

from __future__ import annotations

import struct


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def build_dex(methods: list[tuple[str, str]], extra_strings: tuple[str, ...] = ()) -> bytes:
    strings: list[str] = []
    for cls, name in methods:
        for s in (cls, name):
            if s not in strings:
                strings.append(s)
    for s in extra_strings:
        if s not in strings:
            strings.append(s)
    types = []
    for cls, _ in methods:
        if cls not in types:
            types.append(cls)

    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strings)
    proto_ids_off = type_ids_off + 4 * len(types)
    method_ids_off = proto_ids_off
    data_off = method_ids_off + 8 * len(methods)

    data = bytearray()
    string_offsets = []
    for s in strings:
        string_offsets.append(data_off + len(data))
        raw = s.encode("utf-8")
        data += _uleb(len(s)) + raw + b"\x00"

    body = bytearray()
    body += b"".join(struct.pack("<I", off) for off in string_offsets)
    body += b"".join(struct.pack("<I", strings.index(t)) for t in types)
    for cls, name in methods:
        body += struct.pack("<HHI", types.index(cls), 0, strings.index(name))

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    total = header_size + len(body) + len(data)
    struct.pack_into("<I", header, 0x20, total)
    struct.pack_into("<I", header, 0x24, header_size)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<IIII", header, 0x38, len(strings), string_ids_off, len(types), type_ids_off)
    struct.pack_into("<II", header, 0x58, len(methods), method_ids_off)
    return bytes(header + body + data)
