"""A tiny AXML *encoder*, used only by the tests.

Writing the format lets us decode something we know the answer to, instead of
needing a real APK checked into the repo.
"""

from __future__ import annotations

import struct

ANDROID_NS = "http://schemas.android.com/apk/res/android"

TYPE_STRING = 0x03
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_DEC = 0x10
NO_ENTRY = 0xFFFFFFFF


class Pool:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, value: str) -> int:
        if value not in self.items:
            self.items.append(value)
        return self.items.index(value)

    def encode(self, utf8: bool = False) -> bytes:
        offsets: list[int] = []
        blob = bytearray()
        for text in self.items:
            offsets.append(len(blob))
            if utf8:
                raw = text.encode("utf-8")
                blob += bytes([len(text) & 0x7F, len(raw) & 0x7F]) + raw + b"\x00"
            else:
                raw = text.encode("utf-16-le")
                blob += struct.pack("<H", len(text)) + raw + b"\x00\x00"
        while len(blob) % 4:
            blob += b"\x00"

        header_size = 28
        strings_start = header_size + 4 * len(self.items)
        size = strings_start + len(blob)
        flags = (1 << 8) if utf8 else 0
        out = struct.pack(
            "<HHIIIIII", 0x0001, header_size, size, len(self.items), 0, flags, strings_start, 0
        )
        out += b"".join(struct.pack("<I", o) for o in offsets)
        out += bytes(blob)
        return out


def _attr(pool: Pool, ns: str | None, name: str, value) -> bytes:
    ns_idx = pool.add(ns) if ns else NO_ENTRY
    name_idx = pool.add(name)
    if isinstance(value, bool):
        raw_idx, data_type, data = NO_ENTRY, TYPE_INT_BOOLEAN, (0xFFFFFFFF if value else 0)
    elif isinstance(value, int):
        raw_idx, data_type, data = NO_ENTRY, TYPE_INT_DEC, value
    else:
        raw_idx = pool.add(value)
        data_type, data = TYPE_STRING, raw_idx
    return (
        struct.pack("<III", ns_idx, name_idx, raw_idx)
        + struct.pack("<HBBI", 8, 0, data_type, data)
    )


def _start_element(pool: Pool, name: str, attrs: list[tuple[str | None, str, object]]) -> bytes:
    body = struct.pack("<II", NO_ENTRY, pool.add(name))
    body += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
    for ns, attr_name, value in attrs:
        body += _attr(pool, ns, attr_name, value)
    size = 16 + len(body)
    return struct.pack("<HHIII", 0x0102, 16, size, 1, NO_ENTRY) + body


def _end_element(pool: Pool, name: str) -> bytes:
    body = struct.pack("<II", NO_ENTRY, pool.add(name))
    return struct.pack("<HHIII", 0x0103, 16, 16 + len(body), 1, NO_ENTRY) + body


def _namespace(pool: Pool, chunk_type: int, prefix: str, uri: str) -> bytes:
    body = struct.pack("<II", pool.add(prefix), pool.add(uri))
    return struct.pack("<HHIII", chunk_type, 16, 16 + len(body), 1, NO_ENTRY) + body


def build_manifest_axml(utf8: bool = False) -> bytes:
    """A manifest with one permission, one exported activity and one service."""
    pool = Pool()
    # Strings are interned as chunks are built, so build bodies first.
    chunks = [
        _namespace(pool, 0x0100, "android", ANDROID_NS),
        _start_element(pool, "manifest", [(None, "package", "com.fixture.app")]),
        _start_element(
            pool, "uses-permission",
            [(ANDROID_NS, "name", "android.permission.QUERY_ALL_PACKAGES")],
        ),
        _end_element(pool, "uses-permission"),
        _start_element(
            pool, "uses-sdk",
            [(ANDROID_NS, "minSdkVersion", 24), (ANDROID_NS, "targetSdkVersion", 33)],
        ),
        _end_element(pool, "uses-sdk"),
        _start_element(pool, "application", [(ANDROID_NS, "debuggable", True)]),
        _start_element(
            pool, "service",
            [(ANDROID_NS, "name", "com.fixture.app.Sync"), (ANDROID_NS, "exported", True)],
        ),
        _end_element(pool, "service"),
        _end_element(pool, "application"),
        _end_element(pool, "manifest"),
        _namespace(pool, 0x0101, "android", ANDROID_NS),
    ]
    body = b"".join(chunks)
    pool_bytes = pool.encode(utf8=utf8)
    total = 8 + len(pool_bytes) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + pool_bytes + body
