"""Generate packaging/playgate.ico with the standard library only.

A rounded blue square with a white "gate" chevron, rendered at 16/32/48/256 px
and stored as PNG-compressed ICO entries (supported since Windows Vista).

    python packaging/make_icon.py
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

BLUE = (47, 111, 228)
WHITE = (255, 255, 255)


def _pixel(x: float, y: float, size: int) -> tuple[int, int, int, int]:
    # Coordinates normalised to 0..1.
    u, v = x / size, y / size
    r = 0.22  # corner radius
    inside = True
    for cx, cy in ((r, r), (1 - r, r), (r, 1 - r), (1 - r, 1 - r)):
        if (u < r or u > 1 - r) and (v < r or v > 1 - r):
            if (u - cx) ** 2 + (v - cy) ** 2 > r * r and abs(u - cx) < r and abs(v - cy) < r:
                inside = False
    if not inside:
        return (0, 0, 0, 0)
    # A right-pointing chevron (the "gate" / play mark).
    t = 0.12  # stroke thickness
    in_chevron = 0.30 <= u <= 0.72 and abs(v - 0.5) <= 0.5 * (0.72 - u) * 1.35 + t / 2 \
        and abs(v - 0.5) >= 0.5 * (0.72 - u) * 1.35 - t / 2
    if in_chevron:
        return (*WHITE, 255)
    return (*BLUE, 255)


def _png(size: int) -> bytes:
    ss = 4  # supersampling for smooth edges
    rows = []
    for y in range(size):
        row = bytearray([0])  # filter: none
        for x in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    p = _pixel(x + (sx + 0.5) / ss, y + (sy + 0.5) / ss, size)
                    for i in range(4):
                        acc[i] += p[i]
            n = ss * ss
            a = acc[3] // n
            if a:
                row += bytes((acc[0] // n * 255 // max(a, 1) if a < 255 else acc[0] // n,
                              acc[1] // n * 255 // max(a, 1) if a < 255 else acc[1] // n,
                              acc[2] // n * 255 // max(a, 1) if a < 255 else acc[2] // n, a))
            else:
                row += b"\x00\x00\x00\x00"
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def build_ico(sizes=(16, 32, 48, 256)) -> bytes:
    images = [_png(s) for s in sizes]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for s, img in zip(sizes, images):
        dim = 0 if s >= 256 else s
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
    return header + entries + b"".join(images)


if __name__ == "__main__":
    out = Path(__file__).with_name("playgate.ico")
    out.write_bytes(build_ico())
    print(f"wrote {out} ({out.stat().st_size} bytes)")
