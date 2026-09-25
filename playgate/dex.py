"""Read method references out of a DEX file.

A compiled package no longer has source, but every API the code calls is still
listed in the DEX ``method_ids`` table as (class, name). Reading that table —
not disassembling bytecode — is enough to know that an app calls
``WebView.addJavascriptInterface`` or loads code with ``DexClassLoader``.

Standard library only. The input is untrusted (someone else's APK), so every
count and offset is bounded against the buffer and any inconsistency raises
:class:`DexError` instead of reading out of range.

Format: https://source.android.com/docs/core/runtime/dex-format
"""

from __future__ import annotations

import re
import struct

MAGIC_PREFIX = b"dex\n"
HEADER_SIZE = 0x70
MAX_ITEMS = 4_000_000  # far above any real app; guards a forged size field


class DexError(ValueError):
    """Raised when the bytes are not a readable DEX file."""


def looks_like_dex(data: bytes) -> bool:
    return len(data) >= HEADER_SIZE and data[:4] == MAGIC_PREFIX


def _uleb128(data: bytes, at: int) -> tuple[int, int]:
    result = shift = 0
    for _ in range(5):
        if at >= len(data):
            raise DexError("truncated uleb128")
        b = data[at]
        at += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, at
        shift += 7
    raise DexError("uleb128 too long")


class Dex:
    def __init__(self, data: bytes) -> None:
        if not looks_like_dex(data):
            raise DexError("not a DEX file")
        self.data = data
        try:
            (self.string_ids_size, self.string_ids_off,
             self.type_ids_size, self.type_ids_off) = struct.unpack_from("<IIII", data, 0x38)
            self.method_ids_size, self.method_ids_off = struct.unpack_from("<II", data, 0x58)
        except struct.error as exc:
            raise DexError(f"bad header: {exc}") from exc
        self._check_table(self.string_ids_size, self.string_ids_off, 4, "string_ids")
        self._check_table(self.type_ids_size, self.type_ids_off, 4, "type_ids")
        self._check_table(self.method_ids_size, self.method_ids_off, 8, "method_ids")
        self._strings: dict[int, str] = {}

    def _check_table(self, size: int, off: int, item: int, name: str) -> None:
        if size > MAX_ITEMS:
            raise DexError(f"{name} size {size} is implausible")
        if size and (off < HEADER_SIZE or off + size * item > len(self.data)):
            raise DexError(f"{name} table runs outside the file")

    def string(self, idx: int) -> str:
        if idx in self._strings:
            return self._strings[idx]
        if idx >= self.string_ids_size:
            raise DexError("string index out of range")
        (data_off,) = struct.unpack_from("<I", self.data, self.string_ids_off + 4 * idx)
        if data_off >= len(self.data):
            raise DexError("string data outside the file")
        _utf16_len, at = _uleb128(self.data, data_off)
        end = self.data.find(b"\x00", at, at + 65536)
        if end < 0:
            raise DexError("unterminated string")
        # MUTF-8 is UTF-8 for every name we care about; replace anything odd.
        text = self.data[at:end].decode("utf-8", errors="replace")
        self._strings[idx] = text
        return text

    def type_name(self, idx: int) -> str:
        if idx >= self.type_ids_size:
            raise DexError("type index out of range")
        (desc,) = struct.unpack_from("<I", self.data, self.type_ids_off + 4 * idx)
        return self.string(desc)

    def method_refs(self) -> set[str]:
        """Every referenced method as 'Lpkg/Class;->name'."""
        out: set[str] = set()
        for i in range(self.method_ids_size):
            class_idx, _proto_idx, name_idx = struct.unpack_from(
                "<HHI", self.data, self.method_ids_off + 8 * i
            )
            out.add(f"{self.type_name(class_idx)}->{self.string(name_idx)}")
        return out


def method_refs(data: bytes) -> set[str]:
    try:
        return Dex(data).method_refs()
    except (struct.error, IndexError, RecursionError, MemoryError) as exc:
        raise DexError(f"malformed DEX: {exc}") from exc


# Cipher transformations / digest names that are weak. A bare "AES" defaults
# to AES/ECB on Android, so it counts.
WEAK_CIPHER = re.compile(r"(?:AES|DES|DESede|Blowfish|RC4|ARCFOUR)|[A-Za-z0-9]+/ECB/[A-Za-z0-9]+|(?:DES|DESede|RC4|Blowfish)/\w+/\w+")
WEAK_HASH = re.compile(r"MD5|SHA-?1")


def analyze(data: bytes) -> tuple[set[str], set[str]]:
    """(method refs, weak crypto strings) for one DEX file."""
    try:
        dex = Dex(data)
        refs = dex.method_refs()
        crypto: set[str] = set()
        for i in range(dex.string_ids_size):
            (off,) = struct.unpack_from("<I", data, dex.string_ids_off + 4 * i)
            # Cheap pre-filter on the raw bytes before decoding every string.
            if off + 2 >= len(data) or data[off] > 40:
                continue
            s = dex.string(i)
            if WEAK_CIPHER.fullmatch(s) or WEAK_HASH.fullmatch(s):
                crypto.add(s)
        return refs, crypto
    except (struct.error, IndexError, RecursionError, MemoryError) as exc:
        raise DexError(f"malformed DEX: {exc}") from exc
