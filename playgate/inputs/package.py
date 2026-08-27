"""Read a compiled .apk or .aab into a ScanContext."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from ..axml import AXMLError, decode, looks_like_axml
from ..models import BuildConfig, ProjectKind, ScanContext, SourceFile
from ..proto import ProtoError
from ..proto import decode as decode_proto
from ..proto import looks_like_proto_manifest

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

# Files inside the package worth reading as text for secret scanning.
TEXT_MEMBER_SUFFIXES = {".json", ".xml", ".txt", ".properties", ".js", ".cfg", ".yaml", ".yml"}
TEXT_MEMBER_PREFIXES = ("assets/", "res/raw/", "res/xml/", "META-INF/")

MAX_MEMBER_BYTES = 1024 * 1024
MAX_BINARY_SCAN_BYTES = 24 * 1024 * 1024
MIN_STRING_RUN = 8

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_RUN)


def _extract_strings(blob: bytes, limit: int = 200_000) -> str:
    """Pull printable ASCII runs out of a binary blob (dex, arsc)."""
    found: list[str] = []
    for match in _PRINTABLE_RUN.finditer(blob):
        found.append(match.group().decode("ascii", errors="replace"))
        if len(found) >= limit:
            break
    return "\n".join(found)


def _read_manifest(zf: zipfile.ZipFile, notes: list[str]) -> str | None:
    candidates = ["AndroidManifest.xml", "base/manifest/AndroidManifest.xml"]
    names = set(zf.namelist())
    for name in candidates:
        if name not in names:
            continue
        raw = zf.read(name)
        if looks_like_axml(raw):
            try:
                return decode(raw)
            except AXMLError as exc:
                notes.append(f"{name} could not be decoded ({exc}); manifest rules were skipped.")
                return None
        if raw.lstrip()[:1] == b"<":
            return raw.decode("utf-8", errors="replace")
        if looks_like_proto_manifest(raw):
            try:
                return decode_proto(raw)
            except ProtoError as exc:
                notes.append(
                    f"{name} is a protobuf manifest (typical for .aab) but could not be decoded "
                    f"({exc}). Convert it with `bundletool dump manifest --bundle app.aab`."
                )
                return None
        notes.append(
            f"{name} is in an unrecognised binary form. "
            "Convert it first: `bundletool dump manifest --bundle app.aab`, "
            "or scan the source project instead."
        )
        return None
    notes.append("No AndroidManifest.xml found in the package.")
    return None


def _signature_notes(path: Path, zf: zipfile.ZipFile) -> list[str]:
    notes: list[str] = []
    v1 = [
        n for n in zf.namelist()
        if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
    ]
    blob = path.read_bytes()[-MAX_BINARY_SCAN_BYTES:]
    has_block = APK_SIG_BLOCK_MAGIC in blob
    if has_block:
        notes.append("APK signing block present (v2/v3 scheme).")
    if v1:
        notes.append(f"v1 (JAR) signature present: {v1[0]}")
    if not has_block and not v1:
        notes.append("No signature detected — this looks like an unsigned build.")
    return notes


def context_from_package(path: Path) -> ScanContext:
    from ..collect import parse_manifest_xml  # local import avoids a cycle

    path = path.resolve()
    ctx = ScanContext(root=path, kind=ProjectKind.APK)

    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"{path.name} is not a readable apk/aab: {exc}") from exc

    with zf:
        manifest_xml = _read_manifest(zf, ctx.notes)
        if manifest_xml:
            manifest = parse_manifest_xml(manifest_xml, "AndroidManifest.xml")
            if manifest:
                ctx.manifests.append(manifest)
            ctx.files.append(
                SourceFile(
                    path=path.parent / "AndroidManifest.xml",
                    relpath="AndroidManifest.xml",
                    text=manifest_xml,
                )
            )

        for info in zf.infolist():
            if info.is_dir() or info.file_size > MAX_MEMBER_BYTES:
                continue
            name = info.filename
            suffix = Path(name).suffix.lower()
            interesting = suffix in TEXT_MEMBER_SUFFIXES or name.startswith(TEXT_MEMBER_PREFIXES)
            if not interesting or name == "AndroidManifest.xml":
                continue
            try:
                raw = zf.read(info)
            except (zipfile.BadZipFile, RuntimeError):
                continue
            if looks_like_axml(raw):
                try:
                    text = decode(raw)
                except AXMLError:
                    continue
            else:
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    continue
            ctx.files.append(
                SourceFile(path=path.parent / name, relpath=name, text=text)
            )

        # Compiled code still carries string literals; scan them for secrets.
        for info in zf.infolist():
            base = Path(info.filename).name
            if not (base.startswith("classes") and base.endswith(".dex")):
                if info.filename != "resources.arsc":
                    continue
            if info.file_size > MAX_BINARY_SCAN_BYTES:
                ctx.notes.append(f"{info.filename} skipped for string extraction (too large).")
                continue
            try:
                blob = zf.read(info)
            except (zipfile.BadZipFile, RuntimeError):
                continue
            text = _extract_strings(blob)
            if text:
                label = f"{info.filename} (extracted strings)"
                ctx.files.append(
                    SourceFile(path=path.parent / info.filename, relpath=label, text=text)
                )

        ctx.notes.extend(_signature_notes(path, zf))

    build = BuildConfig(source_path="AndroidManifest.xml")
    if ctx.manifests:
        uses_sdk = ctx.manifests[0].uses_sdk
        for key, attr in (
            ("targetSdkVersion", "target_sdk"),
            ("minSdkVersion", "min_sdk"),
        ):
            value = uses_sdk.get(key)
            if value and value.isdigit():
                setattr(build, attr, int(value))
        app = ctx.manifests[0].application_attrs
        if "android:debuggable" in app:
            build.debuggable_release = app["android:debuggable"].lower() == "true"
    ctx.build = build
    return ctx
