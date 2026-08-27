"""Godot 4 export configuration rules."""

from __future__ import annotations

import re
from typing import Iterator

from ..models import Category, Finding, Location, ProjectKind, ScanContext, Severity
from .base import rule

DOC_EXPORT = "https://docs.godotengine.org/en/stable/tutorials/export/exporting_for_android.html"

# Permissions Godot exposes as checkboxes that are rarely needed by a game and
# that Play treats as sensitive.
NOISY_PERMISSIONS = {
    "read_phone_state", "read_sms", "receive_sms", "send_sms", "read_call_log",
    "write_call_log", "process_outgoing_calls", "read_contacts", "write_contacts",
    "record_audio", "camera", "access_fine_location", "access_background_location",
    "read_external_storage", "write_external_storage", "get_accounts",
    "system_alert_window", "request_install_packages", "query_all_packages",
}


def _preset_blocks(text: str) -> list[tuple[str, int]]:
    """Split export_presets.cfg into (block_text, start_offset) per preset."""
    blocks: list[tuple[str, int]] = []
    matches = list(re.finditer(r"^\[preset\.\d+\]", text, re.MULTILINE))
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        blocks.append((text[match.start() : end], match.start()))
    return blocks or [(text, 0)]


@rule("godot.permissions")
def noisy_permissions(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.kind is not ProjectKind.GODOT:
        return
    pattern = re.compile(r'permissions/([a-z_0-9]+)\s*=\s*true')
    for f in ctx.files_named("export_presets.cfg"):
        enabled = []
        first_offset = None
        for match in pattern.finditer(f.text):
            name = match.group(1).lower()
            if name in NOISY_PERMISSIONS:
                enabled.append(name)
                if first_offset is None:
                    first_offset = match.start()
        if not enabled:
            continue
        yield Finding(
            id="GDT-PERMISSIONS",
            title=f"Export preset enables {len(enabled)} sensitive permission(s)",
            severity=Severity.MEDIUM,
            category=Category.POLICY,
            why=(
                "Godot's permission checkboxes go straight into the manifest. Play requires a "
                "justification for sensitive permissions, and asking for ones the game never "
                "uses is a common rejection reason: "
                + ", ".join(sorted(enabled))
            ),
            fix=(
                "Untick every permission the game does not actually use, re-export, and confirm "
                "the generated manifest with `aapt dump permissions`."
            ),
            location=Location(f.relpath, f.line_of(first_offset) if first_offset else None),
            evidence=", ".join(f"permissions/{p}=true" for p in sorted(enabled)[:6]),
            refs=(DOC_EXPORT,),
            rejection_weight=15,
        )


@rule("godot.signing")
def release_signing(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.kind is not ProjectKind.GODOT:
        return
    for f in ctx.files_named("export_presets.cfg"):
        for block, offset in _preset_blocks(f.text):
            if "platform=" in block.replace(" ", "") and "Android" not in block:
                continue
            release_keystore = re.search(r'keystore/release\s*=\s*"([^"]*)"', block)
            debug_used = re.search(r'package/signed\s*=\s*false', block)
            if debug_used:
                yield Finding(
                    id="GDT-UNSIGNED",
                    title="Export preset produces an unsigned package",
                    severity=Severity.MEDIUM,
                    category=Category.POLICY,
                    why="Play will not accept an unsigned artifact.",
                    fix="Enable signing on the preset and point it at your release keystore.",
                    location=Location(f.relpath, f.line_of(offset)),
                    evidence="package/signed=false",
                    refs=(DOC_EXPORT,),
                    rejection_weight=20,
                )
            if release_keystore is not None and not release_keystore.group(1).strip():
                yield Finding(
                    id="GDT-DEBUG-KEYSTORE",
                    title="No release keystore set — the debug key will be used",
                    severity=Severity.HIGH,
                    category=Category.POLICY,
                    why=(
                        "A build signed with the Android debug key is rejected by Play, and a "
                        "debug-signed APK cannot later be updated by a properly signed one."
                    ),
                    fix=(
                        "Create a release keystore, set keystore/release and its user/password "
                        "through environment variables, and enrol in Play App Signing."
                    ),
                    location=Location(f.relpath, f.line_of(release_keystore.start())),
                    evidence='keystore/release=""',
                    refs=(DOC_EXPORT,),
                    rejection_weight=25,
                )


@rule("godot.gradle_build")
def gradle_build_disabled(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.kind is not ProjectKind.GODOT:
        return
    for f in ctx.files_named("export_presets.cfg"):
        match = re.search(r"gradle_build/use_gradle_build\s*=\s*false", f.text)
        if not match:
            continue
        yield Finding(
            id="GDT-NO-GRADLE",
            title="Gradle build is disabled for the Android export",
            severity=Severity.LOW,
            category=Category.POLICY,
            why=(
                "Without the gradle build you use Godot's prebuilt template, so you cannot set "
                "target SDK, add plugins, or produce an .aab with custom manifest entries — all "
                "of which Play now expects."
            ),
            fix="Install the Android build template and set use_gradle_build=true.",
            location=Location(f.relpath, f.line_of(match.start())),
            evidence=match.group(0),
            refs=(DOC_EXPORT,),
            rejection_weight=5,
        )
