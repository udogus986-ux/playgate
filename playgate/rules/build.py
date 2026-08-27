"""Rules over build configuration (Gradle release setup)."""

from __future__ import annotations

from typing import Iterator

from ..models import Category, Finding, Location, ScanContext, Severity
from .base import rule

DOC_SHRINK = "https://developer.android.com/build/shrink-code"
DOC_SIGNING = "https://developer.android.com/studio/publish/app-signing"


@rule("build.debuggable_release")
def debuggable_release(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.build.debuggable_release is not True:
        return
    yield Finding(
        id="BLD-DEBUGGABLE",
        title="Release build type sets debuggable = true",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        why=(
            "Every release built from this config is debuggable: memory is readable, code is "
            "attachable, and Play will reject the upload."
        ),
        fix="Remove the debuggable flag from buildTypes { release { ... } }.",
        location=Location(ctx.build.source_path),
        evidence="release { debuggable = true }",
        refs=(DOC_SHRINK,),
    )


@rule("build.minify")
def minify_disabled(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.build.minify_enabled is not False:
        return
    yield Finding(
        id="BLD-NO-MINIFY",
        title="R8 shrinking/obfuscation is off for release",
        severity=Severity.LOW,
        category=Category.SECURITY,
        why=(
            "Without R8 the shipped code keeps original class, method and field names, so "
            "reading your logic — including any client-side check — takes minutes."
        ),
        fix=(
            "Set isMinifyEnabled = true (and isShrinkResources = true) in the release build "
            "type, then test the release build once for reflection breakage."
        ),
        location=Location(ctx.build.source_path),
        evidence="release { isMinifyEnabled = false }",
        refs=(DOC_SHRINK,),
    )


@rule("build.min_sdk")
def very_old_min_sdk(ctx: ScanContext) -> Iterator[Finding]:
    min_sdk = ctx.build.min_sdk
    if min_sdk is None or min_sdk >= 21:
        return
    yield Finding(
        id="BLD-OLD-MINSDK",
        title=f"minSdk {min_sdk} keeps the app on unpatched Android versions",
        severity=Severity.LOW,
        category=Category.SECURITY,
        why=(
            "Below API 21 you inherit an old TLS stack and platform bugs that no longer receive "
            "fixes, and modern security config is unavailable."
        ),
        fix="Raise minSdk to 21 or higher unless a measured share of your users is below it.",
        location=Location(ctx.build.source_path),
        evidence=f"minSdk = {min_sdk}",
        refs=(DOC_SIGNING,),
    )
