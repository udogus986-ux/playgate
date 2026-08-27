"""Unity-specific rules, aimed at shipped mobile games."""

from __future__ import annotations

import re
from typing import Iterator

from ..models import Category, Finding, Location, ProjectKind, ScanContext, Severity
from .base import rule

DOC_IL2CPP = "https://docs.unity3d.com/Manual/IL2CPP.html"
DOC_IAP = "https://docs.unity3d.com/Packages/com.unity.purchasing@4.12/manual/BackendReceiptValidation.html"
DOC_64BIT = "https://developer.android.com/google/play/requirements/64-bit"

# PlayerPrefs holding anything that looks like currency or entitlement.
PLAYERPREFS_ECONOMY = re.compile(
    r"""(?ix)PlayerPrefs\.(?:Set|Get)(?:Int|Float|String)\s*\(\s*["']
        ([^"']*(?:coin|gem|gold|cash|money|credit|premium|vip|purchase|owned|unlock
         |nolimit|noads|no_ads|remove_?ads|score|level|diamond|token)[^"']*)["']"""
)

IAP_VALIDATION_HINTS = (
    "CrossPlatformValidator",
    "ValidateReceipt",
    "GooglePlayReceipt",
    "AppleReceipt",
    "receipt_validation",
)


@rule("unity.scripting_backend")
def scripting_backend(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.kind is not ProjectKind.UNITY:
        return
    backend = ctx.build.scripting_backend
    if backend is None or backend.upper() == "IL2CPP":
        return
    yield Finding(
        id="UNI-MONO-BACKEND",
        title="Android build uses the Mono scripting backend",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        why=(
            "Mono ships your game logic as .NET assemblies inside the APK. They decompile back "
            "to near-original C# in seconds, and can be edited and repacked — which is how "
            "modded builds of paid or ad-supported games appear."
        ),
        fix=(
            "Switch Player Settings > Configuration > Scripting Backend to IL2CPP for Android. "
            "It is also required for the 64-bit ARM64 build Play expects."
        ),
        location=Location(ctx.build.source_path),
        evidence="scriptingBackend: Android = Mono2x",
        refs=(DOC_IL2CPP, DOC_64BIT),
    )


@rule("unity.playerprefs_economy")
def playerprefs_economy(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.kind is not ProjectKind.UNITY:
        return
    reported: set[str] = set()
    for f in ctx.files_with_suffix(".cs"):
        for match in PLAYERPREFS_ECONOMY.finditer(f.text):
            key = match.group(1)
            if key in reported:
                continue
            reported.add(key)
            yield Finding(
                id="UNI-PLAYERPREFS-ECONOMY",
                title=f"Game economy value stored in PlayerPrefs: '{key}'",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                why=(
                    "PlayerPrefs is a plain XML file in shared_prefs on Android. Any rooted "
                    "device — or any of the widely available save editors — can set this to any "
                    "value. If purchases, ad removal or progression depend on it, they are free."
                ),
                fix=(
                    "Treat the client as untrusted: keep entitlement and currency on a server "
                    "you control, or at minimum sign the local value with a key derived at "
                    "runtime and re-verify on load. Never grant IAP entitlement from PlayerPrefs alone."
                ),
                location=Location(f.relpath, f.line_of(match.start())),
                evidence=match.group(0).strip()[:160],
                refs=(DOC_IAP,),
            )


@rule("unity.iap_validation")
def iap_without_validation(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.kind is not ProjectKind.UNITY:
        return
    purchase_files = [
        f for f in ctx.files_with_suffix(".cs")
        if "IStoreListener" in f.text or "ProcessPurchase" in f.text
    ]
    if not purchase_files:
        return
    joined = "\n".join(f.text for f in ctx.files_with_suffix(".cs"))
    if any(hint in joined for hint in IAP_VALIDATION_HINTS):
        return
    first = purchase_files[0]
    yield Finding(
        id="UNI-IAP-NOVALIDATION",
        title="In-app purchases are processed without any receipt validation",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        why=(
            "ProcessPurchase is reached, but nothing in the project validates the receipt. "
            "Tools that fake the billing response are common on Android, so entitlement can be "
            "granted without a real purchase."
        ),
        fix=(
            "Validate server-side against the Google Play Developer API. If that is out of "
            "scope for now, at least add Unity's CrossPlatformValidator as a first barrier — "
            "but treat local validation as a speed bump, not a control."
        ),
        location=Location(first.relpath),
        evidence="ProcessPurchase implemented; no validator found in project",
        refs=(DOC_IAP,),
    )


@rule("unity.architectures")
def target_architectures(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.kind is not ProjectKind.UNITY:
        return
    for f in ctx.files_named("ProjectSettings.asset"):
        match = re.search(r"AndroidTargetArchitectures:\s*(\d+)", f.text)
        if not match:
            continue
        mask = int(match.group(1))
        # Bit 1 = ARMv7, bit 2 = ARM64, bit 4 = x86, bit 8 = x86_64.
        if mask & 2:
            continue
        yield Finding(
            id="UNI-NO-ARM64",
            title="Android build does not include an ARM64 architecture",
            severity=Severity.HIGH,
            category=Category.POLICY,
            why=(
                "Google Play requires apps with native code to provide 64-bit versions. A build "
                "without ARM64 is refused at upload."
            ),
            fix=(
                "Enable ARM64 in Player Settings > Target Architectures. It requires the IL2CPP "
                "scripting backend."
            ),
            location=Location(f.relpath, f.line_of(match.start())),
            evidence=match.group(0),
            refs=(DOC_64BIT,),
            rejection_weight=30,
        )
