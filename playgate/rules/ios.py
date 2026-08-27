"""iOS / Apple App Store checks.

Runs whenever iOS artifacts are present — a native Xcode project, or the iOS
side of a Flutter / React Native app — regardless of the reported project kind.
Covers the App Store review issues that most reliably bounce a submission:
App Transport Security, missing/empty permission purpose strings, the privacy
manifest Apple now requires, deprecated UIWebView, App Tracking Transparency,
and the export-compliance declaration.

Info.plist is read with targeted regexes rather than a plist parser, so a
partial or oddly-encoded plist degrades gracefully instead of raising.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from ..models import Category, Finding, Location, ScanContext, Severity, SourceFile
from .base import rule

DOC_ATS = "https://developer.apple.com/documentation/security/preventing-insecure-network-connections"
DOC_PRIVACY_MANIFEST = "https://developer.apple.com/documentation/bundleresources/privacy-manifest-files"
DOC_ATT = "https://developer.apple.com/documentation/apptrackingtransparency"
DOC_UIWEBVIEW = "https://developer.apple.com/documentation/uikit/uiwebview"
DOC_ENCRYPTION = "https://developer.apple.com/documentation/security/complying-with-encryption-export-regulations"
DOC_PURPOSE = "https://developer.apple.com/documentation/bundleresources/information-property-list/protected-resources"

_USAGE_KEY = re.compile(r"<key>\s*(NS\w*UsageDescription)\s*</key>\s*<string>(.*?)</string>", re.DOTALL)
_ATS_ARBITRARY = re.compile(r"<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<(true)/>", re.IGNORECASE)
_HAS_KEY = lambda text, key: re.search(rf"<key>\s*{re.escape(key)}\s*</key>", text) is not None

_PLACEHOLDER_PURPOSE = re.compile(r"(?i)^(?:\s*|todo|tbd|xxx+|test|placeholder|\.\.\.|-)?\s*$")


@dataclass
class _IOS:
    present: bool = False
    info_plists: list[SourceFile] = None
    code: list[SourceFile] = None
    has_privacy_manifest: bool = False
    evidence: str | None = None


def _detect(ctx: ScanContext) -> _IOS:
    plists: list[SourceFile] = []
    code: list[SourceFile] = []
    has_manifest = False
    evidence = None
    for f in ctx.files:
        name = f.path.name.lower()
        suffix = f.path.suffix.lower()
        if name == "info.plist" and ("CFBundle" in f.text or "UsageDescription" in f.text
                                     or "NSAppTransportSecurity" in f.text):
            plists.append(f)
            evidence = evidence or f.relpath
        elif suffix == ".xcprivacy":
            has_manifest = True
            evidence = evidence or f.relpath
        elif suffix in {".swift", ".m", ".mm"}:
            code.append(f)
    present = bool(plists or has_manifest or (code and ctx.kind.value in {"ios", "flutter", "react-native"}))
    if present and evidence is None and code:
        evidence = code[0].relpath
    return _IOS(present=present, info_plists=plists, code=code,
                has_privacy_manifest=has_manifest, evidence=evidence)


@rule("ios.ats")
def app_transport_security(ctx: ScanContext) -> Iterator[Finding]:
    ios = _detect(ctx)
    if not ios.present:
        return
    for f in ios.info_plists:
        for match in _ATS_ARBITRARY.finditer(f.text):
            yield Finding(
                id="IOS-ATS-ARBITRARY",
                title="App Transport Security is disabled (NSAllowsArbitraryLoads)",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                why=(
                    "Turning off ATS lets the app make plain-HTTP connections app-wide, which can "
                    "be read and modified on any network. App Review also requires a written "
                    "justification for a blanket exception and rejects apps that cannot give one."
                ),
                fix=(
                    "Remove NSAllowsArbitraryLoads and serve everything over HTTPS with TLS 1.2+. "
                    "If one host genuinely needs an exception, scope it under "
                    "NSExceptionDomains for that domain only."
                ),
                location=Location(f.relpath, f.line_of(match.start())),
                evidence="NSAllowsArbitraryLoads = true",
                refs=(DOC_ATS,),
            )


@rule("ios.usage_descriptions")
def usage_descriptions(ctx: ScanContext) -> Iterator[Finding]:
    ios = _detect(ctx)
    if not ios.present:
        return
    for f in ios.info_plists:
        for match in _USAGE_KEY.finditer(f.text):
            key, purpose = match.group(1), match.group(2).strip()
            if _PLACEHOLDER_PURPOSE.match(purpose):
                yield Finding(
                    id="IOS-USAGE-DESC-EMPTY",
                    title=f"{key} has an empty or placeholder purpose string",
                    severity=Severity.HIGH,
                    category=Category.POLICY,
                    why=(
                        "Apple requires a specific, user-facing reason for every protected "
                        "resource. An empty or placeholder purpose string is a standard App Store "
                        "rejection, and at runtime the permission prompt shows nothing."
                    ),
                    fix=(
                        f"Write a concrete sentence for {key} explaining what the app does with "
                        "the data and why the user benefits."
                    ),
                    location=Location(f.relpath, f.line_of(match.start())),
                    evidence=f"{key} = \"{purpose[:40]}\"",
                    refs=(DOC_PURPOSE,),
                    rejection_weight=15,
                )


@rule("ios.privacy_manifest")
def privacy_manifest(ctx: ScanContext) -> Iterator[Finding]:
    ios = _detect(ctx)
    if not ios.present or ios.has_privacy_manifest:
        return
    yield Finding(
        id="IOS-PRIVACY-MANIFEST-MISSING",
        title="No PrivacyInfo.xcprivacy — Apple requires a privacy manifest",
        severity=Severity.HIGH,
        category=Category.POLICY,
        why=(
            "Since May 2024 App Store submissions must include a privacy manifest declaring data "
            "collection, tracking domains, and any 'required-reason' API use. Missing it — or "
            "using an SDK that needs one — triggers an automated rejection email (ITMS-91053 and "
            "related)."
        ),
        fix=(
            "Add a PrivacyInfo.xcprivacy to the app target (and check that your third-party SDKs "
            "ship theirs). Declare collected data types, NSPrivacyTracking, and the reason codes "
            "for any required-reason API you call."
        ),
        location=Location(ios.evidence),
        evidence="no *.xcprivacy in the project",
        refs=(DOC_PRIVACY_MANIFEST,),
        rejection_weight=25,
    )


@rule("ios.uiwebview")
def deprecated_uiwebview(ctx: ScanContext) -> Iterator[Finding]:
    ios = _detect(ctx)
    if not ios.present:
        return
    pattern = re.compile(r"\bUIWebView\b")
    for f in list(ios.code) + list(ios.info_plists):
        for match in pattern.finditer(f.text):
            line = f.lines[f.line_of(match.start()) - 1] if f.line_of(match.start()) <= len(f.lines) else ""
            if line.strip().startswith(("//", "*", "/*")):
                continue
            yield Finding(
                id="IOS-UIWEBVIEW",
                title="Deprecated UIWebView is referenced",
                severity=Severity.HIGH,
                category=Category.POLICY,
                why=(
                    "Apple removed UIWebView and rejects new apps and updates that reference it "
                    "(ITMS-90809), including when it is pulled in by an old SDK."
                ),
                fix="Migrate to WKWebView, and update or remove any SDK that still links UIWebView.",
                location=Location(f.relpath, f.line_of(match.start())),
                evidence=line.strip()[:120] or "UIWebView",
                refs=(DOC_UIWEBVIEW,),
                rejection_weight=20,
            )
            break  # one per file is enough


@rule("ios.tracking")
def app_tracking_transparency(ctx: ScanContext) -> Iterator[Finding]:
    ios = _detect(ctx)
    if not ios.present:
        return
    idfa = re.compile(r"\b(ASIdentifierManager|advertisingIdentifier|ATTrackingManager)\b")
    uses_idfa_at = None
    for f in ios.code:
        m = idfa.search(f.text)
        if m:
            uses_idfa_at = Location(f.relpath, f.line_of(m.start()))
            break
    if uses_idfa_at is None:
        return
    has_att_key = any(_HAS_KEY(f.text, "NSUserTrackingUsageDescription") for f in ios.info_plists)
    if has_att_key:
        return
    yield Finding(
        id="IOS-IDFA-NO-ATT",
        title="Advertising identifier is used without an App Tracking Transparency prompt",
        severity=Severity.HIGH,
        category=Category.POLICY,
        why=(
            "Accessing the IDFA or tracking users requires the ATT prompt and an "
            "NSUserTrackingUsageDescription string. Reading the IDFA without it returns zeros and, "
            "when detected in review, is rejected under App Store guideline 5.1.2."
        ),
        fix=(
            "Add NSUserTrackingUsageDescription to Info.plist and call "
            "ATTrackingManager.requestTrackingAuthorization before touching the IDFA — or remove "
            "the tracking SDK if you do not need it."
        ),
        location=uses_idfa_at,
        evidence="IDFA/tracking API used; NSUserTrackingUsageDescription missing",
        refs=(DOC_ATT,),
        rejection_weight=20,
    )


@rule("ios.encryption_export")
def encryption_export(ctx: ScanContext) -> Iterator[Finding]:
    ios = _detect(ctx)
    if not ios.present or not ios.info_plists:
        return
    if any(_HAS_KEY(f.text, "ITSAppUsesNonExemptEncryption") for f in ios.info_plists):
        return
    yield Finding(
        id="IOS-ENCRYPTION-EXPORT",
        title="Export-compliance key ITSAppUsesNonExemptEncryption is not set",
        severity=Severity.LOW,
        category=Category.POLICY,
        why=(
            "Without ITSAppUsesNonExemptEncryption, every submission stops on the encryption "
            "export-compliance question in App Store Connect. Most apps only use exempt "
            "encryption (HTTPS) and can declare so up front to avoid the manual step."
        ),
        fix=(
            "Add <key>ITSAppUsesNonExemptEncryption</key><false/> if you only use standard "
            "HTTPS/exempt encryption; otherwise set it true and attach the required documentation."
        ),
        location=Location(ios.info_plists[0].relpath),
        evidence="ITSAppUsesNonExemptEncryption absent",
        refs=(DOC_ENCRYPTION,),
        rejection_weight=5,
    )
