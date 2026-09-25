"""Deeper Android platform checks.

Patterns that a single-line regex over a manifest attribute misses: how
PendingIntents are built, what a FileProvider actually shares, whether https
deep links are verified, where tokens are persisted, and whether biometric auth
is bound to a key.
"""

from __future__ import annotations

import re
from typing import Iterator
from xml.etree import ElementTree as ET

from ..models import Category, Finding, Location, ScanContext, Severity, SourceFile
from .base import rule

DOC_PI = "https://developer.android.com/privacy-and-security/risks/pending-intent"
DOC_FP = "https://developer.android.com/privacy-and-security/risks/file-providers"
DOC_APPLINKS = "https://developer.android.com/training/app-links/verify-android-applinks"
DOC_STORAGE = "https://developer.android.com/privacy-and-security/security-tips#StoringData"
DOC_BIOMETRIC = "https://developer.android.com/privacy-and-security/risks/insecure-biometric-authentication"
DOC_BROADCAST = "https://developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver"

_A = "{http://schemas.android.com/apk/res/android}"
_JVM = (".kt", ".java")
_COMMENT = ("//", "*", "/*")


def _code_files(ctx: ScanContext) -> Iterator[SourceFile]:
    for f in ctx.files:
        if f.path.suffix.lower() in _JVM and not f.relpath.endswith("(extracted strings)"):
            yield f


def _call_args(text: str, open_paren: int, limit: int = 600) -> str:
    """Text between ``(`` at ``open_paren`` and its matching ``)``, capped."""
    depth = 0
    end = min(len(text), open_paren + limit)
    for i in range(open_paren, end):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i]
    return text[open_paren + 1 : end]


def _is_comment(f: SourceFile, index: int) -> bool:
    line_no = f.line_of(index)
    line = f.lines[line_no - 1] if line_no <= len(f.lines) else ""
    return line.strip().startswith(_COMMENT)


# --------------------------------------------------------------------------

_PI_CALL = re.compile(r"\bPendingIntent\s*\.\s*get(?:Activity|Activities|Broadcast|Service|ForegroundService)\s*\(")


@rule("android.pending_intent")
def pending_intent_mutability(ctx: ScanContext) -> Iterator[Finding]:
    for f in _code_files(ctx):
        for m in _PI_CALL.finditer(f.text):
            if _is_comment(f, m.start()):
                continue
            args = _call_args(f.text, m.end() - 1)
            if "FLAG_IMMUTABLE" in args or "FLAG_MUTABLE" in args:
                continue
            yield Finding(
                id="AND-PENDINGINTENT-MUTABLE",
                title="PendingIntent created without FLAG_IMMUTABLE",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                why=(
                    "Without an explicit mutability flag the PendingIntent is mutable. Another app "
                    "that receives it can fill in the empty fields and act with your app's "
                    "identity and permissions. Targeting API 31+ it also crashes at runtime."
                ),
                fix=(
                    "Pass PendingIntent.FLAG_IMMUTABLE (combined with your other flags). Use "
                    "FLAG_MUTABLE only when a system API needs to fill in the intent, and then "
                    "make the base intent explicit."
                ),
                location=Location(f.relpath, f.line_of(m.start())),
                evidence=f.lines[f.line_of(m.start()) - 1].strip()[:160],
                refs=(DOC_PI,),
            )


@rule("android.file_provider")
def file_provider_paths(ctx: ScanContext) -> Iterator[Finding]:
    root_path = re.compile(r"<root-path\b[^>]*>")
    broad = re.compile(r"<(?:external|files|cache|external-files)-path\b[^>]*\bpath\s*=\s*\"(?:\.|/)?\"[^>]*>")
    for f in ctx.files:
        rel = f.relpath.replace("\\", "/")
        if f.path.suffix.lower() != ".xml" or "/res/xml/" not in "/" + rel:
            continue
        if "<paths" not in f.text:
            continue
        for m in root_path.finditer(f.text):
            yield Finding(
                id="AND-FILEPROVIDER-ROOT",
                title="FileProvider shares the device root (<root-path>)",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                why=(
                    "A <root-path> entry lets the provider hand out URIs for any file the app can "
                    "read — including its private databases and shared_prefs — to whichever app "
                    "is granted the URI."
                ),
                fix="Remove <root-path>. Share only a dedicated subdirectory via <files-path> or <cache-path>.",
                location=Location(f.relpath, f.line_of(m.start())),
                evidence=m.group(0)[:120],
                refs=(DOC_FP,),
            )
        for m in broad.finditer(f.text):
            yield Finding(
                id="AND-FILEPROVIDER-BROAD",
                title="FileProvider shares a whole storage root",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                why=(
                    "path=\".\" (or empty) exposes the entire directory tree of that storage area "
                    "rather than the one folder the feature needs."
                ),
                fix="Point path= at a dedicated subdirectory such as \"shared/\".",
                location=Location(f.relpath, f.line_of(m.start())),
                evidence=m.group(0)[:120],
                refs=(DOC_FP,),
            )


@rule("android.deep_links")
def deep_link_verification(ctx: ScanContext) -> Iterator[Finding]:
    for manifest in ctx.manifests:
        if not manifest.raw:
            continue
        try:
            root = ET.fromstring(manifest.raw)
        except ET.ParseError:
            continue
        app = root.find("application")
        if app is None:
            continue
        for kind in ("activity", "activity-alias"):
            for node in app.findall(kind):
                name = node.get(f"{_A}name") or "<unnamed>"
                for flt in node.findall("intent-filter"):
                    actions = {a.get(f"{_A}name") for a in flt.findall("action")}
                    cats = {c.get(f"{_A}name") for c in flt.findall("category")}
                    schemes = {d.get(f"{_A}scheme") for d in flt.findall("data")}
                    if "android.intent.action.VIEW" not in actions:
                        continue
                    if "android.intent.category.BROWSABLE" not in cats:
                        continue
                    if not schemes & {"http", "https"}:
                        continue
                    if (flt.get(f"{_A}autoVerify") or "").lower() == "true":
                        continue
                    hosts = sorted({d.get(f"{_A}host") for d in flt.findall("data") if d.get(f"{_A}host")})
                    yield Finding(
                        id="AND-DEEPLINK-NO-AUTOVERIFY",
                        title=f"Web deep link on '{name}' is not verified (autoVerify missing)",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        why=(
                            "Without android:autoVerify=\"true\" and a matching assetlinks.json, "
                            "any app can declare the same https links and be offered to the user "
                            "— or chosen — instead of yours, receiving login and reset links."
                        ),
                        fix=(
                            "Add android:autoVerify=\"true\" to the intent-filter and publish "
                            "/.well-known/assetlinks.json on "
                            + (", ".join(hosts) if hosts else "each host")
                            + " with your signing-certificate fingerprint."
                        ),
                        location=Location(manifest.source_path),
                        evidence=f"<intent-filter> VIEW+BROWSABLE https host={','.join(hosts) or '*'}",
                        refs=(DOC_APPLINKS,),
                    )


_PREFS_PUT = re.compile(
    r"""\bput(?:String|StringSet)\s*\(\s*["']([^"']*(?:token|password|passwd|secret|session|jwt|api_?key|refresh)[^"']*)["']""",
    re.IGNORECASE,
)


@rule("android.prefs_plaintext")
def plaintext_preferences(ctx: ScanContext) -> Iterator[Finding]:
    for f in _code_files(ctx):
        if "SharedPreferences" not in f.text and "getSharedPreferences" not in f.text and ".edit()" not in f.text:
            continue
        if "EncryptedSharedPreferences" in f.text:
            continue
        seen: set[str] = set()
        for m in _PREFS_PUT.finditer(f.text):
            key = m.group(1)
            if key in seen or _is_comment(f, m.start()):
                continue
            seen.add(key)
            yield Finding(
                id="CODE-PREFS-PLAINTEXT",
                title=f"Credential stored in plain SharedPreferences: '{key}'",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                why=(
                    "SharedPreferences is an unencrypted XML file. It is readable on rooted "
                    "devices, included in backups unless excluded, and trivially extracted from "
                    "a debug build."
                ),
                fix=(
                    "Keep the value in the Android Keystore, or wrap it with a Keystore-backed "
                    "key (e.g. Tink / EncryptedSharedPreferences), and exclude the file from backup."
                ),
                location=Location(f.relpath, f.line_of(m.start())),
                evidence=m.group(0)[:120],
                refs=(DOC_STORAGE,),
            )


_BIO_AUTH_NO_CRYPTO = re.compile(r"\.authenticate\s*\(\s*[\w.]+\s*\)")


@rule("android.biometric")
def biometric_without_crypto(ctx: ScanContext) -> Iterator[Finding]:
    for f in _code_files(ctx):
        if "BiometricPrompt" not in f.text or "CryptoObject" in f.text:
            continue
        for m in _BIO_AUTH_NO_CRYPTO.finditer(f.text):
            if _is_comment(f, m.start()):
                continue
            yield Finding(
                id="CODE-BIOMETRIC-NO-CRYPTO",
                title="Biometric authentication is not bound to a cryptographic key",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                why=(
                    "BiometricPrompt.authenticate(promptInfo) without a CryptoObject only raises a "
                    "callback. On a rooted or instrumented device the success callback can be "
                    "invoked directly, skipping the fingerprint entirely."
                ),
                fix=(
                    "Generate a Keystore key with setUserAuthenticationRequired(true), pass a "
                    "CryptoObject wrapping a Cipher using it, and only unlock data by decrypting "
                    "with that cipher in onAuthenticationSucceeded."
                ),
                location=Location(f.relpath, f.line_of(m.start())),
                evidence=f.lines[f.line_of(m.start()) - 1].strip()[:160],
                refs=(DOC_BIOMETRIC,),
            )
            break


_SEND_BROADCAST_1 = re.compile(r"\bsendBroadcast\s*\(\s*[\w.]+\s*\)")
_SENSITIVE_EXTRA = re.compile(
    r"""putExtra\s*\(\s*["'][^"']*(?:token|password|secret|session|jwt|otp|auth)[^"']*["']""", re.IGNORECASE
)


@rule("android.implicit_broadcast")
def sensitive_implicit_broadcast(ctx: ScanContext) -> Iterator[Finding]:
    for f in _code_files(ctx):
        if "setPackage(" in f.text or "LocalBroadcastManager" in f.text:
            continue
        if not _SENSITIVE_EXTRA.search(f.text):
            continue
        m = _SEND_BROADCAST_1.search(f.text)
        if not m or _is_comment(f, m.start()):
            continue
        yield Finding(
            id="AND-BROADCAST-SENSITIVE",
            title="Sensitive extra sent in a broadcast any app can receive",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            why=(
                "sendBroadcast(intent) with no receiver permission and no target package is "
                "delivered to every app that registers for the action — including the token or "
                "password placed in its extras."
            ),
            fix=(
                "Call intent.setPackage(packageName) to keep it in-app, or pass a signature-level "
                "receiverPermission to sendBroadcast."
            ),
            location=Location(f.relpath, f.line_of(m.start())),
            evidence=m.group(0),
            refs=(DOC_BROADCAST,),
        )
