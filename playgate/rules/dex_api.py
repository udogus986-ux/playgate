"""API-usage checks for compiled packages, from the DEX method table.

Source rules can't run on an .apk; these can. They report *that* the code calls
a risky API — they cannot see the arguments — so the wording asks the reviewer
to confirm where the argument matters. Only third-party-reachable, high-signal
APIs are listed; a call that merely exists in a bundled SDK is still reported,
because it ships.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from ..dex import WEAK_CIPHER, WEAK_HASH
from ..models import Category, Finding, Location, ProjectKind, ScanContext, Severity
from .base import rule

DOC_WEBVIEW = "https://developer.android.com/privacy-and-security/risks/insecure-webview"
DOC_DCL = "https://developer.android.com/privacy-and-security/risks/dynamic-code-loading"
DOC_TLS = "https://developer.android.com/privacy-and-security/security-ssl"
DOC_CRYPTO = "https://developer.android.com/privacy-and-security/cryptography"
DOC_ADID = "https://support.google.com/googleplay/android-developer/answer/6048248"


@dataclass(frozen=True)
class ApiRule:
    id: str
    refs: tuple[str, ...]
    title: str
    severity: Severity
    why: str
    fix: str
    doc: str
    category: Category = Category.SECURITY


API_RULES = [
    ApiRule(
        "DEX-WEBVIEW-JSBRIDGE", ("Landroid/webkit/WebView;->addJavascriptInterface",),
        "Compiled code exposes a native object to WebView JavaScript", Severity.HIGH,
        "addJavascriptInterface is called. Any page the WebView loads can call the exposed "
        "object's methods; with remote or injectable content that is remote code reaching the app.",
        "Confirm only bundled or allowlisted https content is loaded where the bridge is attached, "
        "and minimise the exposed surface.",
        DOC_WEBVIEW,
    ),
    ApiRule(
        "DEX-WEBVIEW-FILEACCESS",
        ("Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs",
         "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs"),
        "Compiled code changes WebView file:// origin access", Severity.MEDIUM,
        "The app toggles file-URL cross-origin access. If it is set to true, a page loaded from "
        "file:// can read other local files and send them off-device.",
        "Confirm the argument is false (the default on API 16+) or remove the call.",
        DOC_WEBVIEW,
    ),
    ApiRule(
        "DEX-WEBVIEW-DEBUG", ("Landroid/webkit/WebView;->setWebContentsDebuggingEnabled",),
        "Compiled code toggles WebView remote debugging", Severity.LOW,
        "setWebContentsDebuggingEnabled is called. If true in a release build, anyone with adb can "
        "inspect and script the WebView.",
        "Guard the call with a debug-build check.",
        DOC_WEBVIEW,
    ),
    ApiRule(
        "DEX-DYNAMIC-CODE",
        ("Ldalvik/system/DexClassLoader;-><init>", "Ldalvik/system/PathClassLoader;-><init>",
         "Ldalvik/system/InMemoryDexClassLoader;-><init>"),
        "Code is loaded dynamically at runtime", Severity.MEDIUM,
        "The app constructs a class loader for code that is not in the APK. Code fetched or "
        "written at runtime bypasses Play review, and if it comes from writable storage another "
        "app can replace it.",
        "Ship code in the APK or use Play Feature Delivery. If loading is unavoidable, load only "
        "from app-private storage and verify a signature before loading.",
        DOC_DCL,
    ),
    ApiRule(
        "DEX-GLOBAL-HOSTNAME-VERIFIER",
        ("Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier",
         "Ljavax/net/ssl/HttpsURLConnection;->setDefaultSSLSocketFactory"),
        "Process-wide TLS verification is replaced", Severity.MEDIUM,
        "The app installs a default hostname verifier or socket factory for every "
        "HttpsURLConnection. These are the usual places certificate checks get disabled.",
        "Confirm the replacement still validates certificates and hostnames; prefer a network "
        "security config over code.",
        DOC_TLS,
    ),
    ApiRule(
        "DEX-ADID-READ",
        ("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;->getAdvertisingIdInfo",),
        "Compiled code reads the advertising ID", Severity.INFO,
        "The advertising ID is read (by the app or a bundled SDK). It must be declared in Data "
        "Safety, requires the AD_ID permission on API 33+, and is not allowed in apps for children.",
        "Declare 'Advertising ID' in Data Safety, or remove the SDK that reads it.",
        DOC_ADID, Category.POLICY,
    ),
]


@rule("dex.api_usage")
def dex_api_usage(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.kind is not ProjectKind.APK or not ctx.api_refs:
        return
    for api in API_RULES:
        hits = [ref for ref in api.refs if ref in ctx.api_refs]
        if not hits:
            continue
        dex_file = ctx.api_refs[hits[0]]
        yield Finding(
            id=api.id,
            title=api.title,
            severity=api.severity,
            category=api.category,
            why=api.why,
            fix=api.fix,
            location=Location(dex_file),
            evidence=", ".join(hits),
            refs=(api.doc,),
        )


@rule("dex.crypto")
def dex_weak_crypto(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.kind is not ProjectKind.APK or not ctx.api_refs:
        return
    cipher_ref = "Ljavax/crypto/Cipher;->getInstance"
    digest_ref = "Ljava/security/MessageDigest;->getInstance"
    ciphers = sorted(s for s in ctx.dex_crypto if WEAK_CIPHER.fullmatch(s))
    digests = sorted(s for s in ctx.dex_crypto if WEAK_HASH.fullmatch(s))
    if cipher_ref in ctx.api_refs and ciphers:
        yield Finding(
            id="DEX-WEAK-CIPHER",
            title="Compiled code uses a weak or ECB cipher transformation",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            why=(
                f"Cipher.getInstance is called and {', '.join(repr(c) for c in ciphers[:4])} ships in "
                "the DEX. A bare \"AES\" defaults to ECB, which leaks plaintext structure; DES/RC4 "
                "are broken."
            ),
            fix="Use \"AES/GCM/NoPadding\" with a random 12-byte IV per message and a Keystore key.",
            location=Location(ctx.api_refs[cipher_ref]),
            evidence=", ".join(ciphers[:4]),
            refs=(DOC_CRYPTO,),
        )
    if digest_ref in ctx.api_refs and digests:
        yield Finding(
            id="DEX-WEAK-HASH",
            title="Compiled code uses MD5 or SHA-1",
            severity=Severity.LOW,
            category=Category.SECURITY,
            why=(
                f"MessageDigest.getInstance is called and {', '.join(repr(d) for d in digests)} ships in "
                "the DEX. Both are collision-broken — fine for a cache key, not for integrity or passwords."
            ),
            fix="Use SHA-256 for integrity checks; Argon2id/scrypt/bcrypt server-side for passwords.",
            location=Location(ctx.api_refs[digest_ref]),
            evidence=", ".join(digests),
            refs=(DOC_CRYPTO,),
        )
