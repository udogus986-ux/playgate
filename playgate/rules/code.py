"""Source-pattern rules for Kotlin/Java, C# (Unity) and GDScript."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from ..models import Category, Finding, Location, ScanContext, Severity
from .base import rule

CODE_SUFFIXES = (".kt", ".java", ".cs", ".gd", ".js", ".ts")

DOC_WEBVIEW = "https://developer.android.com/privacy-and-security/risks/insecure-webview"
DOC_CRYPTO = "https://developer.android.com/privacy-and-security/cryptography"
DOC_STORAGE = "https://developer.android.com/privacy-and-security/security-tips#StoringData"
DOC_NETWORK = "https://developer.android.com/privacy-and-security/security-ssl"

COMMENT_PREFIXES = ("//", "#", "*", "/*", "'''", '"""')


@dataclass(frozen=True)
class CodePattern:
    id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    why: str
    fix: str
    refs: tuple[str, ...] = ()
    suffixes: tuple[str, ...] = CODE_SUFFIXES


PATTERNS: list[CodePattern] = [
    CodePattern(
        id="CODE-WEBVIEW-JSBRIDGE",
        title="WebView exposes a native object to page JavaScript",
        severity=Severity.HIGH,
        pattern=re.compile(r"\baddJavascriptInterface\s*\("),
        why=(
            "Any JavaScript the WebView loads can call the exposed object's @JavascriptInterface "
            "methods. If the page can be swapped — a redirect, an injected ad, plain http — that "
            "is remote code calling into your app."
        ),
        fix=(
            "Drop the bridge if you can. If you need it, load only bundled local content, pin the "
            "allowed origins, and expose the smallest possible surface."
        ),
        refs=(DOC_WEBVIEW,),
    ),
    CodePattern(
        id="CODE-WEBVIEW-FILEACCESS",
        title="WebView allows file:// access to other origins",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\bset(?:AllowFileAccessFromFileURLs|AllowUniversalAccessFromFileURLs)\s*\(\s*true\s*\)"
        ),
        why=(
            "A page loaded from file:// can read other local files, including your app's private "
            "storage, and ship them off-device."
        ),
        fix="Set both to false. They default to false on API 16+; this call re-enables the risk.",
        refs=(DOC_WEBVIEW,),
    ),
    CodePattern(
        id="CODE-WEBVIEW-DEBUG",
        title="WebView contents debugging is enabled",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)"),
        why="Anyone with adb access can inspect and script the WebView in a release build.",
        fix="Guard the call with a debug-build check (e.g. BuildConfig.DEBUG).",
        refs=(DOC_WEBVIEW,),
    ),
    CodePattern(
        id="CODE-TLS-TRUSTALL",
        title="TLS certificate validation is disabled",
        severity=Severity.CRITICAL,
        # Only names that exist for the sole purpose of bypassing validation.
        pattern=re.compile(
            r"(?i)\b(ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts?|TrustAllX509TrustManager"
            r"|NullHostNameVerifier|NoopHostnameVerifier"
            r"|ServerCertificateValidationCallback\s*\+?=\s*[^;\n]*true)\b"
        ),
        why=(
            "With validation off, anyone on the network can present their own certificate and "
            "read or rewrite every request the app makes, https included."
        ),
        fix=(
            "Remove the custom TrustManager/HostnameVerifier. For a self-signed dev server, add "
            "the certificate to a debug-only network security config instead."
        ),
        refs=(DOC_NETWORK,),
    ),
    CodePattern(
        id="CODE-TLS-VERIFY-TRUE",
        title="Hostname verifier appears to accept every host",
        severity=Severity.HIGH,
        # Narrower than it looks: requires the HostnameVerifier contract shape.
        pattern=re.compile(
            r"(?is)HostnameVerifier[^{;]{0,200}\{[^}]{0,200}?\breturn\s+true\b"
        ),
        why=(
            "A verify() that always returns true accepts a certificate issued for any hostname, "
            "which removes the guarantee that you are talking to your own server."
        ),
        fix=(
            "Delete the custom verifier and let the platform check the hostname. If a dev host "
            "needs an exception, scope it in a debug-only network security config."
        ),
        refs=(DOC_NETWORK,),
    ),
    CodePattern(
        id="CODE-WORLD-PERMS",
        title="File written with world-readable/writable mode",
        severity=Severity.HIGH,
        pattern=re.compile(r"\bMODE_WORLD_(?:READABLE|WRITEABLE|WRITABLE)\b"),
        why="Every other app on the device can read — or overwrite — this file.",
        fix="Use MODE_PRIVATE, and share data through a FileProvider with explicit grants.",
        refs=(DOC_STORAGE,),
    ),
    CodePattern(
        id="CODE-WEAK-CIPHER",
        title="Weak or ECB-mode cipher in use",
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"""(?i)(?:Cipher\.getInstance|CreateEncryptor|new\s+DESCryptoServiceProvider)"""
            r"""\s*\(\s*["'](?:[^"']*(?:/ECB/|\bDES\b|\bDESede\b|\bRC[24]\b|\bBlowfish\b)[^"']*)["']"""
        ),
        why=(
            "ECB leaks structure — identical plaintext blocks produce identical ciphertext — and "
            "DES/RC4 are broken outright."
        ),
        fix="Use AES-256-GCM with a random 12-byte IV per message, keys held in the Android Keystore.",
        refs=(DOC_CRYPTO,),
    ),
    CodePattern(
        id="CODE-WEAK-HASH",
        title="MD5 or SHA-1 used for hashing",
        severity=Severity.LOW,
        pattern=re.compile(r"""(?i)MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']"""),
        why=(
            "Both are collision-broken. Harmless for a cache key, unacceptable for signatures, "
            "integrity checks or password handling."
        ),
        fix="Use SHA-256 for integrity; for passwords use Argon2id, scrypt or bcrypt server-side.",
        refs=(DOC_CRYPTO,),
    ),
    CodePattern(
        id="CODE-LOG-SECRET",
        title="Credential-shaped value written to the log",
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"""(?i)\b(?:Log\.[vdiwe]|Debug\.Log|println|print|Console\.WriteLine)\s*\("""
            r"""[^)\n]{0,120}\b(token|password|secret|apikey|api_key|auth|session|jwt)\b"""
        ),
        why=(
            "Logcat is readable by adb and by crash/analytics SDKs. Tokens printed here leak to "
            "places you did not intend."
        ),
        fix="Remove the log line, or log only a short non-reversible fingerprint of the value.",
        refs=(DOC_STORAGE,),
    ),
    CodePattern(
        id="CODE-HTTP-URL",
        title="Plain http:// endpoint in code",
        severity=Severity.LOW,
        pattern=re.compile(
            r"""["']http://(?!"""
            r"""localhost|127\.0\.0\.1|10\.0\.2\.2"""              # loopback + emulator host
            r"""|10\.|192\.168\.|169\.254\."""                    # private / link-local
            r"""|172\.(?:1[6-9]|2\d|3[01])\."""                   # 172.16.0.0/12
            r"""|schemas\.|www\.w3\.)"""                          # XML namespaces, not endpoints
        ),
        why="Requests to this host are readable and modifiable on any shared network.",
        fix="Move the endpoint to https. If it is a local dev server, keep it out of release builds.",
        refs=(DOC_NETWORK,),
    ),
    CodePattern(
        id="CODE-EXTERNAL-STORAGE",
        title="App data written to shared external storage",
        severity=Severity.LOW,
        pattern=re.compile(
            r"\b(?:getExternalStorageDirectory|Environment\.getExternalStoragePublicDirectory)\s*\("
        ),
        why=(
            "Shared storage is world-readable and survives uninstall. Anything sensitive placed "
            "there is available to other apps."
        ),
        fix="Use getFilesDir()/getExternalFilesDir() for app-owned data, or MediaStore for user media.",
        refs=(DOC_STORAGE,),
    ),
]


def _is_comment(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(COMMENT_PREFIXES)


@rule("code.patterns")
def code_patterns(ctx: ScanContext) -> Iterator[Finding]:
    for f in ctx.files:
        if f.relpath.endswith("(extracted strings)"):
            continue
        suffix = f.path.suffix.lower()
        for spec in PATTERNS:
            if suffix not in spec.suffixes:
                continue
            seen_lines: set[int] = set()
            for match in spec.pattern.finditer(f.text):
                line_no = f.line_of(match.start())
                if line_no in seen_lines:
                    continue
                line_text = f.lines[line_no - 1] if line_no <= len(f.lines) else ""
                if _is_comment(line_text):
                    continue
                seen_lines.add(line_no)
                yield Finding(
                    id=spec.id,
                    title=spec.title,
                    severity=spec.severity,
                    category=Category.SECURITY,
                    why=spec.why,
                    fix=spec.fix,
                    location=Location(f.relpath, line_no),
                    evidence=line_text.strip()[:200],
                    refs=spec.refs,
                )
