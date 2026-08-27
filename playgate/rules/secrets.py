"""Credential and key material detection."""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..models import Category, Finding, Location, ScanContext, Severity
from .base import rule

DOC_KEYS = "https://developer.android.com/privacy-and-security/security-tips#Credentials"
DOC_API_RESTRICT = "https://cloud.google.com/docs/authentication/api-keys#securing"

_SECRET_WHY = (
    "Anything compiled into an APK is readable — unzip it and the string is "
    "there. Treat this credential as already public."
)
_SECRET_FIX = (
    "Rotate the credential now, then move the call behind a server you control "
    "so the app never holds it. Obfuscation does not help here."
)


@dataclass(frozen=True)
class SecretPattern:
    id: str
    label: str
    pattern: re.Pattern[str]
    severity: Severity
    why: str = _SECRET_WHY
    fix: str = _SECRET_FIX


# Patterns that identify a specific provider. A hit here is nearly always real.
STRONG_PATTERNS: list[SecretPattern] = [
    SecretPattern("SEC-GOOGLE-KEY", "Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), Severity.HIGH),
    SecretPattern("SEC-AWS-KEY", "AWS access key id",
                  re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b"), Severity.CRITICAL),
    SecretPattern("SEC-STRIPE-LIVE", "Stripe live secret key",
                  re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}"), Severity.CRITICAL),
    SecretPattern("SEC-STRIPE-RESTRICTED", "Stripe restricted key",
                  re.compile(r"\brk_live_[0-9a-zA-Z]{20,}"), Severity.HIGH),
    SecretPattern("SEC-SLACK", "Slack token",
                  re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}"), Severity.HIGH),
    SecretPattern("SEC-GITHUB-PAT", "GitHub personal access token",
                  re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), Severity.CRITICAL),
    SecretPattern("SEC-PRIVATE-KEY", "Private key block",
                  re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"), Severity.CRITICAL),
    SecretPattern("SEC-SERVICE-ACCOUNT", "Google service account JSON",
                  re.compile(r'"type"\s*:\s*"service_account"'), Severity.CRITICAL),
    SecretPattern("SEC-JWT", "Hard-coded JWT",
                  re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
                  Severity.HIGH),
    SecretPattern("SEC-OPENAI", "OpenAI-style API key",
                  re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}"), Severity.CRITICAL),
    SecretPattern("SEC-TWILIO-KEY", "Twilio API key",
                  re.compile(r"\bSK[0-9a-f]{32}\b"), Severity.HIGH),
    SecretPattern("SEC-SENDGRID", "SendGrid API key",
                  re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), Severity.CRITICAL),
    SecretPattern("SEC-MAILGUN", "Mailgun API key",
                  re.compile(r"\bkey-[0-9a-f]{32}\b"), Severity.HIGH),
    SecretPattern("SEC-GOOGLE-OAUTH", "Google OAuth client secret",
                  re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{20,}"), Severity.HIGH),
    SecretPattern(
        "SEC-SENTRY-DSN", "Sentry DSN with a secret key",
        re.compile(r"https://[0-9a-f]{16,}:[0-9a-f]{16,}@[\w.-]+/\d+"), Severity.MEDIUM,
        why=(
            "A DSN that still contains the secret half (public:secret@host) lets anyone "
            "forge events into your Sentry project. Modern DSNs drop the secret; an old one "
            "with it is a leak."
        ),
        fix="Rotate the DSN in Sentry and switch to the public-only DSN format.",
    ),
    SecretPattern(
        "SEC-FIREBASE-DB", "Firebase Realtime Database URL",
        re.compile(r"https://[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)"), Severity.LOW,
        why=(
            "The URL itself is not a secret, but it points straight at your database. If the "
            "security rules are open (the default during development), anyone with this URL can "
            "read or write everything."
        ),
        fix=(
            "Confirm the Realtime Database rules require auth and scope each path. Test with the "
            "Firebase emulator's rules coverage, not by trusting the client."
        ),
    ),
    SecretPattern(
        "SEC-SUPABASE-URL", "Supabase project URL",
        re.compile(r"https://[a-z0-9]{16,}\.supabase\.co"), Severity.LOW,
        why=(
            "The URL and the anon key are meant to ship in the client, so their presence is "
            "expected. The real exposure is Row Level Security: without RLS policies the anon key "
            "reads and writes every table directly. A service_role key must never ship — it "
            "bypasses RLS entirely (and would also be caught here as a hard-coded JWT)."
        ),
        fix=(
            "Enable RLS on every table and write policies scoped to auth.uid(). Keep the "
            "service_role key server-side only. Verify by querying with the anon key and "
            "confirming you cannot reach another user's rows."
        ),
    ),
]

# Looser patterns: real often enough to report, noisy enough to need entropy.
GENERIC_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(api[_-]?key|apikey|secret|secret[_-]?key|access[_-]?token|auth[_-]?token
       |client[_-]?secret|password|passwd|private[_-]?key)
    \s*[:=]\s*
    ["']([^"'\s]{12,120})["']
    """
)

# Groovy allows `storePassword "x"`, Kotlin DSL uses `storePassword = "x"`,
# and .properties files use `storePassword=x` with no quotes at all.
KEYSTORE_CREDENTIAL = re.compile(
    r"""(?ix)
    \b(storePassword|keyPassword|storeFile|keyAlias)
    \s*(?:[:=]\s*|\s+)
    (?: ["']([^"'\n]{3,})["'] | ([^\s"'\n]{3,}) )
    """
)

PLACEHOLDER_HINTS = (
    "your", "example", "changeme", "placeholder", "xxxx", "todo", "dummy",
    "sample", "test", "fake", "insert", "replace", "<", "${", "abcdef",
    "0000", "1234", "null", "none", "random", "demo", "mock",
)

KEYSTORE_SUFFIXES = {".jks", ".keystore", ".p12", ".pfx", ".pem", ".key"}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    return any(hint in low for hint in PLACEHOLDER_HINTS)


def _redact(value: str) -> str:
    if len(value) <= 10:
        return value[:2] + "*" * (len(value) - 2)
    return f"{value[:6]}…{value[-4:]}"


def _is_generated(relpath: str) -> bool:
    low = relpath.replace("\\", "/").lower()
    return any(
        marker in low
        for marker in ("/test/", "/androidtest/", "/tests/", "sample", "example", "mock")
    )


@rule("secrets.strong")
def strong_secrets(ctx: ScanContext) -> Iterator[Finding]:
    seen: set[tuple[str, str]] = set()
    for f in ctx.files:
        for spec in STRONG_PATTERNS:
            finding_id, label, pattern, severity = spec.id, spec.label, spec.pattern, spec.severity
            for match in pattern.finditer(f.text):
                value = match.group(0)
                key = (finding_id, value)
                if key in seen:
                    continue
                seen.add(key)

                # A google-services.json key is client-side by design; the real
                # issue is whether it is restricted, not that it is present.
                if finding_id == "SEC-GOOGLE-KEY" and "google-services" in f.relpath.lower():
                    yield Finding(
                        id="SEC-GOOGLE-KEY-CLIENT",
                        title="Firebase/Google client API key ships in the app",
                        severity=Severity.LOW,
                        category=Category.SECURITY,
                        why=(
                            "This key is meant to be public, so its presence is expected. It is "
                            "only dangerous if it has no application restriction — then anyone "
                            "who pulls it from your APK can bill your project."
                        ),
                        fix=(
                            "In Google Cloud Console restrict the key to your Android package "
                            "name + SHA-1, and to only the APIs it needs."
                        ),
                        location=Location(f.relpath, f.line_of(match.start())),
                        evidence=_redact(value),
                        refs=(DOC_API_RESTRICT,),
                    )
                    continue

                yield Finding(
                    id=finding_id,
                    title=f"{label} found in the app",
                    severity=severity,
                    category=Category.SECURITY,
                    why=spec.why,
                    fix=spec.fix,
                    location=Location(f.relpath, f.line_of(match.start())),
                    evidence=_redact(value),
                    refs=(DOC_KEYS,),
                )


@rule("secrets.generic")
def generic_secrets(ctx: ScanContext) -> Iterator[Finding]:
    seen: set[str] = set()
    for f in ctx.files:
        if f.relpath.endswith("(extracted strings)"):
            continue  # too noisy against decompiled string tables
        for match in GENERIC_ASSIGNMENT.finditer(f.text):
            name, value = match.group(1), match.group(2)
            if _looks_like_placeholder(value) or value in seen:
                continue
            if shannon_entropy(value) < 3.2:
                continue
            seen.add(value)
            yield Finding(
                id="SEC-GENERIC",
                title=f"Possible hard-coded credential assigned to '{name}'",
                severity=Severity.LOW if _is_generated(f.relpath) else Severity.MEDIUM,
                category=Category.SECURITY,
                why=(
                    "A high-entropy literal assigned to a credential-shaped name. If this is a "
                    "real key it is extractable from the shipped package."
                ),
                fix=(
                    "If it is real: rotate it and move it server-side. If it is not a secret, "
                    "rename the variable so this stops being flagged."
                ),
                location=Location(f.relpath, f.line_of(match.start())),
                evidence=f"{name} = {_redact(value)}",
                refs=(DOC_KEYS,),
            )


DOC_SIGNING = "https://developer.android.com/studio/publish/app-signing"

# Right-hand sides that are lookups, not literals: an env read, a property
# read, a variable, an interpolation. Never a hard-coded secret.
_INDIRECTION = re.compile(
    r"""(?ix)^\s*(?:
        file\s*\( | System\. | project\. | providers\. | rootProject\. |
        \$ | \$\{ |
        \w+\s*\.\s*getProperty\b | getProperty\b | \w+\s*\.\s*get\b |
        System\.getenv | getenv\b | env\b
    )"""
)


def _signing_finding(name: str, value: str, status: str, f, line: int) -> Finding:
    is_pointer = name in {"storeFile", "keyAlias"}
    # A build script is committed by convention, so a literal secret in one is
    # exposed even when git can't confirm it; a .properties/.cfg file is usually
    # gitignored, so hedge lower when git is unavailable.
    is_build_script = f.path.suffix.lower() in {".gradle", ".kts"}
    evidence = f"{name} = {_redact(value)}"
    loc = Location(f.relpath, line)

    if status == "committed":
        if is_pointer:
            sev, title = Severity.LOW, f"Signing config '{name}' is committed in the build file"
            why = (
                "Not a secret by itself, but it points at the keystore and confirms the alias — "
                "half of what an attacker needs."
            )
        else:
            sev, title = Severity.HIGH, f"Keystore credential '{name}' is committed to git"
            why = (
                "This password is tracked in git. Whoever pulls it can sign builds Android accepts "
                "as updates to your app, and rotating a key cannot undo it."
            )
        fix = (
            "Remove the value from the tracked file, move it to a gitignored keystore.properties "
            "or an environment variable, and treat the keystore as burned — enroll in Play App "
            "Signing with a fresh upload key."
        )
    elif status == "uncommitted":
        sev = Severity.INFO
        title = f"Signing value '{name}' is on disk but not committed"
        why = (
            "The value is real, but this file is gitignored and git has no record of it ever being "
            "committed. Keeping signing credentials in a local, uncommitted file is the "
            "recommended setup — nothing is exposed."
        )
        fix = "No action needed. Ensure CI injects these from its secret store rather than a file."
    else:  # unknown — git not available
        if is_pointer:
            sev = Severity.LOW
        elif is_build_script:
            sev = Severity.HIGH  # a literal secret in a normally-committed build file
        else:
            sev = Severity.MEDIUM
        title = f"Signing credential '{name}' is hard-coded"
        why = (
            "A real signing value written as a literal. playgate could not consult git to confirm "
            "whether the file is committed. In a build script this is almost certainly tracked and "
            "exposed; in a gitignored properties file it may be the correct local-only setup."
        )
        fix = (
            f"Confirm with `git ls-files {f.relpath}` and `git log --all -- {f.relpath}`. If "
            "tracked: remove, rotate, and re-enroll in Play App Signing. Otherwise no action."
        )
    return Finding(
        id="SEC-SIGNING", title=title, severity=sev, category=Category.SECURITY,
        why=why, fix=fix, location=loc, evidence=evidence, refs=(DOC_SIGNING,),
    )


@rule("secrets.signing")
def signing_credentials(ctx: ScanContext) -> Iterator[Finding]:
    for f in ctx.files:
        if f.path.name not in {
            "build.gradle", "build.gradle.kts", "gradle.properties", "local.properties",
            "keystore.properties", "export_presets.cfg",
        }:
            continue
        # In a .properties file an unquoted right-hand side IS the literal value.
        # In a build script (.gradle/.kts/.cfg) an unquoted RHS is an expression
        # — a getProperty()/getenv()/variable read — never a hard-coded secret.
        properties_file = f.path.suffix.lower() == ".properties"
        status = ctx.git.status(f.relpath)
        for match in KEYSTORE_CREDENTIAL.finditer(f.text):
            name = match.group(1)
            quoted, unquoted = match.group(2), match.group(3)
            if quoted is not None:
                value = quoted
            elif unquoted is not None and properties_file:
                value = unquoted
            else:
                continue  # unquoted expression in a build script → a lookup, not a secret
            if not value or _looks_like_placeholder(value) or _INDIRECTION.match(value):
                continue
            yield _signing_finding(name, value, status, f, f.line_of(match.start()))


@rule("secrets.keystore_files")
def keystore_files(ctx: ScanContext) -> Iterator[Finding]:
    root = ctx.root
    if not root.is_dir():
        return
    gitignore = ""
    ignore_path = root / ".gitignore"
    if ignore_path.exists():
        gitignore = ignore_path.read_text(encoding="utf-8", errors="replace")

    # Skip generated directories inside the project only — the project itself
    # may live under a path containing "build" or "Library".
    skip = {".git", "build", "node_modules", "Library", ".gradle", ".godot", "Temp"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix.lower() not in KEYSTORE_SUFFIXES:
                continue
            rel = str(path.relative_to(root))
            status = ctx.git.status(rel)
            ignored = path.suffix.lower().lstrip(".") in gitignore or path.name in gitignore

            if status == "committed":
                sev = Severity.HIGH
                title = f"Key material is committed to git: {path.name}"
                why = (
                    "This keystore/private key is tracked in git, so it is in the history and in "
                    "every clone. Anyone with the repo can sign builds as you."
                )
                fix = (
                    "Remove it from history, rotate the key, and enroll in Play App Signing with a "
                    "fresh upload key. A keystore that was ever pushed must be treated as burned."
                )
            elif status == "uncommitted":
                sev = Severity.LOW
                title = f"Key material on disk (not committed): {path.name}"
                why = (
                    "The keystore is in the working tree — which is fine, you need it locally to "
                    "sign — and git confirms it is gitignored and was never committed. Nothing is "
                    "exposed."
                )
                fix = "No action needed. Keep it gitignored and never commit it."
            else:  # unknown — git not available; fall back to the .gitignore text heuristic
                sev = Severity.LOW if ignored else Severity.HIGH
                why = (
                    "Keystores and private keys inside the repo end up in git history and in any "
                    "clone of the project."
                    + (" It appears in .gitignore, so it may not be committed." if ignored else "")
                )
                title = f"Key material file in the project tree: {path.name}"
                fix = (
                    "Keep the keystore outside the repo or gitignored, and verify with "
                    "`git log --all --oneline -- <path>` that it was never committed."
                )
            yield Finding(
                id="SEC-KEYSTORE-FILE",
                title=title,
                severity=sev,
                category=Category.SECURITY,
                why=why,
                fix=fix,
                location=Location(rel),
                evidence=rel,
                refs=(DOC_SIGNING,),
            )
