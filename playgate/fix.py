"""`playgate fix` — mechanical fixes for mechanical findings.

Only findings whose correct fix is unambiguous and local get a fixer. Each
fixer takes the current file text and the finding and returns new text (or
None if it can't place the edit safely). Nothing is written unless the caller
asks; the default is a unified diff to review.

Every fixer that changes runtime behaviour says so in its note, because a
correct security fix can still break a feature (turning off cleartext breaks a
plain-http endpoint the app actually uses).
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .models import Finding, ProjectKind, Report
from .rules.policy import REQUIREMENTS


@dataclass
class FileEdit:
    path: Path
    relpath: str
    original: str
    updated: str
    applied: list[tuple[str, str]] = field(default_factory=list)  # (finding id, note)

    def diff(self) -> str:
        return "".join(difflib.unified_diff(
            self.original.splitlines(keepends=True),
            self.updated.splitlines(keepends=True),
            fromfile=f"a/{self.relpath.replace(chr(92), '/')}", tofile=f"b/{self.relpath.replace(chr(92), '/')}",
        ))


Fixer = Callable[[str, Finding], "tuple[str, str] | None"]


def _set_manifest_attr(text: str, tag: str, attr: str, value: str) -> str | None:
    m = re.search(rf"<{tag}\b[^>]*>", text)
    if not m:
        return None
    start_tag = m.group(0)
    existing = re.search(rf'android:{attr}\s*=\s*"[^"]*"', start_tag)
    if existing:
        new_tag = start_tag.replace(existing.group(0), f'android:{attr}="{value}"')
    else:
        new_tag = start_tag.replace(f"<{tag}", f'<{tag} android:{attr}="{value}"', 1)
    return text[: m.start()] + new_tag + text[m.end():]


def _drop_manifest_attr(text: str, attr: str, value: str) -> str | None:
    pattern = re.compile(rf'\s*android:{attr}\s*=\s*"{value}"')
    new, n = pattern.subn("", text, count=1)
    return new if n else None


def fix_exported_unset(text: str, f: Finding):
    m = re.match(r"^(\S+) '(.+?)' has an intent filter", f.title)
    if not m:
        return None
    kind, name = m.groups()
    tag = re.search(rf'<{re.escape(kind)}\b(?=[^>]*android:name\s*=\s*"{re.escape(name)}")[^>]*>', text)
    if not tag:
        return None
    close = text.find(f"</{kind}>", tag.end())
    block = text[tag.end(): close if close > 0 else tag.end() + 2000]
    public = "category.LAUNCHER" in block or "category.BROWSABLE" in block
    value = "true" if public else "false"
    new_tag = tag.group(0).replace(f"<{kind}", f'<{kind} android:exported="{value}"', 1)
    note = (
        f"{name}: exported=\"true\" (launcher / deep-link entry point must stay reachable)"
        if public else f"{name}: exported=\"false\" — set true only if another app must start it"
    )
    return text[: tag.start()] + new_tag + text[tag.end():], note


def fix_backup(text: str, f: Finding):
    new = _set_manifest_attr(text, "application", "allowBackup", "false")
    return (new, "allowBackup=\"false\" — behaviour change: app data no longer backed up") if new else None


def fix_debuggable(text: str, f: Finding):
    new = _drop_manifest_attr(text, "debuggable", "true")
    return (new, "removed android:debuggable=\"true\" — the build type now decides") if new else None


def fix_cleartext(text: str, f: Finding):
    new = _drop_manifest_attr(text, "usesCleartextTraffic", "true")
    return (new, "removed usesCleartextTraffic — behaviour change: http:// requests will fail") if new else None


def fix_target_api(text: str, f: Finding):
    required = REQUIREMENTS["standard"]
    pattern = re.compile(r"(targetSdk(?:Version)?\s*(?:=|\(|\s)\s*['\"]?)(\d+)")
    new, n = pattern.subn(lambda m: f"{m.group(1)}{required}", text, count=1)
    if not n or new == text:
        return None
    return new, f"targetSdk → {required} — test the behaviour changes for every API level skipped"


def fix_release_debuggable(text: str, f: Finding):
    from .collect import _release_block

    body = _release_block(text)
    if not body:
        return None
    start = text.find(body)
    new_body, n = re.subn(r"((?:isDebuggable|debuggable)\s*=?\s*)true", r"\1false", body, count=1)
    if not n:
        return None
    return text[:start] + new_body + text[start + len(body):], "release build type: debuggable → false"


def fix_webview_debug(text: str, f: Finding):
    new, n = re.subn(r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)",
                     "setWebContentsDebuggingEnabled(BuildConfig.DEBUG)", text, count=1)
    return (new, "WebView debugging now only in debug builds") if n else None


def fix_pending_intent(text: str, f: Finding):
    from .rules.android_extra import _call_args

    lines = text.splitlines(keepends=True)
    if not f.location.line or f.location.line > len(lines):
        return None
    line_start = sum(len(l) for l in lines[: f.location.line - 1])
    m = re.compile(r"PendingIntent\s*\.\s*get\w+\s*\(").search(text, line_start)
    if not m:
        return None
    open_paren = m.end() - 1
    args = _call_args(text, open_paren)
    close = open_paren + 1 + len(args)
    parts = args.rsplit(",", 1)
    if len(parts) != 2:
        return None
    head, flags = parts
    kotlin = f.location.path and f.location.path.endswith(".kt")
    flag = "PendingIntent.FLAG_IMMUTABLE"
    stripped = flags.strip()
    if stripped in {"0", "0x0"}:
        new_flags = flags.replace(stripped, flag)
    else:
        new_flags = f"{flags.rstrip()} {'or' if kotlin else '|'} {flag}"
        new_flags += flags[len(flags.rstrip()):]
    return text[: open_paren + 1] + head + "," + new_flags + text[close:], "added FLAG_IMMUTABLE"


def fix_ios_encryption(text: str, f: Finding):
    end = text.rfind("</dict>")
    if end < 0 or "ITSAppUsesNonExemptEncryption" in text:
        return None
    insert = "\t<key>ITSAppUsesNonExemptEncryption</key>\n\t<false/>\n"
    return (text[:end] + insert + text[end:],
            "declared exempt encryption — correct only if the app uses nothing beyond standard HTTPS/OS crypto")


FIXERS: dict[str, Fixer] = {
    "AND-EXPORTED-UNSET": fix_exported_unset,
    "AND-BACKUP": fix_backup,
    "AND-DEBUGGABLE": fix_debuggable,
    "AND-CLEARTEXT": fix_cleartext,
    "PLY-TARGET-API": fix_target_api,
    "BLD-DEBUGGABLE": fix_release_debuggable,
    "CODE-WEBVIEW-DEBUG": fix_webview_debug,
    "AND-PENDINGINTENT-MUTABLE": fix_pending_intent,
    "IOS-ENCRYPTION-EXPORT": fix_ios_encryption,
}


def plan(report: Report, only: set[str] | None = None) -> tuple[list[FileEdit], list[Finding]]:
    """Group fixable findings by file and compute the edits. Returns the edits
    and the findings that have a fixer but could not be placed safely."""
    if report.kind is ProjectKind.APK:
        return [], []
    root = Path(report.root)
    edits: dict[str, FileEdit] = {}
    skipped: list[Finding] = []
    # Bottom-up within a file, so earlier line numbers stay valid.
    candidates = sorted(
        (f for f in report.findings if f.id in FIXERS and (not only or f.id in only) and f.location.path),
        key=lambda f: (f.location.path, -(f.location.line or 0)),
    )
    for f in candidates:
        rel = f.location.path
        path = root / rel
        if not path.is_file():
            skipped.append(f)
            continue
        edit = edits.get(rel)
        if edit is None:
            text = path.read_bytes().decode("utf-8")  # keep CRLF / LF exactly as found
            edit = edits[rel] = FileEdit(path=path, relpath=rel, original=text, updated=text)
        result = FIXERS[f.id](edit.updated, f)
        if not result:
            skipped.append(f)
            continue
        edit.updated, note = result
        edit.applied.append((f.id, note))
    return [e for e in edits.values() if e.updated != e.original], skipped


def apply(edits: list[FileEdit]) -> None:
    for edit in edits:
        edit.path.write_bytes(edit.updated.encode("utf-8"))
