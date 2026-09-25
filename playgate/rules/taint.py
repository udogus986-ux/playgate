"""Lightweight intra-procedural taint tracking for Kotlin and Java.

The regex rules see one line at a time. These rules follow a value: they find
data another app or a web link controls (intent extras, deep-link parameters),
track it through local assignments inside the same function, and report when it
reaches a dangerous call (WebView.loadUrl, rawQuery, exec, File, startActivity).

Deliberately simple — no call graph, no fields, no aliasing through objects —
so it stays fast and explainable. Every finding names the source line and the
variable chain, so a reviewer can confirm it in seconds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from ..models import Category, Finding, Location, ScanContext, Severity, SourceFile
from .base import rule

DOC_WEBVIEW = "https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading"
DOC_SQL = "https://developer.android.com/privacy-and-security/risks/sql-injection"
DOC_INTENT = "https://developer.android.com/privacy-and-security/risks/intent-redirection"
DOC_PATH = "https://developer.android.com/privacy-and-security/risks/path-traversal"
DOC_CMD = "https://cwe.mitre.org/data/definitions/78.html"

# Values an attacker controls: anything read off an incoming Intent or URI.
SOURCE = re.compile(
    r"""(?x)
    \b(?:getIntent\(\)|intent)\s*\.\s*
        (?:getStringExtra|getCharSequenceExtra|getData|data|getDataString|dataString|
           getExtras|extras|getBundleExtra|getParcelableExtra|getStringArrayExtra)\b
    | \.getQueryParameter\s*\(
    | \.getStringExtra\s*\(
    | \.getParcelableExtra\s*\(
    | \.getQueryParameters\s*\(
    | \.getLastPathSegment\s*\(|\.lastPathSegment\b
    """
)

_KT_ASSIGN = re.compile(r"^\s*(?:val|var)\s+(\w+)(?:\s*:\s*[\w<>?.,\s]+?)?\s*=\s*(.+)$")
_JAVA_ASSIGN = re.compile(r"^\s*(?:final\s+)?[\w<>\[\].,?\s]+?\s+(\w+)\s*=\s*(.+?);?\s*$")
_REASSIGN = re.compile(r"^\s*(\w+)\s*=\s*(?!=)(.+?);?\s*$")
_FUNC = re.compile(
    r"(?m)^\s*(?:(?:override|private|public|protected|internal|suspend|static|final|open|synchronized)\s+)*"
    r"(?:fun\s+[\w.<>]+\s*\(|[\w<>\[\]]+\s+\w+\s*\([^;{]*\)\s*(?:throws\s+[\w.,\s]+)?\s*\{)"
)
_VALIDATION = re.compile(r"\.host\b|\.getHost\(|startsWith\(|allowlist|whitelist|ALLOWED|isValid\w*\(|resolveActivity\(")


@dataclass(frozen=True)
class Sink:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    why: str
    fix: str
    ref: str
    first_arg_only: bool = False


SINKS = [
    Sink(
        "TAINT-WEBVIEW-URL", "Untrusted input loaded into a WebView",
        re.compile(r"\.loadUrl\s*\("), Severity.HIGH,
        "A URL taken from an incoming intent or deep link is loaded into a WebView. Any app or "
        "web page can send your app a javascript:, file:// or attacker-hosted URL, which then "
        "runs with the WebView's settings and bridges.",
        "Parse the URL and allow only https with a host on an explicit allowlist before loading. "
        "Reject javascript: and file: schemes outright.",
        DOC_WEBVIEW,
    ),
    Sink(
        "TAINT-JS-INJECTION", "Untrusted input evaluated as JavaScript",
        re.compile(r"\.evaluateJavascript\s*\("), Severity.HIGH,
        "Input from outside the app is concatenated into JavaScript that the WebView executes.",
        "Pass data to the page as a JSON-encoded argument, never by string-building code.",
        DOC_WEBVIEW,
    ),
    Sink(
        "TAINT-SQLI", "Untrusted input built into a SQL statement",
        re.compile(r"\.(?:rawQuery|execSQL)\s*\("), Severity.HIGH,
        "Intent or URI data is concatenated into raw SQL. A crafted value changes the query — "
        "dumping or deleting rows another component should never see.",
        "Use placeholders (\"... WHERE id = ?\") with selectionArgs, or Room's bound parameters.",
        DOC_SQL, first_arg_only=True,
    ),
    Sink(
        "TAINT-CMD", "Untrusted input passed to a shell command",
        re.compile(r"Runtime\.getRuntime\(\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\("), Severity.HIGH,
        "Externally supplied data reaches Runtime.exec / ProcessBuilder, allowing command injection.",
        "Do not build commands from input. If unavoidable, pass arguments as an array and validate "
        "each against a strict allowlist.",
        DOC_CMD,
    ),
    Sink(
        "TAINT-PATH", "Untrusted input used as a file path",
        re.compile(r"\bFile\s*\(|\bFileInputStream\s*\(|\bFileOutputStream\s*\(|\bopenFileOutput\s*\("),
        Severity.MEDIUM,
        "A file name or path from an intent or URI is used to open a file. \"../\" sequences let "
        "the caller read or overwrite files outside the intended directory.",
        "Take only the final name component, then check File.canonicalPath starts with the "
        "intended directory's canonical path.",
        DOC_PATH,
    ),
    Sink(
        "TAINT-INTENT-REDIRECT", "Untrusted Intent is forwarded (intent redirection)",
        re.compile(r"\bstartActivity(?:ForResult)?\s*\(|\bstartService\s*\(|\bsendBroadcast\s*\("),
        Severity.HIGH,
        "An Intent received from another app is launched as-is. The caller can make your app open "
        "its non-exported components or grant URI permissions it holds — a known way to reach "
        "private providers.",
        "Do not forward received Intents. If you must, rebuild a new explicit Intent to an allowed "
        "component and verify the target with resolveActivity() against an allowlist.",
        DOC_INTENT,
    ),
]


def _scopes(text: str) -> list[tuple[int, str]]:
    """(offset, body) for each function body; the whole file if none is found."""
    out: list[tuple[int, str]] = []
    for m in _FUNC.finditer(text):
        brace = text.find("{", m.end() - 1)
        eq = text.find("=", m.end() - 1)
        if brace < 0:
            continue
        # Kotlin expression body `fun f() = ...` → skip, no statements to track.
        if 0 <= eq < brace and "\n" not in text[m.end():eq]:
            continue
        depth, i = 0, brace
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append((brace, text[brace : i + 1]))
    return out or [(0, text)]


def _split_args(args: str) -> list[str]:
    parts, depth, cur, quote = [], 0, [], None
    for ch in args:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return parts


def _call_args(text: str, open_paren: int) -> str:
    depth = 0
    for i in range(open_paren, min(len(text), open_paren + 800)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i]
    return ""


_STRING = re.compile(r'"(?:[^"\\]|\\.)*"' + r"|'(?:[^'\\]|\\.)*'")
_TEMPLATE = re.compile(r"\$\{([^}]*)\}|\$(\w+)")


def _code_only(expr: str) -> str:
    """Drop string-literal text (so the word `id` in "WHERE id = ?" is not a
    variable) but keep Kotlin template expressions, which *are* code."""
    def keep_templates(m: re.Match) -> str:
        return " ".join(a or b for a, b in _TEMPLATE.findall(m.group(0)))
    return _STRING.sub(keep_templates, expr)


def _mentions(expr: str, tainted: dict[str, str]) -> str | None:
    if SOURCE.search(expr):
        return "<source>"
    code = _code_only(expr)
    for name in tainted:
        if re.search(rf"(?<![\w.]){re.escape(name)}\b", code):
            return name
    return None


def _track(body: str) -> dict[str, str]:
    """var name → the source line that tainted it (directly or transitively)."""
    tainted: dict[str, str] = {}
    lines = body.splitlines()
    for _ in range(2):  # a second pass catches uses above their definition in loops
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            m = _KT_ASSIGN.match(line) or _JAVA_ASSIGN.match(line) or _REASSIGN.match(line)
            if not m:
                continue
            name, expr = m.group(1), m.group(2)
            if name in {"if", "return", "else", "when", "for", "while"}:
                continue
            via = _mentions(expr, tainted)
            if via and name not in tainted:
                tainted[name] = stripped[:140] if via == "<source>" else tainted[via]
    return tainted


@rule("taint.flows")
def taint_flows(ctx: ScanContext) -> Iterator[Finding]:
    for f in ctx.files:
        if f.path.suffix.lower() not in (".kt", ".java") or f.relpath.endswith("(extracted strings)"):
            continue
        if not SOURCE.search(f.text):
            continue  # nothing attacker-controlled read in this file
        reported: set[tuple[str, int]] = set()
        for offset, body in _scopes(f.text):
            tainted = _track(body)
            for sink in SINKS:
                for m in sink.pattern.finditer(body):
                    args = _call_args(body, m.end() - 1)
                    if not args:
                        continue
                    target = _split_args(args)[0] if sink.first_arg_only else args
                    via = _mentions(target, tainted)
                    if via is None:
                        continue
                    abs_index = offset + m.start()
                    line = f.line_of(abs_index)
                    if (sink.id, line) in reported:
                        continue
                    code_line = f.lines[line - 1].strip() if line <= len(f.lines) else ""
                    if code_line.startswith(("//", "*", "/*")):
                        continue
                    reported.add((sink.id, line))
                    origin = "read directly at the call" if via == "<source>" else f"'{via}' ← {tainted[via]}"
                    validated = via != "<source>" and _VALIDATION.search(body) is not None
                    yield Finding(
                        id=sink.id,
                        title=sink.title + (" (validation seen — confirm it)" if validated else ""),
                        severity=Severity.MEDIUM if validated and sink.severity > Severity.MEDIUM else sink.severity,
                        category=Category.SECURITY,
                        why=f"{sink.why} Flow: {origin}.",
                        fix=sink.fix,
                        location=Location(f.relpath, line),
                        evidence=code_line[:200],
                        refs=(sink.ref,),
                    )
