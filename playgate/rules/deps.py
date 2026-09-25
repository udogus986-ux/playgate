"""Offline software-composition analysis (SCA).

Reads declared dependency versions — Gradle string coordinates (with simple
same-file variables), Gradle version catalogs (libs.versions.toml), package.json
and package-lock.json — and matches them against a small, curated advisory list
bundled in playgate/data/advisories.toml. No network, no CVE database: it
catches the well-known, high-impact cases, and says so.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from typing import Iterator

from ..models import Category, Finding, Location, ScanContext, Severity, SourceFile
from ..resources import data_path
from .base import rule

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


@dataclass(frozen=True)
class Advisory:
    ecosystem: str
    package: str
    fixed: tuple[str, ...]
    severity: Severity
    id: str
    summary: str
    introduced: str | None = None


def _load() -> tuple[str, dict[tuple[str, str], list[Advisory]]]:
    with open(data_path("data", "advisories.toml"), "rb") as fh:
        raw = tomllib.load(fh)
    index: dict[tuple[str, str], list[Advisory]] = {}
    for eco in ("maven", "npm"):
        for entry in raw.get(eco, []):
            adv = Advisory(
                ecosystem=eco,
                package=entry["package"],
                fixed=tuple(entry["fixed"]),
                severity=_SEVERITY[entry["severity"]],
                id=entry["id"],
                summary=entry["summary"],
                introduced=entry.get("introduced"),
            )
            index.setdefault((eco, adv.package.lower()), []).append(adv)
    return raw.get("version", "?"), index


ADVISORIES_VERSION, ADVISORIES = _load()


def parse_version(text: str) -> tuple[int, ...] | None:
    m = re.match(r"\s*[v=^~>< ]*(\d+(?:\.\d+)*)", text or "")
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


def is_vulnerable(version: str, adv: Advisory) -> bool:
    v = parse_version(version)
    if v is None:
        return False
    if adv.introduced and _lt(v, parse_version(adv.introduced) or (0,)):
        return False
    fixes = [f for f in (parse_version(x) for x in adv.fixed) if f]
    if not fixes:
        return False
    same_line = [f for f in fixes if f[:2] == v[:2]]
    if same_line:
        return _lt(v, max(same_line))
    same_major = [f for f in fixes if f[0] == v[0]]
    if same_major:
        return _lt(v, max(same_major))
    return _lt(v, min(fixes))


@dataclass(frozen=True)
class Dep:
    ecosystem: str
    package: str
    version: str
    file: SourceFile
    line: int
    note: str = ""


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------

_GRADLE_COORD = re.compile(r"""["']([\w.\-]+):([\w.\-]+):([^"'\s@:]+)(?:@\w+)?["']""")
_GRADLE_VAR = re.compile(r"""(?m)^\s*(?:val|var|def|ext\.|extra\[")?\s*(\w+)"?\]?\s*=\s*["']([\w.\-+]+)["']""")


def _gradle_deps(f: SourceFile) -> Iterator[Dep]:
    variables = {m.group(1): m.group(2) for m in _GRADLE_VAR.finditer(f.text)}
    for m in _GRADLE_COORD.finditer(f.text):
        group, artifact, version = m.groups()
        var = re.fullmatch(r"\$\{?(\w+)\}?", version)
        if var:
            version = variables.get(var.group(1), "")
        if not version or version.startswith("$"):
            continue
        yield Dep("maven", f"{group}:{artifact}", version, f, f.line_of(m.start()))


def _catalog_deps(f: SourceFile) -> Iterator[Dep]:
    try:
        data = tomllib.loads(f.text)
    except tomllib.TOMLDecodeError:
        return
    versions = data.get("versions", {})
    for alias, spec in data.get("libraries", {}).items():
        module = version = None
        if isinstance(spec, str):
            parts = spec.split(":")
            if len(parts) == 3:
                module, version = f"{parts[0]}:{parts[1]}", parts[2]
        elif isinstance(spec, dict):
            module = spec.get("module") or (
                f"{spec['group']}:{spec['name']}" if "group" in spec and "name" in spec else None
            )
            ver = spec.get("version")  # `version.ref = "x"` parses as {"ref": "x"}
            if isinstance(ver, str):
                version = ver
            elif isinstance(ver, dict):
                if "ref" in ver:
                    version = versions.get(ver["ref"])
                else:
                    version = ver.get("strictly") or ver.get("require") or ver.get("prefer")
            if isinstance(version, dict):  # [versions] entry can itself be a rich table
                version = version.get("strictly") or version.get("require") or version.get("prefer")
        if module and isinstance(version, str):
            idx = f.text.find(alias)
            yield Dep("maven", module, version, f, f.line_of(idx) if idx >= 0 else 1)


def _package_json_deps(f: SourceFile) -> Iterator[Dep]:
    try:
        data = json.loads(f.text)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    for section, note in (("dependencies", ""), ("devDependencies", "devDependency — not shipped")):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            idx = f.text.find(f'"{name}"')
            yield Dep("npm", name, spec, f, f.line_of(idx) if idx >= 0 else 1, note)


def _package_lock_deps(f: SourceFile) -> Iterator[Dep]:
    try:
        data = json.loads(f.text)
    except json.JSONDecodeError:
        return
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return
    for path, meta in packages.items():
        if not path or not isinstance(meta, dict) or "version" not in meta:
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        note = "devDependency — not shipped" if meta.get("dev") else "resolved (incl. transitive)"
        idx = f.text.find(f'"{path}"')
        yield Dep("npm", name, meta["version"], f, f.line_of(idx) if idx >= 0 else 1, note)


def collect_deps(ctx: ScanContext) -> list[Dep]:
    deps: list[Dep] = []
    has_lock = any(f.path.name == "package-lock.json" for f in ctx.files)
    for f in ctx.files:
        name = f.path.name
        if name in {"build.gradle", "build.gradle.kts"}:
            deps.extend(_gradle_deps(f))
        elif name.endswith(".versions.toml"):
            deps.extend(_catalog_deps(f))
        elif name == "package-lock.json":
            deps.extend(_package_lock_deps(f))
        elif name == "package.json" and not has_lock and "node_modules" not in f.relpath:
            deps.extend(_package_json_deps(f))
    return deps


@rule("deps.known_vulnerable")
def known_vulnerable(ctx: ScanContext) -> Iterator[Finding]:
    seen: set[tuple[str, str, str]] = set()
    for dep in collect_deps(ctx):
        for adv in ADVISORIES.get((dep.ecosystem, dep.package.lower()), []):
            key = (dep.package, dep.version, adv.id)
            if key in seen or not is_vulnerable(dep.version, adv):
                continue
            seen.add(key)
            severity = adv.severity
            if dep.note.startswith("devDependency") and severity > Severity.LOW:
                severity = Severity(int(severity) - 1)
            fixed = " / ".join(adv.fixed)
            yield Finding(
                id="DEP-VULNERABLE",
                title=f"{dep.package} {dep.version} is affected by {adv.id}",
                severity=severity,
                category=Category.SECURITY,
                why=(
                    f"{adv.summary} The declared version is below the fixed release."
                    + (f" ({dep.note})" if dep.note else "")
                ),
                fix=(
                    f"Upgrade {dep.package} to {fixed} or later (the fix for your release line), "
                    "then re-run the build and tests."
                ),
                location=Location(dep.file.relpath, dep.line),
                evidence=f"{dep.package}:{dep.version}",
                refs=(f"https://nvd.nist.gov/vuln/detail/{adv.id}",),
            )
