"""Turn a directory (or an APK/AAB) into a ScanContext the rules can read."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tomllib
from pathlib import Path
from xml.etree import ElementTree as ET

from .models import (
    BuildConfig,
    GitInfo,
    ListingMeta,
    Manifest,
    ManifestComponent,
    ProjectKind,
    ScanContext,
    SourceFile,
)

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_A = f"{{{ANDROID_NS}}}"

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__",
    "build", "out", "bin", "obj", ".gradle", ".kotlin", ".cxx",
    "node_modules", "venv", ".venv", "env",
    # Nested checkouts / agent worktrees — a second copy of the same repo, which
    # would otherwise be scanned and double-counted.
    ".claude", "worktrees", ".worktrees",
    # Unity generated
    "Library", "Temp", "Logs", "UserSettings", "MemoryCaptures",
    # Godot generated
    ".godot", ".import",
}

TEXT_SUFFIXES = {
    ".xml", ".gradle", ".kts", ".properties", ".pro", ".cfg", ".conf",
    ".kt", ".java", ".cs", ".gd", ".js", ".ts", ".json", ".toml",
    ".yaml", ".yml", ".txt", ".asset", ".env", ".plist",
    # Cloud / BaaS security config: Firebase rules, Supabase migrations,
    # Cloudflare wrangler.
    ".rules", ".sql", ".jsonc",
}

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_FILES = 6000


def _is_react_native(root: Path) -> bool:
    pkg = root / "package.json"
    if not pkg.exists():
        return False
    try:
        data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return False
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    return any(k == "react-native" or k.startswith("react-native") for k in deps) or (
        "react-native" in json.dumps(data.get("scripts", {}))
    )


def detect_kind(root: Path) -> ProjectKind:
    if root.is_file() and root.suffix.lower() in {".apk", ".aab"}:
        return ProjectKind.APK
    if (root / "ProjectSettings" / "ProjectSettings.asset").exists():
        return ProjectKind.UNITY
    if (root / "project.godot").exists():
        return ProjectKind.GODOT
    # Flutter and React Native wrap a normal Gradle module under android/.
    if (root / "pubspec.yaml").exists() and (root / "android").is_dir():
        return ProjectKind.FLUTTER
    if _is_react_native(root) and (root / "android").is_dir():
        return ProjectKind.REACT_NATIVE
    for name in ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts"):
        if (root / name).exists():
            return ProjectKind.GRADLE
    # Nested: a repo that holds the Android project one level down.
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        if child.name in SKIP_DIRS:
            continue
        if (child / "build.gradle").exists() or (child / "build.gradle.kts").exists():
            return ProjectKind.GRADLE
    if any(root.rglob("AndroidManifest.xml")):
        return ProjectKind.GRADLE
    return ProjectKind.UNKNOWN


def _should_read(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return path.name in {"gradle.properties", "local.properties", "AndroidManifest.xml"}


def collect_git_info(root: Path) -> GitInfo:
    """Ask git what it tracks, so rules can tell a committed secret from a
    gitignored file that only lives on disk. Best-effort: git being absent, or
    the tree not being a repo, simply leaves ``available`` False.
    """
    if not root.is_dir():
        return GitInfo()

    def _git(*args: str, timeout: int) -> str | None:
        try:
            proc = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout

    inside = _git("rev-parse", "--is-inside-work-tree", timeout=5)
    if inside is None or inside.strip() != "true":
        return GitInfo()

    tracked_out = _git("ls-files", timeout=20)
    # --diff-filter=A lists every path ever added on any branch → "ever committed".
    history_out = _git("log", "--all", "--pretty=format:", "--name-only", "--diff-filter=A", timeout=30)
    if tracked_out is None or history_out is None:
        # Partial data would let us wrongly call a file "uncommitted"; bail to
        # the filesystem heuristics instead.
        return GitInfo()

    tracked = {p.replace("\\", "/") for p in tracked_out.splitlines() if p.strip()}
    historical = {p.replace("\\", "/") for p in history_out.splitlines() if p.strip()}
    return GitInfo(available=True, tracked=tracked, historical=historical)


def walk_files(root: Path) -> list[SourceFile]:
    # SKIP_DIRS is applied to directories *inside* the project only — the
    # project itself may live under a path containing "Temp", "Library",
    # "build" and so on, and that must not silence the scan. Pruning during
    # the walk also keeps huge generated trees (Unity's Library/) unvisited.
    files: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        # Prune SKIP_DIRS, and never descend into a subdirectory that is its own
        # git root (a submodule or worktree) — scanning it double-counts code.
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not (here / d / ".git").exists()
        )
        for name in sorted(filenames):
            if len(files) >= MAX_TOTAL_FILES:
                return files
            path = Path(dirpath) / name
            if not _should_read(path):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files.append(
                SourceFile(path=path, relpath=str(path.relative_to(root)), text=text)
            )
    return files


# --------------------------------------------------------------------------
# AndroidManifest (source XML)
# --------------------------------------------------------------------------

def _line_for(text: str, needle: str) -> int | None:
    idx = text.find(needle)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def parse_manifest_xml(text: str, source_path: str | None = None) -> Manifest | None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    if root.tag != "manifest":
        return None

    manifest = Manifest(source_path=source_path, raw=text)
    manifest.package = root.get("package")

    for node in root.findall("uses-permission") + root.findall("uses-permission-sdk-23"):
        name = node.get(f"{_A}name")
        if name:
            manifest.permissions.append(name)

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        for key in ("minSdkVersion", "targetSdkVersion", "maxSdkVersion"):
            value = uses_sdk.get(f"{_A}{key}")
            if value:
                manifest.uses_sdk[key] = value

    app = root.find("application")
    if app is not None:
        for key, value in app.attrib.items():
            manifest.application_attrs[key.replace(_A, "android:")] = value
        for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
            for node in app.findall(kind):
                name = node.get(f"{_A}name") or "<unnamed>"
                exported_raw = node.get(f"{_A}exported")
                exported: bool | None
                if exported_raw is None:
                    exported = None
                else:
                    exported = exported_raw.strip().lower() == "true"
                extra = {
                    k.replace(_A, "android:"): v
                    for k, v in node.attrib.items()
                    if k != f"{_A}name"
                }
                manifest.components.append(
                    ManifestComponent(
                        kind=kind,
                        name=name,
                        exported=exported,
                        has_intent_filter=node.find("intent-filter") is not None,
                        permission=node.get(f"{_A}permission"),
                        line=_line_for(text, name.rsplit(".", 1)[-1]),
                        extra=extra,
                    )
                )
    return manifest


# --------------------------------------------------------------------------
# Build config
# --------------------------------------------------------------------------

_INT_PATTERNS = {
    "target_sdk": r"targetSdk(?:Version)?\s*[=\s(]\s*['\"]?(\d+)",
    "min_sdk": r"minSdk(?:Version)?\s*[=\s(]\s*['\"]?(\d+)",
    "compile_sdk": r"compileSdk(?:Version)?\s*[=\s(]\s*['\"]?(\d+)",
    "version_code": r"versionCode\s*[=\s(]\s*['\"]?(\d+)",
}


def _balanced_block(text: str, open_at: int) -> str | None:
    """Return the body between the brace at/after ``open_at`` and its match."""
    try:
        start = text.index("{", open_at)
    except ValueError:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    return None


def _release_block(text: str) -> str | None:
    """Body of buildTypes { release { ... } }.

    Scoped to buildTypes on purpose: signingConfigs also contains a block named
    ``release``, and it usually appears first in the file.
    """
    build_types = re.search(r"\bbuildTypes\s*\{", text)
    scope = _balanced_block(text, build_types.start()) if build_types else text
    if scope is None:
        return None
    match = re.search(r"\brelease\s*(?:\{|\(\s*\)\s*\{|\s*\{)", scope)
    if not match:
        # Kotlin DSL also allows getByName("release") { ... } / named form.
        match = re.search(r"""(?:getByName|named|create)\s*\(\s*["']release["']\s*\)\s*\{""", scope)
    if not match:
        return None
    return _balanced_block(scope, match.start())


def parse_gradle(files: list[SourceFile]) -> BuildConfig:
    cfg = BuildConfig()
    for f in files:
        if f.path.name not in {"build.gradle", "build.gradle.kts"}:
            continue
        text = f.text
        if "android" not in text:
            continue
        for attr, pattern in _INT_PATTERNS.items():
            if getattr(cfg, attr) is None:
                m = re.search(pattern, text)
                if m:
                    setattr(cfg, attr, int(m.group(1)))
        if cfg.version_name is None:
            m = re.search(r"versionName\s*[=\s(]\s*[\"']([^\"']+)", text)
            if m:
                cfg.version_name = m.group(1)
        block = _release_block(text)
        if block is not None:
            cfg.source_path = f.relpath
            m = re.search(r"(?:isMinifyEnabled|minifyEnabled)\s*[=\s]\s*(true|false)", block)
            if m:
                cfg.minify_enabled = m.group(1) == "true"
            m = re.search(r"(?:isShrinkResources|shrinkResources)\s*[=\s]\s*(true|false)", block)
            if m:
                cfg.shrink_resources = m.group(1) == "true"
            m = re.search(r"(?:isDebuggable|debuggable)\s*[=\s]\s*(true|false)", block)
            if m:
                cfg.debuggable_release = m.group(1) == "true"
        if cfg.source_path is None:
            cfg.source_path = f.relpath
    return cfg


_UNITY_KEYS = {
    "target_sdk": r"AndroidTargetSdkVersion:\s*(\d+)",
    "min_sdk": r"AndroidMinSdkVersion:\s*(\d+)",
    "version_code": r"AndroidBundleVersionCode:\s*(\d+)",
}


def parse_unity(files: list[SourceFile]) -> BuildConfig:
    cfg = BuildConfig()
    for f in files:
        if f.path.name != "ProjectSettings.asset":
            continue
        cfg.source_path = f.relpath
        for attr, pattern in _UNITY_KEYS.items():
            m = re.search(pattern, f.text)
            if m:
                setattr(cfg, attr, int(m.group(1)))
        m = re.search(r"bundleVersion:\s*(\S+)", f.text)
        if m:
            cfg.version_name = m.group(1)
        # scriptingBackend is a map keyed by build target; Android == "Android".
        m = re.search(r"scriptingBackend:\s*\n(?:\s+\w+:\s*\d+\n)*", f.text)
        if m:
            block = m.group(0)
            am = re.search(r"Android:\s*(\d+)", block)
            if am:
                cfg.scripting_backend = "IL2CPP" if am.group(1) == "1" else "Mono2x"
    return cfg


def parse_godot(files: list[SourceFile]) -> BuildConfig:
    cfg = BuildConfig()
    for f in files:
        if f.path.name != "export_presets.cfg":
            continue
        cfg.source_path = f.relpath
        m = re.search(r'version/code\s*=\s*(\d+)', f.text)
        if m:
            cfg.version_code = int(m.group(1))
        m = re.search(r'version/name\s*=\s*"([^"]*)"', f.text)
        if m:
            cfg.version_name = m.group(1)
        m = re.search(r'gradle_build/target_sdk\s*=\s*"?(\d+)', f.text)
        if m:
            cfg.target_sdk = int(m.group(1))
        m = re.search(r'gradle_build/min_sdk\s*=\s*"?(\d+)', f.text)
        if m:
            cfg.min_sdk = int(m.group(1))
    return cfg


# --------------------------------------------------------------------------
# Listing metadata
# --------------------------------------------------------------------------

LISTING_FILENAMES = ("playgate.toml", "playgate.json", "playgate.yaml", "playgate.yml")

_LIST_FIELDS = {"collects_data", "data_safety_declared", "ignore"}
_BOOL_FIELDS = {
    "account_creation", "in_app_account_deletion", "uses_ads",
    "target_audience_children", "sells_digital_goods", "uses_play_billing",
    "first_release",
}


def _coerce_listing(data: dict, source: str) -> ListingMeta:
    meta = ListingMeta(source_path=source)
    known = {f for f in ListingMeta.__dataclass_fields__ if f != "source_path"}
    for key, value in data.items():
        norm = key.strip().lower().replace("-", "_")
        if norm not in known:
            continue
        if norm in _LIST_FIELDS:
            if isinstance(value, str):
                value = [v.strip() for v in value.split(",") if v.strip()]
            elif not isinstance(value, list):
                continue
            value = [str(v) for v in value]
        elif norm in _BOOL_FIELDS:
            # JSON/YAML authors sometimes quote booleans; a truthy "false"
            # string would silently invert the check, so normalise or skip.
            if isinstance(value, str):
                low = value.strip().lower()
                if low in {"true", "yes", "1"}:
                    value = True
                elif low in {"false", "no", "0"}:
                    value = False
                else:
                    continue
            elif not isinstance(value, bool):
                continue
        setattr(meta, norm, value)
    return meta


def load_listing(path: Path) -> ListingMeta | None:
    """Read a listing declaration file. TOML and JSON need no dependencies."""
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()
    data: dict | None = None
    if suffix == ".toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"{path.name} is not valid TOML: {exc}") from exc
    elif suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name} is not valid JSON: {exc}") from exc
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "YAML listing files need PyYAML installed; "
                "use playgate.toml or playgate.json instead."
            ) from exc
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        return None
    # Allow either a flat file or a [listing] table.
    if "listing" in data and isinstance(data["listing"], dict):
        data = data["listing"]
    return _coerce_listing(data, str(path))


def find_listing(root: Path) -> ListingMeta | None:
    base = root if root.is_dir() else root.parent
    for name in LISTING_FILENAMES:
        candidate = base / name
        if candidate.exists():
            return load_listing(candidate)
    return None


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def build_context(root: Path, listing_path: Path | None = None) -> ScanContext:
    root = root.resolve()
    kind = detect_kind(root)

    if kind is ProjectKind.APK:
        from .inputs.package import context_from_package

        ctx = context_from_package(root)
    else:
        files = walk_files(root)
        ctx = ScanContext(root=root, kind=kind, files=files)
        for f in files:
            if f.path.name == "AndroidManifest.xml":
                manifest = parse_manifest_xml(f.text, f.relpath)
                if manifest:
                    ctx.manifests.append(manifest)
        if kind is ProjectKind.UNITY:
            ctx.build = parse_unity(files)
        elif kind is ProjectKind.GODOT:
            ctx.build = parse_godot(files)
            # A Godot project with gradle build enabled also has real gradle files.
            gradle = parse_gradle(files)
            if ctx.build.target_sdk is None:
                ctx.build.target_sdk = gradle.target_sdk
        else:
            # Gradle, React Native and Flutter all build a normal Gradle module.
            ctx.build = parse_gradle(files)
        ctx.git = collect_git_info(root)

    try:
        ctx.listing = load_listing(listing_path) if listing_path else find_listing(root)
    except ValueError as exc:
        if listing_path:
            raise  # the user named this file; failing loudly beats skipping it
        # An auto-detected but broken file must not sink the whole scan.
        ctx.notes.append(f"Listing file could not be read ({exc}); listing checks were skipped.")
    if ctx.listing and ctx.listing.source_path:
        base = root if root.is_dir() else root.parent
        try:
            ctx.listing.source_path = str(Path(ctx.listing.source_path).relative_to(base))
        except ValueError:
            pass
    return ctx
