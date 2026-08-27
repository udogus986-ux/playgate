"""Regression tests for three verified false-positive bugs:

1. literal vs lookup — getProperty()/getenv() in a build script is not a secret
2. git-awareness — a gitignored, never-committed secret file is not HIGH
3. nested checkouts / worktrees must not be scanned (no double-counting)
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from playgate.collect import walk_files
from playgate.models import Severity
from playgate.scan import scan

from .conftest import ids, write

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _init_commit(root: Path) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e",
    }

    def g(*args: str) -> None:
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       capture_output=True, env=env)

    g("init", "-b", "main")
    g("add", "-A")          # respects .gitignore
    g("commit", "-m", "init")


# --------------------------------------------------------------------------
# Bug 1 — literal vs lookup
# --------------------------------------------------------------------------

def test_gradle_property_lookup_is_not_a_secret(gradle_project) -> None:
    root = gradle_project(
        gradle=(
            "android {\n"
            "  defaultConfig { targetSdk 36 }\n"
            "  signingConfigs { release {\n"
            '    storePassword keystoreProps.getProperty("storePassword")\n'
            '    keyPassword System.getenv("KEY_PASSWORD")\n'
            "  } }\n"
            "}\n"
        )
    )
    assert "SEC-SIGNING" not in ids(scan(root))


def test_gradle_kts_getproperty_is_not_a_secret(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(
        root / "app" / "build.gradle.kts",
        'android {\n  signingConfigs {\n    create("release") {\n'
        '      storePassword = keystoreProps.getProperty("storePassword")\n'
        '      keyPassword = keystoreProps.getProperty("keyPassword")\n'
        "    }\n  }\n}\n",
    )
    assert "SEC-SIGNING" not in ids(scan(root))


def test_quoted_literal_in_build_script_is_still_high(gradle_project) -> None:
    root = gradle_project(
        gradle=(
            "android {\n  defaultConfig { targetSdk 36 }\n"
            '  signingConfigs { release { storePassword "Zx9Kq2Lm7Pv4Real" } }\n}\n'
        )
    )
    finding = next(f for f in scan(root).findings if f.id == "SEC-SIGNING")
    assert finding.severity is Severity.HIGH


# --------------------------------------------------------------------------
# Bug 2 — git-awareness
# --------------------------------------------------------------------------

@needs_git
def test_gitignored_uncommitted_keystore_props_is_info(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 36 } }\n")
    write(root / ".gitignore", "keystore.properties\n")
    write(root / "keystore.properties",
          "storePassword=Zx9Kq2Lm7Pv4Real\nkeyPassword=Zx9Kq2Lm7Pv4Real\n")
    _init_commit(root)  # keystore.properties is gitignored → never committed
    findings = [f for f in scan(root).findings if f.id == "SEC-SIGNING"]
    assert findings
    assert all(f.severity is Severity.INFO for f in findings), [f.severity for f in findings]


@needs_git
def test_committed_keystore_props_is_high(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 36 } }\n")
    write(root / "keystore.properties",
          "storePassword=Zx9Kq2Lm7Pv4Real\nkeyPassword=Zx9Kq2Lm7Pv4Real\n")
    _init_commit(root)  # no .gitignore → keystore.properties IS committed
    findings = [f for f in scan(root).findings if f.id == "SEC-SIGNING"]
    assert findings
    assert any(f.severity is Severity.HIGH for f in findings)


@needs_git
def test_committed_keystore_file_is_high_uncommitted_is_low(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 36 } }\n")
    write(root / ".gitignore", "*.jks\n")
    (root / "release.jks").write_bytes(b"\xfe\xed\xfe\xed")
    _init_commit(root)  # release.jks gitignored → uncommitted
    finding = next(f for f in scan(root).findings if f.id == "SEC-KEYSTORE-FILE")
    assert finding.severity is Severity.LOW
    assert "not committed" in finding.title


# --------------------------------------------------------------------------
# Bug 3 — nested checkouts / worktrees
# --------------------------------------------------------------------------

def test_nested_git_root_is_not_scanned(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 36 } }\n")
    nested = root / "vendor" / "copy"
    write(nested / ".git" / "HEAD", "ref: refs/heads/main\n")   # makes it a git root
    write(nested / "app" / "Secret.kt", 'val v = TrustAllCerts()\n')
    rels = [f.relpath.replace("\\", "/") for f in walk_files(root)]
    assert all("vendor/copy" not in r for r in rels)


def test_claude_worktrees_are_skipped(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / ".claude" / "worktrees" / "x" / "app" / "build.gradle",
          'storePassword "Zx9Kq2Lm7Pv4Real"\n')
    rels = [f.relpath.replace("\\", "/") for f in walk_files(root)]
    assert all(".claude" not in r for r in rels)
