"""Regression tests for fixed bugs."""

from __future__ import annotations

from pathlib import Path

from playgate.cli import main
from playgate.collect import load_listing, walk_files
from playgate.scan import scan

from .conftest import ids, write


def test_project_under_skiplist_named_parent_is_still_scanned(tmp_path: Path) -> None:
    """SKIP_DIRS must apply inside the project, not to the path leading to it.

    A project living under .../Temp/... or .../build/... (Windows temp dirs,
    macOS ~/Library) used to be silently skipped entirely.
    """
    root = tmp_path / "Temp" / "build" / "Library" / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 30 } }\n")
    files = walk_files(root)
    assert [f.relpath for f in files]  # not empty
    assert "PLY-TARGET-API" in ids(scan(root))


def test_generated_dirs_inside_project_are_still_skipped(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "build" / "generated" / "Gen.kt", 'val apiKey = "Xq7pL2mNv8Zr4Tw9Xq7p"\n')
    assert all("generated" not in f.relpath for f in walk_files(root))


def test_broken_autodetected_listing_degrades_to_note(gradle_project) -> None:
    root = gradle_project(extra={"playgate.toml": "title = unclosed [\n"})
    report = scan(root)
    assert any("Listing file could not be read" in n for n in report.notes)


def test_broken_explicit_listing_exits_2(gradle_project, tmp_path: Path, capsys) -> None:
    root = gradle_project()
    bad = tmp_path / "bad.toml"
    bad.write_text("title = unclosed [\n", encoding="utf-8")
    assert main(["scan", str(root), "--listing", str(bad), "--no-color"]) == 2
    assert "not valid TOML" in capsys.readouterr().err


def test_quoted_boolean_string_does_not_invert_the_check(tmp_path: Path) -> None:
    """A JSON listing with "false" (string) must not read as truthy."""
    path = tmp_path / "playgate.json"
    path.write_text('{"account_creation": "false", "uses_ads": "true"}', encoding="utf-8")
    listing = load_listing(path)
    assert listing is not None
    assert listing.account_creation is False
    assert listing.uses_ads is True


def test_min_severity_does_not_change_fail_on(gradle_project, capsys) -> None:
    dirty = gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n")
    code = main([
        "scan", str(dirty), "--min-severity", "critical",
        "--fail-on", "high", "--no-color",
    ])
    capsys.readouterr()
    assert code == 1  # the HIGH/CRITICAL finding is hidden, but still counted


def test_keystore_file_found_under_skiplist_named_parent(tmp_path: Path) -> None:
    root = tmp_path / "Temp" / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    (root / "release.jks").write_bytes(b"\xfe\xed\xfe\xed")
    assert "SEC-KEYSTORE-FILE" in ids(scan(root))
