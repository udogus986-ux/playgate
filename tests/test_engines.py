"""Unity and Godot rules."""

from __future__ import annotations

from pathlib import Path

from playgate.models import Severity
from playgate.scan import scan

from .conftest import ids, write

PROJECT_SETTINGS = """%YAML 1.1
PlayerSettings:
  bundleVersion: 1.4.2
  AndroidMinSdkVersion: 24
  AndroidTargetSdkVersion: {target}
  AndroidBundleVersionCode: 12
  AndroidTargetArchitectures: {arch}
  scriptingBackend:
    Android: {backend}
    Standalone: 1
"""


def unity_project(tmp_path: Path, *, backend: int = 0, arch: int = 1, cs: str = "") -> Path:
    root = tmp_path / "unity"
    write(
        root / "ProjectSettings" / "ProjectSettings.asset",
        PROJECT_SETTINGS.format(target=36, arch=arch, backend=backend),
    )
    if cs:
        write(root / "Assets" / "Scripts" / "Game.cs", cs)
    return root


def test_mono_backend_flagged(tmp_path: Path) -> None:
    finding = next(
        f for f in scan(unity_project(tmp_path, backend=0)).findings
        if f.id == "UNI-MONO-BACKEND"
    )
    assert finding.severity is Severity.MEDIUM


def test_il2cpp_backend_clean(tmp_path: Path) -> None:
    assert "UNI-MONO-BACKEND" not in ids(scan(unity_project(tmp_path, backend=1)))


def test_missing_arm64_is_a_policy_finding(tmp_path: Path) -> None:
    finding = next(
        f for f in scan(unity_project(tmp_path, arch=1)).findings if f.id == "UNI-NO-ARM64"
    )
    assert finding.category.value == "policy"
    assert finding.rejection_weight == 30


def test_arm64_present_is_clean(tmp_path: Path) -> None:
    # bit 2 = ARM64
    assert "UNI-NO-ARM64" not in ids(scan(unity_project(tmp_path, arch=3)))


def test_playerprefs_economy(tmp_path: Path) -> None:
    root = unity_project(
        tmp_path,
        cs='void Buy() { PlayerPrefs.SetInt("coins", 9999); PlayerPrefs.SetInt("volume", 5); }',
    )
    findings = [f for f in scan(root).findings if f.id == "UNI-PLAYERPREFS-ECONOMY"]
    assert len(findings) == 1
    assert "coins" in findings[0].title
    assert findings[0].severity is Severity.HIGH


def test_iap_without_validation(tmp_path: Path) -> None:
    root = unity_project(
        tmp_path,
        cs="class Shop : IStoreListener { public void ProcessPurchase(Product p) { Grant(); } }",
    )
    assert "UNI-IAP-NOVALIDATION" in ids(scan(root))


def test_iap_with_validator_is_clean(tmp_path: Path) -> None:
    root = unity_project(
        tmp_path,
        cs=(
            "class Shop : IStoreListener {\n"
            "  CrossPlatformValidator validator;\n"
            "  public void ProcessPurchase(Product p) { validator.Validate(p.receipt); }\n"
            "}"
        ),
    )
    assert "UNI-IAP-NOVALIDATION" not in ids(scan(root))


# --------------------------------------------------------------------------
# Godot
# --------------------------------------------------------------------------

def godot_project(tmp_path: Path, preset: str) -> Path:
    root = tmp_path / "godot"
    write(root / "project.godot", 'config_version=5\n[application]\nconfig/name="G"\n')
    write(root / "export_presets.cfg", preset)
    return root


def test_godot_sensitive_permissions(tmp_path: Path) -> None:
    root = godot_project(
        tmp_path,
        """[preset.0]
name="Android"
platform="Android"
[preset.0.options]
permissions/internet=true
permissions/read_sms=true
permissions/camera=true
permissions/access_fine_location=true
keystore/release="/keys/rel.jks"
""",
    )
    finding = next(f for f in scan(root).findings if f.id == "GDT-PERMISSIONS")
    assert "read_sms" in finding.why
    # internet is normal for a game and must not be counted
    assert "internet" not in finding.evidence


def test_godot_empty_release_keystore(tmp_path: Path) -> None:
    root = godot_project(
        tmp_path,
        '[preset.0]\nname="Android"\nplatform="Android"\n[preset.0.options]\nkeystore/release=""\n',
    )
    finding = next(f for f in scan(root).findings if f.id == "GDT-DEBUG-KEYSTORE")
    assert finding.severity is Severity.HIGH


def test_godot_configured_keystore_is_clean(tmp_path: Path) -> None:
    root = godot_project(
        tmp_path,
        '[preset.0]\nname="Android"\nplatform="Android"\n'
        '[preset.0.options]\nkeystore/release="/keys/release.jks"\n',
    )
    assert "GDT-DEBUG-KEYSTORE" not in ids(scan(root))
