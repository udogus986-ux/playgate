"""iOS / App Store checks."""

from __future__ import annotations

from pathlib import Path

from playgate.collect import detect_kind
from playgate.models import ProjectKind, Severity
from playgate.scan import scan

from .conftest import ids, write

PLIST_HEAD = '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n'
PLIST_TAIL = "\n</dict></plist>\n"
BUNDLE = "<key>CFBundleIdentifier</key><string>com.demo.app</string>\n"


def ios_project(tmp_path: Path, *, plist_extra: str = "", swift: str = "", xcprivacy: bool = False) -> Path:
    root = tmp_path / "app"
    write(root / "Podfile", "platform :ios, '15.0'\n")
    write(root / "MyApp" / "Info.plist", PLIST_HEAD + BUNDLE + plist_extra + PLIST_TAIL)
    if swift:
        write(root / "MyApp" / "AppDelegate.swift", swift)
    if xcprivacy:
        write(root / "MyApp" / "PrivacyInfo.xcprivacy",
              PLIST_HEAD + "<key>NSPrivacyTracking</key><false/>" + PLIST_TAIL)
    return root


def test_detect_kind_ios(tmp_path: Path) -> None:
    root = ios_project(tmp_path, xcprivacy=True)
    assert detect_kind(root) is ProjectKind.IOS


def test_ats_arbitrary_loads(tmp_path: Path) -> None:
    root = ios_project(
        tmp_path, xcprivacy=True,
        plist_extra="<key>NSAppTransportSecurity</key><dict>"
                    "<key>NSAllowsArbitraryLoads</key><true/></dict>\n",
    )
    finding = next(f for f in scan(root).findings if f.id == "IOS-ATS-ARBITRARY")
    assert finding.severity is Severity.HIGH


def test_empty_usage_description_flagged(tmp_path: Path) -> None:
    root = ios_project(
        tmp_path, xcprivacy=True,
        plist_extra="<key>NSCameraUsageDescription</key><string></string>\n",
    )
    assert "IOS-USAGE-DESC-EMPTY" in ids(scan(root))


def test_real_usage_description_is_quiet(tmp_path: Path) -> None:
    root = ios_project(
        tmp_path, xcprivacy=True,
        plist_extra="<key>NSCameraUsageDescription</key>"
                    "<string>We use the camera to scan your plant.</string>\n",
    )
    assert "IOS-USAGE-DESC-EMPTY" not in ids(scan(root))


def test_privacy_manifest_missing(tmp_path: Path) -> None:
    root = ios_project(tmp_path, xcprivacy=False)
    finding = next(f for f in scan(root).findings if f.id == "IOS-PRIVACY-MANIFEST-MISSING")
    assert finding.severity is Severity.HIGH


def test_privacy_manifest_present_is_quiet(tmp_path: Path) -> None:
    root = ios_project(tmp_path, xcprivacy=True)
    assert "IOS-PRIVACY-MANIFEST-MISSING" not in ids(scan(root))


def test_uiwebview_flagged(tmp_path: Path) -> None:
    root = ios_project(tmp_path, xcprivacy=True, swift="let w = UIWebView(frame: .zero)\n")
    assert "IOS-UIWEBVIEW" in ids(scan(root))


def test_idfa_without_att(tmp_path: Path) -> None:
    root = ios_project(
        tmp_path, xcprivacy=True,
        swift="let id = ASIdentifierManager.shared().advertisingIdentifier\n",
    )
    assert "IOS-IDFA-NO-ATT" in ids(scan(root))


def test_idfa_with_att_key_is_quiet(tmp_path: Path) -> None:
    root = ios_project(
        tmp_path, xcprivacy=True,
        plist_extra="<key>NSUserTrackingUsageDescription</key><string>To show relevant ads.</string>\n",
        swift="let id = ASIdentifierManager.shared().advertisingIdentifier\n",
    )
    assert "IOS-IDFA-NO-ATT" not in ids(scan(root))


def test_encryption_export_missing(tmp_path: Path) -> None:
    root = ios_project(tmp_path, xcprivacy=True)
    assert "IOS-ENCRYPTION-EXPORT" in ids(scan(root))


def test_encryption_export_declared_is_quiet(tmp_path: Path) -> None:
    root = ios_project(
        tmp_path, xcprivacy=True,
        plist_extra="<key>ITSAppUsesNonExemptEncryption</key><false/>\n",
    )
    assert "IOS-ENCRYPTION-EXPORT" not in ids(scan(root))


def test_android_project_has_no_ios_findings(gradle_project) -> None:
    found = ids(scan(gradle_project()))
    assert not any(i.startswith("IOS-") for i in found)


def test_hardcoded_secret_in_swift_is_found(tmp_path: Path) -> None:
    key = "sk_live_" + "51H8kQpLmNvBxWzYt3RfGh2Jd"
    root = ios_project(tmp_path, xcprivacy=True, swift=f'let k = "{key}"\n')
    assert "SEC-STRIPE-LIVE" in ids(scan(root))


def test_ios_findings_do_not_inflate_play_rejection_score(tmp_path: Path) -> None:
    # A pure iOS project (no Play policy issues) must not carry a Google Play
    # rejection score just because it has App Store findings.
    root = ios_project(tmp_path, xcprivacy=False)  # → IOS-PRIVACY-MANIFEST-MISSING etc.
    report = scan(root)
    assert any(f.id.startswith("IOS-") for f in report.findings)
    assert report.rejection_score() == 0
    assert report.rejection_band() == "NONE"
