"""`playgate fix`: each fixer, and that a fixed finding is gone on re-scan."""

from __future__ import annotations

from pathlib import Path

from playgate import fix
from playgate.cli import main
from playgate.scan import scan

from .conftest import ids, write

MANIFEST = "app/src/main/AndroidManifest.xml"


def _fix_all(root: Path) -> list[fix.FileEdit]:
    edits, _ = fix.plan(scan(root))
    fix.apply(edits)
    return edits


def test_exported_unset_keeps_launcher_public(gradle_project) -> None:
    root = gradle_project(manifest_body="""
<application android:allowBackup="false">
  <activity android:name=".Main">
    <intent-filter>
      <action android:name="android.intent.action.MAIN"/>
      <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
  </activity>
  <receiver android:name=".Boot">
    <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
  </receiver>
</application>
""")
    _fix_all(root)
    text = (root / MANIFEST).read_text()
    assert '<activity android:exported="true" android:name=".Main">' in text
    assert '<receiver android:exported="false" android:name=".Boot">' in text
    assert "AND-EXPORTED-UNSET" not in ids(scan(root))


def test_manifest_attribute_fixes(gradle_project) -> None:
    root = gradle_project(manifest_body=(
        '<application android:debuggable="true" android:usesCleartextTraffic="true"/>\n'))
    _fix_all(root)
    text = (root / MANIFEST).read_text()
    assert "debuggable" not in text
    assert "usesCleartextTraffic" not in text
    assert 'android:allowBackup="false"' in text
    assert not {"AND-DEBUGGABLE", "AND-CLEARTEXT", "AND-BACKUP"} & ids(scan(root))


def test_target_api_and_release_debuggable(gradle_project) -> None:
    root = gradle_project(gradle=(
        "android {\n  defaultConfig { targetSdk 33 }\n"
        "  buildTypes { release { debuggable true\n minifyEnabled true } }\n}\n"))
    _fix_all(root)
    text = (root / "app/build.gradle").read_text()
    assert "targetSdk 36" in text
    assert "debuggable false" in text
    assert not {"PLY-TARGET-API", "BLD-DEBUGGABLE"} & ids(scan(root))


def test_pending_intent_flags(gradle_project) -> None:
    root = gradle_project(extra={
        "app/src/main/java/A.kt": (
            "val a = PendingIntent.getActivity(ctx, 0, i, 0)\n"
            "val b = PendingIntent.getBroadcast(ctx, 1, j, PendingIntent.FLAG_UPDATE_CURRENT)\n"),
        "app/src/main/java/B.java": "PendingIntent p = PendingIntent.getService(c, 0, i, FLAG_ONE_SHOT);\n",
    })
    _fix_all(root)
    kt = (root / "app/src/main/java/A.kt").read_text()
    java = (root / "app/src/main/java/B.java").read_text()
    assert "getActivity(ctx, 0, i, PendingIntent.FLAG_IMMUTABLE)" in kt
    assert "FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)" in kt
    assert "FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE)" in java
    assert "AND-PENDINGINTENT-MUTABLE" not in ids(scan(root))


def test_webview_debug(gradle_project) -> None:
    root = gradle_project(extra={"app/src/main/java/W.kt": "WebView.setWebContentsDebuggingEnabled(true)\n"})
    _fix_all(root)
    assert "setWebContentsDebuggingEnabled(BuildConfig.DEBUG)" in (root / "app/src/main/java/W.kt").read_text()


def test_ios_encryption_key(tmp_path: Path) -> None:
    root = tmp_path / "ios"
    write(root / "Podfile", "platform :ios, '15.0'\n")
    write(root / "App" / "PrivacyInfo.xcprivacy", "<plist><dict></dict></plist>\n")
    write(root / "App" / "Info.plist",
          '<plist version="1.0"><dict>\n<key>CFBundleIdentifier</key><string>x</string>\n</dict></plist>\n')
    _fix_all(root)
    assert "IOS-ENCRYPTION-EXPORT" not in ids(scan(root))


def test_dry_run_writes_nothing_and_crlf_is_kept(gradle_project, capsys) -> None:
    root = gradle_project(manifest_body="<application/>\n")
    path = root / MANIFEST
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    before = path.read_bytes()
    assert main(["fix", str(root)]) == 0
    out = capsys.readouterr().out
    assert "Dry run" in out and "allowBackup" in out
    assert path.read_bytes() == before
    assert main(["fix", str(root), "--apply"]) == 0
    capsys.readouterr()
    after = path.read_bytes()
    assert b'android:allowBackup="false"' in after
    assert b"\r\n" in after and b"\r\r\n" not in after


def test_only_filter(gradle_project, capsys) -> None:
    root = gradle_project(gradle="android { defaultConfig { targetSdk 30 } }\n",
                          manifest_body="<application/>\n")
    main(["fix", str(root), "--only", "AND-BACKUP", "--apply"])
    capsys.readouterr()
    assert "targetSdk 30" in (root / "app/build.gradle").read_text()
    assert "AND-BACKUP" not in ids(scan(root))
