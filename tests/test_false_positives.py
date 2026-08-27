"""A well-configured project must produce almost nothing.

A scanner that flags everything is the same as a scanner that flags nothing —
these tests exist to keep the rule set honest.
"""

from __future__ import annotations

from pathlib import Path

from playgate.models import Severity
from playgate.scan import scan

from .conftest import ids, write

CLEAN_GRADLE = """
android {
    namespace 'com.clean'
    compileSdk 36
    defaultConfig {
        applicationId "com.clean"
        minSdk 26
        targetSdk 36
        versionCode 3
        versionName "1.0.2"
    }
    signingConfigs {
        release {
            storeFile file(System.getenv("KEYSTORE_PATH"))
            storePassword System.getenv("KEYSTORE_PASSWORD")
            keyPassword System.getenv("KEY_PASSWORD")
        }
    }
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            signingConfig signingConfigs.release
        }
    }
}
"""

CLEAN_MANIFEST = """
    <uses-permission android:name="android.permission.INTERNET"/>
    <application
        android:allowBackup="false"
        android:label="Clean">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <service android:name=".WorkService" android:exported="false"/>
        <provider
            android:name=".FileProvider"
            android:authorities="com.clean.files"
            android:exported="false"
            android:grantUriPermissions="true"/>
    </application>
"""

CLEAN_KOTLIN = """
package com.clean

import android.util.Log

class Repo(private val http: HttpClient) {
    private val baseUrl = "https://api.clean.example/v1"

    // Not a secret: a public feature-flag identifier.
    private val flagsChannel = "production"

    suspend fun load(id: String): Result<Item> {
        Log.d(TAG, "loading item")
        return http.get("$baseUrl/items/$id")
    }

    fun verify(input: Int): Boolean {
        if (input > 0) return true
        return false
    }

    companion object { private const val TAG = "Repo" }
}
"""

CLEAN_LISTING = """
title = "Clean Notes"
short_description = "Write notes, sync them, find them again."
full_description = \"\"\"
Clean Notes keeps a plain-text notebook on your device and syncs it when you
sign in. You can organise entries into folders, search the full text, attach
images, and export everything as Markdown at any time. Notes are stored
locally first and uploaded in the background when a connection is available.
\"\"\"
privacy_policy_url = "https://clean.example/privacy"
account_creation = true
in_app_account_deletion = true
account_deletion_url = "https://clean.example/delete"
uses_ads = false
sells_digital_goods = false
target_audience_children = false
data_safety_declared = ["personal_info"]
developer_account_type = "organization"
first_release = false
"""


def clean_project(tmp_path: Path) -> Path:
    root = tmp_path / "clean"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", CLEAN_GRADLE)
    write(
        root / "app" / "src" / "main" / "AndroidManifest.xml",
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.clean">\n' + CLEAN_MANIFEST + "\n</manifest>\n",
    )
    write(root / "app" / "src" / "main" / "java" / "com" / "clean" / "Repo.kt", CLEAN_KOTLIN)
    write(root / "playgate.toml", CLEAN_LISTING)
    return root


def test_clean_project_has_no_findings(tmp_path: Path) -> None:
    report = scan(clean_project(tmp_path))
    assert report.findings == [], [f"{f.id} {f.location.render()}" for f in report.findings]
    assert report.rejection_band() == "NONE"


def test_ordinary_verify_method_is_not_a_tls_finding(tmp_path: Path) -> None:
    """`fun verify(x): Boolean { return true }` must not read as a TLS bypass."""
    found = ids(scan(clean_project(tmp_path)))
    assert "CODE-TLS-TRUSTALL" not in found
    assert "CODE-TLS-VERIFY-TRUE" not in found


def test_real_hostname_verifier_is_still_caught(tmp_path: Path) -> None:
    root = clean_project(tmp_path)
    write(
        root / "app" / "src" / "main" / "java" / "com" / "clean" / "Net.java",
        """
        class Net {
            static void relax(HttpsURLConnection c) {
                c.setHostnameVerifier(new HostnameVerifier() {
                    public boolean verify(String host, SSLSession s) { return true; }
                });
            }
        }
        """,
    )
    finding = next(f for f in scan(root).findings if f.id == "CODE-TLS-VERIFY-TRUE")
    assert finding.severity is Severity.HIGH


def test_env_var_signing_config_is_clean(tmp_path: Path) -> None:
    assert "SEC-SIGNING" not in ids(scan(clean_project(tmp_path)))


def test_normal_description_is_not_keyword_stuffing(tmp_path: Path) -> None:
    assert "PLY-KEYWORD-STUFFING" not in ids(scan(clean_project(tmp_path)))


def test_stuffed_description_is_caught(tmp_path: Path) -> None:
    root = clean_project(tmp_path)
    stuffed = "notes " * 30 + "app for writing and reading and syncing your things daily"
    write(
        root / "playgate.toml",
        CLEAN_LISTING.replace(
            'full_description = """',
            f'full_description = "{stuffed}"\nunused_field = """',
        ),
    )
    assert "PLY-KEYWORD-STUFFING" in ids(scan(root))
