from __future__ import annotations

from pathlib import Path

from playgate.collect import parse_gradle, parse_manifest_xml, walk_files
from playgate.models import Severity
from playgate.rules.secrets import shannon_entropy
from playgate.scan import scan

from .conftest import ids, write


# --------------------------------------------------------------------------
# Gradle parsing
# --------------------------------------------------------------------------

def test_release_block_is_not_confused_by_signing_configs(tmp_path: Path) -> None:
    """signingConfigs also has a block called `release`, and it comes first."""
    write(
        tmp_path / "build.gradle",
        """
        android {
          signingConfigs { release { storeFile file("a.jks") } }
          buildTypes {
            debug { minifyEnabled false }
            release { minifyEnabled true
                      debuggable false }
          }
        }
        """,
    )
    cfg = parse_gradle(walk_files(tmp_path))
    assert cfg.minify_enabled is True
    assert cfg.debuggable_release is False


def test_kotlin_dsl_named_release_block(tmp_path: Path) -> None:
    write(
        tmp_path / "build.gradle.kts",
        """
        android {
            defaultConfig { targetSdk = 34 }
            buildTypes {
                getByName("release") {
                    isMinifyEnabled = false
                }
            }
        }
        """,
    )
    cfg = parse_gradle(walk_files(tmp_path))
    assert cfg.target_sdk == 34
    assert cfg.minify_enabled is False


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------

def test_exported_defaults(gradle_project) -> None:
    root = gradle_project(
        manifest_body="""
        <application>
          <receiver android:name=".Silent"/>
          <receiver android:name=".Loud">
            <intent-filter><action android:name="X"/></intent-filter>
          </receiver>
        </application>
        """
    )
    report = scan(root)
    exported = [f for f in report.findings if f.id == "AND-EXPORTED-UNSET"]
    # Only the receiver with an intent filter is missing an explicit exported.
    assert len(exported) == 1
    assert ".Loud" in exported[0].title


def test_launcher_activity_is_not_flagged(gradle_project) -> None:
    root = gradle_project(
        manifest_body="""
        <application>
          <activity android:name=".Main" android:exported="true">
            <intent-filter>
              <action android:name="android.intent.action.MAIN"/>
              <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
          </activity>
        </application>
        """
    )
    assert "AND-EXPORTED-OPEN" not in ids(scan(root))


def test_exported_provider_is_high(gradle_project) -> None:
    root = gradle_project(
        manifest_body="""
        <application>
          <provider android:name=".P" android:authorities="a" android:exported="true"/>
        </application>
        """
    )
    finding = next(f for f in scan(root).findings if f.id == "AND-EXPORTED-OPEN")
    assert finding.severity is Severity.HIGH


def test_permission_guard_suppresses_exported_finding(gradle_project) -> None:
    root = gradle_project(
        manifest_body="""
        <application>
          <service android:name=".S" android:exported="true"
                   android:permission="com.test.PRIVATE"/>
        </application>
        """
    )
    assert "AND-EXPORTED-OPEN" not in ids(scan(root))


def test_backup_disabled_is_clean(gradle_project) -> None:
    root = gradle_project(manifest_body='<application android:allowBackup="false"/>')
    assert "AND-BACKUP" not in ids(scan(root))


def test_data_extraction_rules_satisfy_backup_rule(gradle_project) -> None:
    root = gradle_project(
        manifest_body='<application android:dataExtractionRules="@xml/rules"/>'
    )
    assert "AND-BACKUP" not in ids(scan(root))


def test_manifest_parser_rejects_non_manifest() -> None:
    assert parse_manifest_xml("<other/>") is None
    assert parse_manifest_xml("<not xml") is None


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

def test_entropy_ordering() -> None:
    assert shannon_entropy("aaaaaaaaaaaa") < shannon_entropy("Xq7$pL2mNv8Z")


def test_placeholder_is_not_reported(gradle_project) -> None:
    root = gradle_project(
        extra={"app/src/main/java/A.kt": 'val apiKey = "YOUR_API_KEY_HERE_XX"\n'}
    )
    assert "SEC-GENERIC" not in ids(scan(root))


def test_low_entropy_is_not_reported(gradle_project) -> None:
    root = gradle_project(
        extra={"app/src/main/java/A.kt": 'val password = "aaaaaaaaaaaaaaaa"\n'}
    )
    assert "SEC-GENERIC" not in ids(scan(root))


def test_google_services_key_is_downgraded(gradle_project) -> None:
    key = "AIza" + "B" * 35
    root = gradle_project(
        extra={"app/google-services.json": '{"current_key": "%s"}' % key}
    )
    found = ids(scan(root))
    assert "SEC-GOOGLE-KEY-CLIENT" in found
    assert "SEC-GOOGLE-KEY" not in found


def test_groovy_keystore_password_is_detected(gradle_project) -> None:
    root = gradle_project(
        gradle="""
        android {
          defaultConfig { targetSdk 36 }
          signingConfigs { release { storePassword "Zx9Kq2Lm7Pv4" } }
        }
        """
    )
    finding = next(f for f in scan(root).findings if f.id == "SEC-SIGNING")
    assert finding.severity is Severity.HIGH
    assert "Zx9Kq2" in finding.evidence  # redacted, but identifiable


def test_property_indirection_is_not_a_secret(gradle_project) -> None:
    root = gradle_project(
        gradle="""
        android {
          defaultConfig { targetSdk 36 }
          signingConfigs { release { storePassword System.getenv("KS_PASS") } }
        }
        """
    )
    assert "SEC-SIGNING" not in ids(scan(root))


# --------------------------------------------------------------------------
# Code patterns
# --------------------------------------------------------------------------

def test_commented_out_code_is_ignored(gradle_project) -> None:
    root = gradle_project(
        extra={"app/src/main/java/A.kt": "// web.addJavascriptInterface(B(), \"x\")\n"}
    )
    assert "CODE-WEBVIEW-JSBRIDGE" not in ids(scan(root))


def test_localhost_http_is_ignored(gradle_project) -> None:
    root = gradle_project(
        extra={"app/src/main/java/A.kt": 'val dev = "http://localhost:8080"\n'}
    )
    assert "CODE-HTTP-URL" not in ids(scan(root))


def test_trust_all_certs_is_critical(gradle_project) -> None:
    root = gradle_project(
        extra={"app/src/main/java/A.kt": "val v = TrustAllCerts()\n"}
    )
    finding = next(f for f in scan(root).findings if f.id == "CODE-TLS-TRUSTALL")
    assert finding.severity is Severity.CRITICAL


# --------------------------------------------------------------------------
# Play policy
# --------------------------------------------------------------------------

def test_current_target_sdk_passes(gradle_project) -> None:
    root = gradle_project()
    assert "PLY-TARGET-API" not in ids(scan(root))


def test_old_target_sdk_is_critical(gradle_project) -> None:
    root = gradle_project(
        gradle="android { defaultConfig { targetSdk 33 } }\n"
    )
    finding = next(f for f in scan(root).findings if f.id == "PLY-TARGET-API")
    assert finding.severity is Severity.CRITICAL
    assert finding.rejection_weight >= 40


def test_target_sdk_35_is_high_not_critical(gradle_project) -> None:
    root = gradle_project(gradle="android { defaultConfig { targetSdk 35 } }\n")
    finding = next(f for f in scan(root).findings if f.id == "PLY-TARGET-API")
    assert finding.severity is Severity.HIGH


def test_data_safety_gap(gradle_project) -> None:
    root = gradle_project(
        manifest_body=(
            '<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>'
            "<application/>"
        ),
        extra={
            "playgate.toml": (
                'privacy_policy_url = "https://x.example/p"\n'
                'data_safety_declared = ["personal_info"]\n'
            )
        },
    )
    gaps = [f for f in scan(root).findings if f.id == "PLY-DATA-SAFETY-GAP"]
    assert len(gaps) == 1
    assert "location" in gaps[0].title


def test_declared_data_safety_category_clears_the_gap(gradle_project) -> None:
    root = gradle_project(
        manifest_body=(
            '<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>'
            "<application/>"
        ),
        extra={
            "playgate.toml": (
                'privacy_policy_url = "https://x.example/p"\n'
                'data_safety_declared = ["location"]\n'
            )
        },
    )
    assert "PLY-DATA-SAFETY-GAP" not in ids(scan(root))


def test_listing_text_rules(gradle_project) -> None:
    root = gradle_project(
        extra={
            "playgate.toml": (
                'title = "THE BEST FREE APP EVER MADE FOR EVERYONE"\n'
                'privacy_policy_url = "https://x.example/p"\n'
            )
        },
    )
    found = ids(scan(root))
    assert {"PLY-TITLE-LENGTH", "PLY-TITLE-CAPS", "PLY-PROMO-TERMS"} <= found


def test_valid_listing_is_quiet(gradle_project) -> None:
    root = gradle_project(
        extra={
            "playgate.toml": (
                'title = "Notes"\n'
                'short_description = "A small notebook."\n'
                'privacy_policy_url = "https://x.example/p"\n'
                "account_creation = false\n"
                "sells_digital_goods = false\n"
            )
        },
    )
    policy_ids = {f.id for f in scan(root).findings if f.id.startswith("PLY-")}
    assert policy_ids == set()


def test_accessibility_service_permission_is_flagged(gradle_project) -> None:
    root = gradle_project(
        manifest_body=(
            '<uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>'
            "<application/>"
        )
    )
    finding = next(
        f for f in scan(root).findings if f.id == "PLY-PERM-BIND_ACCESSIBILITY_SERVICE"
    )
    assert finding.severity is Severity.HIGH
    assert finding.rejection_weight == 30


def test_children_plus_ad_id_is_critical(gradle_project) -> None:
    root = gradle_project(
        manifest_body=(
            '<uses-permission android:name="com.google.android.gms.permission.AD_ID"/>'
            "<application/>"
        ),
        extra={
            "playgate.toml": (
                'privacy_policy_url = "https://x.example/p"\n'
                "target_audience_children = true\n"
            )
        },
    )
    finding = next(f for f in scan(root).findings if f.id == "PLY-ADID-CHILDREN")
    assert finding.severity is Severity.CRITICAL


def test_no_listing_yields_info_note(gradle_project) -> None:
    assert "PLY-NO-LISTING" in ids(scan(gradle_project()))
