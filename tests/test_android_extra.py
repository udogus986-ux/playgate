"""Deeper Android platform checks."""

from __future__ import annotations

from playgate.scan import scan

from .conftest import ids

KT = "app/src/main/java/com/x/A.kt"


def test_pending_intent_without_immutable(gradle_project) -> None:
    root = gradle_project(extra={KT: "val pi = PendingIntent.getActivity(ctx, 0, intent, 0)\n"})
    assert "AND-PENDINGINTENT-MUTABLE" in ids(scan(root))


def test_pending_intent_immutable_is_clean(gradle_project) -> None:
    root = gradle_project(extra={KT: (
        "val pi = PendingIntent.getActivity(\n  ctx, 0, intent,\n"
        "  PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE\n)\n")})
    assert "AND-PENDINGINTENT-MUTABLE" not in ids(scan(root))


def test_file_provider_root_path(gradle_project) -> None:
    root = gradle_project(extra={"app/src/main/res/xml/file_paths.xml":
                                 '<paths><root-path name="all" path="/"/></paths>\n'})
    assert "AND-FILEPROVIDER-ROOT" in ids(scan(root))


def test_file_provider_scoped_is_clean(gradle_project) -> None:
    root = gradle_project(extra={"app/src/main/res/xml/file_paths.xml":
                                 '<paths><cache-path name="s" path="shared/"/></paths>\n'})
    found = ids(scan(root))
    assert "AND-FILEPROVIDER-ROOT" not in found
    assert "AND-FILEPROVIDER-BROAD" not in found


DEEP = """
<application>
  <activity android:name=".Link" android:exported="true">
    <intent-filter{verify}>
      <action android:name="android.intent.action.VIEW"/>
      <category android:name="android.intent.category.DEFAULT"/>
      <category android:name="android.intent.category.BROWSABLE"/>
      <data android:scheme="https" android:host="app.example.com"/>
    </intent-filter>
  </activity>
</application>
"""


def test_unverified_https_deep_link(gradle_project) -> None:
    root = gradle_project(manifest_body=DEEP.format(verify=""))
    assert "AND-DEEPLINK-NO-AUTOVERIFY" in ids(scan(root))


def test_verified_https_deep_link_is_clean(gradle_project) -> None:
    root = gradle_project(manifest_body=DEEP.format(verify=' android:autoVerify="true"'))
    assert "AND-DEEPLINK-NO-AUTOVERIFY" not in ids(scan(root))


def test_token_in_plain_prefs(gradle_project) -> None:
    root = gradle_project(extra={KT: (
        'val p = ctx.getSharedPreferences("auth", 0)\n'
        'p.edit().putString("access_token", t).apply()\n')})
    assert "CODE-PREFS-PLAINTEXT" in ids(scan(root))


def test_token_in_encrypted_prefs_is_clean(gradle_project) -> None:
    root = gradle_project(extra={KT: (
        "val p = EncryptedSharedPreferences.create(ctx, \"auth\", key, a, b)\n"
        'p.edit().putString("access_token", t).apply()\n')})
    assert "CODE-PREFS-PLAINTEXT" not in ids(scan(root))


def test_biometric_without_crypto(gradle_project) -> None:
    root = gradle_project(extra={KT: "val bp = BiometricPrompt(a, e, cb)\nbp.authenticate(promptInfo)\n"})
    assert "CODE-BIOMETRIC-NO-CRYPTO" in ids(scan(root))


def test_biometric_with_crypto_is_clean(gradle_project) -> None:
    root = gradle_project(extra={KT: (
        "val bp = BiometricPrompt(a, e, cb)\n"
        "bp.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))\n")})
    assert "CODE-BIOMETRIC-NO-CRYPTO" not in ids(scan(root))


def test_sensitive_implicit_broadcast(gradle_project) -> None:
    root = gradle_project(extra={KT: (
        'val i = Intent("com.x.LOGIN")\ni.putExtra("auth_token", tok)\nsendBroadcast(i)\n')})
    assert "AND-BROADCAST-SENSITIVE" in ids(scan(root))


def test_package_scoped_broadcast_is_clean(gradle_project) -> None:
    root = gradle_project(extra={KT: (
        'val i = Intent("com.x.LOGIN")\ni.setPackage(packageName)\n'
        'i.putExtra("auth_token", tok)\nsendBroadcast(i)\n')})
    assert "AND-BROADCAST-SENSITIVE" not in ids(scan(root))
