"""A labelled benchmark corpus for playgate.

Each vulnerable case reproduces a vulnerability *class* demonstrated by a
well-known intentionally-insecure app (DIVA, InsecureBankv2, OVAA, AndroGoat,
…) as a minimal synthetic project, and lists the finding ids that must fire.
Benign cases are well-configured projects that must produce nothing.

Honesty note: this corpus was written alongside the rules, so 100% recall on it
is a regression guarantee, not an independent accuracy claim. The real
external benchmark is running playgate on the published vulnerable apps
themselves — see benchmarks/README.md.

Provider-format credentials are assembled from pieces at runtime so this source
file contains no contiguous key for secret scanners to flag.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_HEAD = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.bench">\n'
)
CLEAN_GRADLE = (
    "android {\n  defaultConfig { minSdk 26\n    targetSdk 36 }\n"
    "  buildTypes { release { minifyEnabled true\n shrinkResources true } }\n}\n"
)
CLEAN_LISTING = (
    'title = "Bench Notes"\nshort_description = "Write and find notes."\n'
    'privacy_policy_url = "https://bench.example/privacy"\naccount_creation = false\n'
    "sells_digital_goods = false\nuses_ads = false\ndeveloper_account_type = \"organization\"\n"
)

GOOGLE_KEY = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
CLIENT_KEY = "AIza" + "SyZ9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J"  # a different, client-side key
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


@dataclass
class Case:
    name: str
    inspired_by: str
    files: dict[str, str | bytes]
    expect: set[str] = field(default_factory=set)   # ids that must fire (vulnerable cases)
    benign: bool = False                            # must produce no findings at all
    package: str | None = None                      # "apk" → files are zipped into app.apk

    def materialise(self, base: Path) -> Path:
        root = base / self.name
        for rel, content in self.files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        if self.package == "apk":
            import zipfile

            apk = base / f"{self.name}.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                for rel in self.files:
                    zf.write(root / rel, rel)
            return apk
        return root


def _android(manifest_body: str = "<application android:allowBackup=\"false\"/>\n",
             gradle: str = CLEAN_GRADLE, listing: str | None = CLEAN_LISTING,
             **extra: str | bytes) -> dict[str, str | bytes]:
    files: dict[str, str | bytes] = {
        "settings.gradle": "include ':app'\n",
        "app/build.gradle": gradle,
        "app/src/main/AndroidManifest.xml": MANIFEST_HEAD + manifest_body + "</manifest>\n",
    }
    if listing is not None:
        files["playgate.toml"] = listing
    files.update({k.replace("__", "/"): v for k, v in extra.items()})
    return files


KT = "app__src__main__java__com__bench__"


def cases() -> list[Case]:
    from tests.axml_fixture import build_manifest_axml
    from tests.dex_fixture import build_dex

    return [
        # ------------------------------------------------------------ secrets
        Case("hardcoded-secrets", "DIVA: hardcoding issues / insecure logging", _android(**{
            KT + "Keys.kt": (
                f'val mapsKey = "{GOOGLE_KEY}"\n'
                f'val awsId = "{AWS_KEY}"\n'
                'val apiSecret = "Xq7pL2mNv8ZrT4wKb1Hs9Dc"\n'
                'fun login(token: String) { Log.d("auth", "token=$token") }\n'),
            "app__google-services.json": '{"current_key": "' + CLIENT_KEY + '"}',
        }), {"SEC-GOOGLE-KEY", "SEC-AWS-KEY", "SEC-GENERIC", "CODE-LOG-SECRET", "SEC-GOOGLE-KEY-CLIENT"}),

        # ------------------------------------------------------------ manifest
        Case("exposed-components", "InsecureBankv2: exported content provider, backup, debuggable",
             _android(manifest_body=(
                 '<application android:debuggable="true" android:usesCleartextTraffic="true"\n'
                 '    android:networkSecurityConfig="@xml/network_security_config">\n'
                 '  <provider android:name=".Accounts" android:authorities="com.bench.accounts" android:exported="true"/>\n'
                 "</application>\n"), **{
                 "app__src__main__res__xml__network_security_config.xml":
                     '<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>\n',
             }),
             {"AND-EXPORTED-OPEN", "AND-BACKUP", "AND-DEBUGGABLE", "AND-CLEARTEXT", "AND-NETSEC-CLEARTEXT"}),

        Case("platform-hygiene", "AndroGoat: unprotected components, task hijacking",
             _android(gradle="android {\n  defaultConfig { minSdk 24\n targetSdk 34 }\n"
                             "  buildTypes { release { minifyEnabled true } }\n}\n",
                      manifest_body=(
                 '<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>\n'
                 '<application android:allowBackup="false">\n'
                 '  <activity android:name=".Pay" android:exported="true" android:launchMode="singleTask"/>\n'
                 '  <receiver android:name=".Sms"><intent-filter><action android:name="x.SMS"/></intent-filter></receiver>\n'
                 '  <service android:name=".Upload" android:exported="false"/>\n'
                 "</application>\n")),
             {"AND-EXPORTED-UNSET", "AND-FGS-TYPE", "AND-TASK-AFFINITY"}),

        # ------------------------------------------------------------ crypto & storage
        Case("weak-crypto-storage", "InsecureBankv2: weak crypto, insecure storage", _android(**{
            KT + "Crypto.java": (
                'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
                'MessageDigest d = MessageDigest.getInstance("MD5");\n'
                "FileOutputStream f = openFileOutput(\"creds\", MODE_WORLD_READABLE);\n"
                "File dir = Environment.getExternalStorageDirectory();\n"),
        }), {"CODE-WEAK-CIPHER", "CODE-WEAK-HASH", "CODE-WORLD-PERMS", "CODE-EXTERNAL-STORAGE"}),

        Case("webview-tls", "OVAA: insecure WebView, broken TLS", _android(**{
            KT + "Web.kt": (
                'web.addJavascriptInterface(Bridge(), "app")\n'
                "web.settings.setAllowUniversalAccessFromFileURLs(true)\n"
                "WebView.setWebContentsDebuggingEnabled(true)\n"
                "val tm = TrustAllCerts()\n"
                'val base = "http://api.bench.example/v1"\n'),
            KT + "Net.java": (
                "class Net { void relax(HttpsURLConnection c) {\n"
                "  c.setHostnameVerifier(new HostnameVerifier() {\n"
                "    public boolean verify(String h, SSLSession s) { return true; } }); } }\n"),
        }), {"CODE-WEBVIEW-JSBRIDGE", "CODE-WEBVIEW-FILEACCESS", "CODE-WEBVIEW-DEBUG",
             "CODE-TLS-TRUSTALL", "CODE-TLS-VERIFY-TRUE", "CODE-HTTP-URL"}),

        # ------------------------------------------------------------ taint flows
        Case("taint-flows", "OVAA: deep link → WebView, intent redirection, path traversal", _android(**{
            KT + "Deep.kt": (
                "class Deep : Activity() {\n"
                "  override fun onCreate(b: Bundle?) {\n"
                '    val url = intent.getStringExtra("url")\n'
                "    web.loadUrl(url)\n"
                '    web.evaluateJavascript("show(\'$url\')", null)\n'
                "  }\n"
                "  fun open(uri: Uri) {\n"
                "    val name = uri.lastPathSegment\n"
                "    val f = File(filesDir, name)\n"
                '    val id = uri.getQueryParameter("id")\n'
                '    db.rawQuery("SELECT * FROM t WHERE id=" + id, null)\n'
                '    val cmd = uri.getQueryParameter("c")\n'
                "    Runtime.getRuntime().exec(cmd)\n"
                "  }\n}\n"),
            KT + "Router.java": (
                "public class Router extends Activity {\n"
                "  protected void onCreate(Bundle b) {\n"
                '    Intent next = getIntent().getParcelableExtra("next");\n'
                "    startActivity(next);\n  }\n}\n"),
        }), {"TAINT-WEBVIEW-URL", "TAINT-JS-INJECTION", "TAINT-PATH", "TAINT-SQLI", "TAINT-CMD",
             "TAINT-INTENT-REDIRECT"}),

        Case("platform-apis", "OVAA: FileProvider root-path, unverified app links, mutable PendingIntent",
             _android(manifest_body=(
                 '<application android:allowBackup="false">\n'
                 '  <activity android:name=".Link" android:exported="true"><intent-filter>\n'
                 '    <action android:name="android.intent.action.VIEW"/>\n'
                 '    <category android:name="android.intent.category.BROWSABLE"/>\n'
                 '    <data android:scheme="https" android:host="bench.example"/>\n'
                 "  </intent-filter></activity>\n</application>\n"), **{
                 "app__src__main__res__xml__paths.xml": '<paths><root-path name="r" path="/"/></paths>\n',
                 KT + "Plat.kt": (
                     "val pi = PendingIntent.getActivity(ctx, 0, i, 0)\n"
                     'val p = ctx.getSharedPreferences("s", 0)\np.edit().putString("session_token", t).apply()\n'
                     "val bp = BiometricPrompt(a, e, cb)\nbp.authenticate(info)\n"
                     'val i2 = Intent("com.bench.LOGIN")\ni2.putExtra("auth_token", t)\nsendBroadcast(i2)\n'),
             }),
             {"AND-FILEPROVIDER-ROOT", "AND-DEEPLINK-NO-AUTOVERIFY", "AND-PENDINGINTENT-MUTABLE",
              "CODE-PREFS-PLAINTEXT", "CODE-BIOMETRIC-NO-CRYPTO", "AND-BROADCAST-SENSITIVE"}),

        # ------------------------------------------------------------ build
        Case("release-build", "Common: debuggable release, no R8, committed signing secrets",
             _android(gradle=(
                 "android {\n  defaultConfig { minSdk 19\n targetSdk 36 }\n"
                 '  signingConfigs { release { storePassword "Zx9Kq2Lm7Pv4Real" } }\n'
                 "  buildTypes { release { debuggable true\n minifyEnabled false } }\n}\n"),
                 **{"release.jks": b"\xfe\xed\xfe\xed\x00\x00\x00\x02"}),
             {"BLD-DEBUGGABLE", "BLD-NO-MINIFY", "BLD-OLD-MINSDK", "SEC-SIGNING", "SEC-KEYSTORE-FILE"}),

        # ------------------------------------------------------------ Play policy
        Case("play-policy", "Play Console: common rejection reasons",
             _android(gradle="android {\n  defaultConfig { minSdk 26\n targetSdk 33 }\n"
                             "  buildTypes { release { minifyEnabled true } }\n}\n",
                      manifest_body=(
                 '<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>\n'
                 '<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>\n'
                 '<application android:allowBackup="false"/>\n'),
                 listing=(
                     'title = "THE BEST FREE TRACKER APP EVER 🚀"\n'
                     'full_description = "' + "tracker " * 30 + 'for tracking things every day"\n'
                     "account_creation = true\nsells_digital_goods = true\nuses_play_billing = false\n"
                     "uses_ads = true\n"
                     'data_safety_declared = ["personal_info"]\n'
                     'developer_account_type = "personal"\nfirst_release = true\n')),
             {"PLY-TARGET-API", "PLY-PERM-QUERY_ALL_PACKAGES", "PLY-DATA-SAFETY-GAP", "PLY-PRIVACY-POLICY",
              "PLY-ACCOUNT-DELETION", "PLY-BILLING", "PLY-TITLE-LENGTH", "PLY-TITLE-EMOJI", "PLY-TITLE-CAPS",
              "PLY-PROMO-TERMS", "PLY-KEYWORD-STUFFING", "PLY-CLOSED-TESTING", "PLY-ADID-MISSING"}),

        Case("families-ad-id", "Play Families policy: advertising ID in a kids app",
             _android(manifest_body=(
                 '<uses-permission android:name="com.google.android.gms.permission.AD_ID"/>\n'
                 '<application android:allowBackup="false"/>\n'),
                 listing=CLEAN_LISTING + "target_audience_children = true\n"
                         'data_safety_declared = ["advertising_id"]\n'),
             {"PLY-ADID-CHILDREN"}),

        Case("no-listing", "Scanner coverage: store-side checks need a listing",
             _android(listing=None), {"PLY-NO-LISTING"}),

        # ------------------------------------------------------------ engines
        Case("unity-game", "Mobile games: client-side economy, Mono, no ARM64", {
            "ProjectSettings/ProjectSettings.asset": (
                "%YAML 1.1\nPlayerSettings:\n  AndroidMinSdkVersion: 24\n  AndroidTargetSdkVersion: 36\n"
                "  AndroidTargetArchitectures: 1\n  scriptingBackend:\n    Android: 0\n"),
            "Assets/Scripts/Shop.cs": (
                "class Shop : IStoreListener {\n"
                '  public void ProcessPurchase(Product p) { PlayerPrefs.SetInt("coins", 9999); }\n}\n'),
        }, {"UNI-MONO-BACKEND", "UNI-NO-ARM64", "UNI-PLAYERPREFS-ECONOMY", "UNI-IAP-NOVALIDATION"}),

        Case("godot-export", "Godot: sensitive permissions, debug signing", {
            "project.godot": 'config_version=5\n[application]\nconfig/name="G"\n',
            "export_presets.cfg": (
                '[preset.0]\nname="Android"\nplatform="Android"\n[preset.0.options]\n'
                "permissions/read_sms=true\npermissions/camera=true\n"
                'keystore/release=""\npackage/signed=false\ngradle_build/use_gradle_build=false\n'),
        }, {"GDT-PERMISSIONS", "GDT-DEBUG-KEYSTORE", "GDT-UNSIGNED", "GDT-NO-GRADLE"}),

        # ------------------------------------------------------------ cloud
        Case("cloud-open", "Firebase test mode, Supabase without RLS, Cloudflare", _android(**{
            "firestore.rules": "service cloud.firestore { match /{d=**} { allow read, write: if true; } }\n",
            "storage.rules": "service firebase.storage { match /b/{x} { allow read, write: if request.time < timestamp.date(2027,1,1); } }\n",
            "supabase__migrations__001.sql": "create table notes (id uuid primary key, body text);\n",
            "wrangler.toml": 'name = "api"\nmain = "src/index.ts"\n',
        }), {"CLD-FIREBASE-OPEN", "CLD-FIREBASE-TESTMODE", "CLD-SUPABASE-NO-RLS", "COV-CLOUDFLARE"}),

        Case("cloud-unverifiable", "Firebase / Supabase used, security config only server-side",
             _android(**{KT + "Api.kt": (
                 'val db = "https://bench-app.firebaseio.com"\n'
                 'val sb = "https://abcdefghijklmnop.supabase.co"\n')}),
             {"COV-FIREBASE-RULES", "COV-SUPABASE-RLS", "SEC-FIREBASE-DB", "SEC-SUPABASE-URL"}),

        # ------------------------------------------------------------ iOS
        Case("ios-app", "App Store review: ATS, purpose strings, privacy manifest, UIWebView, ATT", {
            "Podfile": "platform :ios, '15.0'\n",
            "App/Info.plist": (
                '<plist version="1.0"><dict>\n<key>CFBundleIdentifier</key><string>com.bench</string>\n'
                "<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>\n"
                "<key>NSCameraUsageDescription</key><string></string>\n</dict></plist>\n"),
            "App/AppDelegate.swift": (
                "let w = UIWebView(frame: .zero)\n"
                "let id = ASIdentifierManager.shared().advertisingIdentifier\n"),
        }, {"IOS-ATS-ARBITRARY", "IOS-USAGE-DESC-EMPTY", "IOS-PRIVACY-MANIFEST-MISSING", "IOS-UIWEBVIEW",
            "IOS-IDFA-NO-ATT", "IOS-ENCRYPTION-EXPORT"}),

        # ------------------------------------------------------------ dependencies
        Case("vulnerable-deps", "Supply chain: Log4Shell, vulnerable npm transitive",
             _android(gradle=CLEAN_GRADLE + 'dependencies { implementation "org.apache.logging.log4j:log4j-core:2.14.1" }\n',
                      **{"web__package.json": '{"dependencies": {"express": "^4.0.0"}}',
                         "web__package-lock.json": (
                             '{"lockfileVersion": 3, "packages": {"": {}, '
                             '"node_modules/semver": {"version": "7.5.1"}}}')}),
             {"DEP-VULNERABLE"}),

        # ------------------------------------------------------------ compiled package
        Case("compiled-apk", "Compiled package: API usage read from DEX", {
            "AndroidManifest.xml": build_manifest_axml(),
            "classes.dex": build_dex(
                [("Landroid/webkit/WebView;", "addJavascriptInterface"),
                 ("Landroid/webkit/WebSettings;", "setAllowUniversalAccessFromFileURLs"),
                 ("Landroid/webkit/WebView;", "setWebContentsDebuggingEnabled"),
                 ("Ldalvik/system/DexClassLoader;", "<init>"),
                 ("Ljavax/net/ssl/HttpsURLConnection;", "setDefaultHostnameVerifier"),
                 ("Ljavax/crypto/Cipher;", "getInstance"),
                 ("Ljava/security/MessageDigest;", "getInstance"),
                 ("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;", "getAdvertisingIdInfo")],
                extra_strings=("AES", "MD5")),
        }, {"DEX-WEBVIEW-JSBRIDGE", "DEX-WEBVIEW-FILEACCESS", "DEX-WEBVIEW-DEBUG", "DEX-DYNAMIC-CODE",
            "DEX-GLOBAL-HOSTNAME-VERIFIER", "DEX-WEAK-CIPHER", "DEX-WEAK-HASH", "DEX-ADID-READ",
            "AND-DEBUGGABLE"}, package="apk"),

        # ------------------------------------------------------------ game profile
        Case("game-native", "Native Android game: client-side economy, unverified IAP, loot boxes, kids ads",
             _android(gradle=CLEAN_GRADLE + 'dependencies { implementation "com.badlogicgames.gdx:gdx:1.12.1" }\n',
                      listing=CLEAN_LISTING + "target_audience_children = true\n", **{
                 KT + "Economy.kt": (
                     'fun save() { prefs.edit().putInt("coins", coins).apply() }\n'
                     "fun openLootBox(): Item = table.random()\n"
                     "fun enableGodMode() { hp = Int.MAX_VALUE }\n"),
                 KT + "Store.kt": (
                     "class Store : PurchasesUpdatedListener {\n"
                     "  override fun onPurchasesUpdated(r: BillingResult, p: List<Purchase>?) {\n"
                     "    p?.forEach { grant(it.products); client.acknowledgePurchase(ack(it)) }\n  }\n}\n"),
                 KT + "Social.kt": (
                     "fun start() { MobileAds.initialize(ctx); FirebaseAuth.getInstance() }\n"
                     "fun post(score: Long) { leaderboardsClient.submitScore(BOARD, score) }\n"),
             }),
             {"GAME-NO-CATEGORY", "GAME-LOCAL-CURRENCY", "GAME-IAP-NO-SERVER-CHECK", "GAME-LOOTBOX-ODDS",
              "GAME-ADS-CHILDREN", "GAME-SCORE-NO-INTEGRITY", "GAME-CHEAT-LEFTOVER", "PLY-REVIEW-ACCESS"}),

        Case("game-flutter", "Flutter/Flame game: currency in shared_preferences", {
            "pubspec.yaml": "name: runner\ndependencies:\n  flame: ^1.18.0\n  shared_preferences: ^2.2.0\n",
            "lib/save.dart": "Future<void> save(SharedPreferences prefs) => prefs.setInt('gems', gems);\n",
            "android/settings.gradle": "include ':app'\n",
            "android/app/build.gradle": CLEAN_GRADLE,
            "android/app/src/main/AndroidManifest.xml":
                MANIFEST_HEAD + '<application android:allowBackup="false" android:appCategory="game"/>\n</manifest>\n',
            "playgate.toml": CLEAN_LISTING,
        }, {"GAME-LOCAL-CURRENCY"}),

        Case("game-godot-save", "Godot game: currency in a ConfigFile save", {
            "project.godot": 'config_version=5\n[application]\nconfig/name="G"\n',
            "export_presets.cfg": ('[preset.0]\nname="Android"\nplatform="Android"\n[preset.0.options]\n'
                                   'keystore/release="/keys/rel.jks"\n'),
            "scripts/save.gd": 'func save():\n\tcfg.set_value("player", "gold", gold)\n\tcfg.save("user://save.cfg")\n',
        }, {"GAME-LOCAL-CURRENCY"}),

        # ------------------------------------------------------------ app profile
        Case("app-webview-wrapper", "Play Minimum functionality / Webview spam",
             _android(manifest_body=(
                 '<application android:allowBackup="false">\n'
                 '  <activity android:name=".Main" android:exported="true"><intent-filter>\n'
                 '    <action android:name="android.intent.action.MAIN"/>\n'
                 '    <category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>\n'
                 "</application>\n"), **{
                 KT + "Main.kt": (
                     "class Main : Activity() {\n  override fun onCreate(b: Bundle?) {\n"
                     "    super.onCreate(b)\n    val w = WebView(this)\n"
                     '    w.loadUrl("https://shop.bench.example")\n    setContentView(w)\n  }\n}\n'),
             }),
             {"APP-WEBVIEW-WRAPPER"}),

        Case("app-login-health", "Play App access + Health Connect declaration",
             _android(manifest_body=(
                 '<uses-permission android:name="android.permission.health.READ_STEPS"/>\n'
                 '<application android:allowBackup="false">\n'
                 '  <activity android:name=".LoginActivity" android:exported="false"/>\n'
                 "</application>\n"),
                 listing=CLEAN_LISTING + 'data_safety_declared = ["health_fitness"]\n'),
             {"PLY-REVIEW-ACCESS", "APP-HEALTH-DECLARATION"}),

        # ============================================================ benign
        Case("clean-game", "Game done right: server-verified IAP, integrity, odds disclosed", _android(
            gradle=CLEAN_GRADLE + 'dependencies { implementation "com.badlogicgames.gdx:gdx:1.12.1" }\n',
            manifest_body='<application android:allowBackup="false" android:appCategory="game"/>\n',
            listing=CLEAN_LISTING + "discloses_loot_box_odds = true\nreview_access_provided = true\n", **{
                KT + "Store.kt": (
                    "override fun onPurchasesUpdated(r: BillingResult, p: List<Purchase>?) {\n"
                    "  p?.forEach { api.verifyPurchase(it.purchaseToken) }\n}\n"),
                KT + "Loot.kt": "fun openLootBox() = server.roll()\n",
                KT + "Scores.kt": (
                    "val token = integrityManager.requestIntegrityToken(req)\n"
                    "fun post(s: Long) = leaderboardsClient.submitScore(BOARD, s)\n"
                    "fun login() = FirebaseAuth.getInstance()\n"),
            }), benign=True),


        Case("clean-android", "Well-configured app", _android(**{
            KT + "Repo.kt": (
                'private val base = "https://api.bench.example/v1"\n'
                'fun load(id: String) { Log.d(TAG, "loading item") }\n'
                "val dev = \"http://10.0.2.2:8080\"\n"
                # credential-shaped names whose values are not secrets
                'val passwordHint = "Use at least twelve characters"\n'
                'val tokenType = "Bearer"\n'),
        }), benign=True),

        Case("clean-safe-patterns", "Safe versions of every flagged pattern", _android(
            gradle=(
                "android {\n  defaultConfig { minSdk 26\n targetSdk 36 }\n"
                "  signingConfigs { release {\n"
                '    storePassword keystoreProps.getProperty("storePassword")\n'
                '    keyPassword System.getenv("KEY_PASSWORD") } }\n'
                "  buildTypes { release { minifyEnabled true } }\n}\n"
                'dependencies { implementation "com.google.code.gson:gson:2.11.0" }\n'),
            manifest_body=(
                '<application android:allowBackup="false">\n'
                '  <activity android:name=".Main" android:exported="true"><intent-filter>\n'
                '    <action android:name="android.intent.action.MAIN"/>\n'
                '    <category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>\n'
                '  <activity android:name=".Link" android:exported="true"><intent-filter android:autoVerify="true">\n'
                '    <action android:name="android.intent.action.VIEW"/>\n'
                '    <category android:name="android.intent.category.BROWSABLE"/>\n'
                '    <data android:scheme="https" android:host="bench.example"/></intent-filter></activity>\n'
                '  <provider android:name=".Files" android:authorities="com.bench.files" android:exported="false"/>\n'
                "</application>\n"), **{
                "app__src__main__res__xml__paths.xml": '<paths><cache-path name="s" path="shared/"/></paths>\n',
                KT + "Safe.kt": (
                    "class Safe : Activity() {\n"
                    "  override fun onCreate(b: Bundle?) {\n"
                    '    val name = intent.getStringExtra("name")\n'
                    '    web.loadUrl("https://bench.example/help")\n'
                    "  }\n"
                    "  fun q(uri: Uri) {\n"
                    '    val id = uri.getQueryParameter("id")\n'
                    '    db.rawQuery("SELECT * FROM t WHERE id = ?", arrayOf(id))\n'
                    "  }\n}\n"
                    "val pi = PendingIntent.getActivity(ctx, 0, i, PendingIntent.FLAG_IMMUTABLE)\n"
                    'val prefs = EncryptedSharedPreferences.create(ctx, "s", k, a, b)\n'
                    'prefs.edit().putString("session_token", t).apply()\n'
                    'val c = Cipher.getInstance("AES/GCM/NoPadding")\n'),
                KT + "Bio.kt": "val bp = BiometricPrompt(a, e, cb)\nbp.authenticate(info, BiometricPrompt.CryptoObject(c))\n",
                KT + "Bus.kt": 'val i = Intent("com.bench.X")\ni.setPackage(packageName)\ni.putExtra("auth_token", t)\nsendBroadcast(i)\n',
            }), benign=True),

        Case("clean-cloud", "Locked-down Firebase rules and Supabase with RLS", _android(**{
            "firestore.rules": "service cloud.firestore { match /u/{uid} { allow read, write: if request.auth.uid == uid; } }\n",
            "supabase__migrations__001.sql": (
                "create table notes (id uuid primary key, owner uuid);\n"
                "alter table notes enable row level security;\n"),
        }), benign=True),

        Case("clean-ios", "App Store-ready iOS project", {
            "Podfile": "platform :ios, '15.0'\n",
            "App/Info.plist": (
                '<plist version="1.0"><dict>\n<key>CFBundleIdentifier</key><string>com.bench</string>\n'
                "<key>NSCameraUsageDescription</key><string>Scan a plant to identify it.</string>\n"
                "<key>ITSAppUsesNonExemptEncryption</key><false/>\n</dict></plist>\n"),
            "App/PrivacyInfo.xcprivacy": '<plist version="1.0"><dict><key>NSPrivacyTracking</key><false/></dict></plist>\n',
            "App/View.swift": "let web = WKWebView(frame: .zero)\n",
        }, benign=True),
    ]
