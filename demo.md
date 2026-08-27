# playgate report

**Target:** `/home/claude/playgate/demo`  
**Project type:** gradle  
**Generated:** 2026-08-27 13:49 UTC

## Summary

| Severity | Count |
| --- | --- |
| CRITICAL | 5 |
| HIGH | 13 |
| MEDIUM | 10 |
| LOW | 7 |
| INFO | 0 |

**Play rejection risk: CRITICAL** (100/100) — At least one issue here blocks the upload or risks removal. Fix before submitting.

> This score is a weighted sum of the policy findings below, capped at 100. It ranks work; it is not a probability, and a clean report is not an approval.

## Google Play policy

### `CRITICAL` Digital goods are sold without Google Play Billing

- **Where:** `playgate.toml`
- **Why it matters:** In-app digital content and subscriptions must go through Play Billing. Routing them to an external processor is one of the fastest ways to lose the listing.
- **Fix:** Integrate the Play Billing Library for anything consumed inside the app. Physical goods and services consumed outside the app are the exception.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/10281818>

### `CRITICAL` No valid privacy policy URL declared

- **Where:** `playgate.toml`
- **Found:** `privacy_policy_url = (missing)`
- **Why it matters:** Every app on Play must link a privacy policy, whether or not it collects data. A missing, http-only or dead link is an automatic block.
- **Fix:** Publish a policy at a stable https URL that names your app, states what is collected and how it is deleted, and add it in Play Console > App content.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/10787469>

### `CRITICAL` targetSdk 33 is below the required API 36

- **Where:** `app/build.gradle`
- **Found:** `targetSdk = 33`
- **Why it matters:** Play requires new apps and updates to target Android 16 (API 36). Uploads below that are refused. Deadline: 31 August 2026 (extension possible to 1 November 2026). Below API 35 the app also stops being discoverable to new users on newer Android versions.
- **Fix:** Set targetSdk = 36, then work through the behaviour changes for every API level you skipped — foreground service types, photo picker, predictive back and exact alarms are the usual breakages. Request the extension in Play Console if you need more time.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/11926878>

### `HIGH` App creates accounts without a complete deletion route

- **Where:** `playgate.toml`
- **Why it matters:** Apps that let users create an account must offer deletion both inside the app and through a web link that works without installing the app. Missing an in-app deletion path and a publicly reachable web deletion URL.
- **Fix:** Add a delete-account screen in the app, publish a web deletion request page, and enter both in Play Console > App content > Data deletion.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/13327111>

### `HIGH` First release from a personal account needs a closed test first

- **Where:** `playgate.toml`
- **Why it matters:** Personal developer accounts created recently must run a closed test with at least 12 testers who stay opted in for 14 continuous days before production access is granted. Testers dropping out resets the clock.
- **Fix:** Start the closed test now — the 14 days are the long pole. Recruit more than 12 so attrition does not restart it, and use the closed track, not internal testing.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/14151465>

### `HIGH` 'location' is not declared in Data Safety but ACCESS_FINE_LOCATION is requested

- **Where:** `app/src/main/AndroidManifest.xml`
- **Found:** `android.permission.ACCESS_FINE_LOCATION`
- **Why it matters:** Play cross-checks the Data Safety form against what the app can actually do. A permission with no matching declaration is treated as an inaccurate disclosure, which suspends the app rather than just rejecting the update.
- **Fix:** Either declare 'location' in the Data Safety form with an accurate purpose, or remove ACCESS_FINE_LOCATION from the manifest if the feature was dropped. Remember that third-party SDKs count as collection too.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/10787469>

### `HIGH` 'app_activity' is not declared in Data Safety but PACKAGE_USAGE_STATS is requested

- **Where:** `app/src/main/AndroidManifest.xml`
- **Found:** `android.permission.PACKAGE_USAGE_STATS`
- **Why it matters:** Play cross-checks the Data Safety form against what the app can actually do. A permission with no matching declaration is treated as an inaccurate disclosure, which suspends the app rather than just rejecting the update.
- **Fix:** Either declare 'app_activity' in the Data Safety form with an accurate purpose, or remove PACKAGE_USAGE_STATS from the manifest if the feature was dropped. Remember that third-party SDKs count as collection too.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/10787469>

### `HIGH` 'advertising_id' is not declared in Data Safety but AD_ID is requested

- **Where:** `app/src/main/AndroidManifest.xml`
- **Found:** `com.google.android.gms.permission.AD_ID`
- **Why it matters:** Play cross-checks the Data Safety form against what the app can actually do. A permission with no matching declaration is treated as an inaccurate disclosure, which suspends the app rather than just rejecting the update.
- **Fix:** Either declare 'advertising_id' in the Data Safety form with an accurate purpose, or remove AD_ID from the manifest if the feature was dropped. Remember that third-party SDKs count as collection too.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/10787469>

### `HIGH` Restricted permission requires a Play declaration: See all installed apps

- **Where:** `app/src/main/AndroidManifest.xml`
- **Found:** `android.permission.QUERY_ALL_PACKAGES`
- **Why it matters:** QUERY_ALL_PACKAGES is a restricted permission. Play only allows it for a short list of app types (launchers, antivirus, accessibility, file managers) and rejects the rest.
- **Fix:** Replace it with a <queries> element naming the specific packages or intents you need. If you truly qualify, submit the permission declaration in Play Console.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/9888170>

### `MEDIUM` Restricted permission requires a Play declaration: Usage access

- **Where:** `app/src/main/AndroidManifest.xml`
- **Found:** `android.permission.PACKAGE_USAGE_STATS`
- **Why it matters:** Usage access reveals which apps the user opens and for how long. It is permitted, but requires a prominent disclosure and a matching Data Safety entry.
- **Fix:** Add an in-app disclosure before sending the user to the usage-access settings screen, and declare 'App activity' in Data Safety.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/9888170>

### `MEDIUM` Restricted permission requires a Play declaration: Draw over other apps

- **Where:** `app/src/main/AndroidManifest.xml`
- **Found:** `android.permission.SYSTEM_ALERT_WINDOW`
- **Why it matters:** Overlays are a common abuse vector, so Play reviews them closely and rejects overlays that obscure consent, ads or system UI.
- **Fix:** Only draw overlays after an explicit user action, never over permission dialogs or ads, and explain the use in the listing.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/9888170>

### `MEDIUM` App title contains emoji or decorative symbols

- **Where:** `playgate.toml`
- **Found:** `DEMO APP - BEST FREE TRACKER 2026 🚀`
- **Why it matters:** Play's metadata policy bans emoji, repeated punctuation and decorative characters in the title.
- **Fix:** Remove the symbols and keep the title to plain text.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/9898842>

### `MEDIUM` App title is 35 characters (limit 30)

- **Where:** `playgate.toml`
- **Found:** `DEMO APP - BEST FREE TRACKER 2026 🚀`
- **Why it matters:** Titles longer than 30 characters are rejected outright at submission.
- **Fix:** Trim the title to 30 characters; move the descriptive part to the short description.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/9898842>

### `LOW` Full description repeats 'tracker' 18 times

- **Where:** `playgate.toml`
- **Why it matters:** 'tracker' is 64% of the description. Repeating a keyword to influence search is explicitly listed as prohibited metadata.
- **Fix:** Rewrite so the keyword appears naturally a handful of times.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/9898842>

### `LOW` Store listing uses promotional or ranking claims

- **Where:** `playgate.toml`
- **Found:** `best, download now`
- **Why it matters:** Play's metadata policy forbids performance claims, price/promotion text and ranking assertions in the listing: best, download now
- **Fix:** Describe what the app does instead. Move any promotion into the app itself.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/9898842>

### `LOW` App title is entirely uppercase

- **Where:** `playgate.toml`
- **Found:** `DEMO APP - BEST FREE TRACKER 2026 🚀`
- **Why it matters:** All-caps titles are treated as attention-grabbing formatting and are refused unless the name is a real acronym.
- **Fix:** Use normal capitalisation.
- **Reference:** <https://support.google.com/googleplay/android-developer/answer/9898842>

## Security

### `CRITICAL` Release build type sets debuggable = true

- **Where:** `app/build.gradle`
- **Found:** `release { debuggable = true }`
- **Why it matters:** Every release built from this config is debuggable: memory is readable, code is attachable, and Play will reject the upload.
- **Fix:** Remove the debuggable flag from buildTypes { release { ... } }.
- **Reference:** <https://developer.android.com/build/shrink-code>

### `CRITICAL` Stripe live secret key found in the app

- **Where:** `app/src/main/java/com/demo/MainActivity.kt:10`
- **Found:** `sk_liv…h2Jd`
- **Why it matters:** Anything compiled into an APK is readable — unzip it and the string is there. Treat this credential as already public.
- **Fix:** Rotate the credential now, then move the call behind a server you control so the app never holds it. Obfuscation does not help here.
- **Reference:** <https://developer.android.com/privacy-and-security/security-tips#Credentials>

### `HIGH` Exported service '.SyncService' has no permission guard

- **Where:** `app/src/main/AndroidManifest.xml:24`
- **Found:** `<service android:name=".SyncService" android:exported="true">`
- **Why it matters:** Any installed app can reach this component. For providers that can mean reading or writing your data; for services, triggering privileged work.
- **Fix:** Set android:exported="false", or add android:permission="..." with a signature-level permission if another app of yours must call it.
- **Reference:** <https://developer.android.com/guide/topics/manifest/activity-element#exported>

### `HIGH` Exported provider '.DataProvider' has no permission guard

- **Where:** `app/src/main/AndroidManifest.xml:27`
- **Found:** `<provider android:name=".DataProvider" android:exported="true">`
- **Why it matters:** Any installed app can reach this component. For providers that can mean reading or writing your data; for services, triggering privileged work.
- **Fix:** Set android:exported="false", or add android:permission="..." with a signature-level permission if another app of yours must call it.
- **Reference:** <https://developer.android.com/guide/topics/manifest/activity-element#exported>

### `HIGH` WebView allows file:// access to other origins

- **Where:** `app/src/main/java/com/demo/MainActivity.kt:15`
- **Found:** `web.settings.setAllowUniversalAccessFromFileURLs(true)`
- **Why it matters:** A page loaded from file:// can read other local files, including your app's private storage, and ship them off-device.
- **Fix:** Set both to false. They default to false on API 16+; this call re-enables the risk.
- **Reference:** <https://developer.android.com/privacy-and-security/risks/insecure-webview>

### `HIGH` WebView exposes a native object to page JavaScript

- **Where:** `app/src/main/java/com/demo/MainActivity.kt:14`
- **Found:** `web.addJavascriptInterface(Bridge(), "android")`
- **Why it matters:** Any JavaScript the WebView loads can call the exposed object's @JavascriptInterface methods. If the page can be swapped — a redirect, an injected ad, plain http — that is remote code calling into your app.
- **Fix:** Drop the bridge if you can. If you need it, load only bundled local content, pin the allowed origins, and expose the smallest possible surface.
- **Reference:** <https://developer.android.com/privacy-and-security/risks/insecure-webview>

### `HIGH` Google API key found in the app

- **Where:** `app/src/main/java/com/demo/MainActivity.kt:6`
- **Found:** `AIzaSy…MBWY`
- **Why it matters:** Anything compiled into an APK is readable — unzip it and the string is there. Treat this credential as already public.
- **Fix:** Rotate the credential now, then move the call behind a server you control so the app never holds it. Obfuscation does not help here.
- **Reference:** <https://developer.android.com/privacy-and-security/security-tips#Credentials>

### `HIGH` Keystore credential 'storePassword' is committed

- **Where:** `app/build.gradle:16`
- **Found:** `storePassword = Hunter…Pass`
- **Why it matters:** Whoever holds your keystore and its passwords can sign builds that Android accepts as updates to your app. This cannot be undone by rotating a key.
- **Fix:** Move signing values into a gitignored keystore.properties or environment variables, and if the file was ever pushed, treat the keystore as burned and enroll in Play App Signing with a fresh upload key.
- **Reference:** <https://developer.android.com/studio/publish/app-signing>

### `HIGH` Keystore credential 'keyPassword' is committed

- **Where:** `app/build.gradle:18`
- **Found:** `keyPassword = Hunter…Pass`
- **Why it matters:** Whoever holds your keystore and its passwords can sign builds that Android accepts as updates to your app. This cannot be undone by rotating a key.
- **Fix:** Move signing values into a gitignored keystore.properties or environment variables, and if the file was ever pushed, treat the keystore as burned and enroll in Play App Signing with a fresh upload key.
- **Reference:** <https://developer.android.com/studio/publish/app-signing>

### `MEDIUM` Auto-backup is on with no exclusion rules

- **Where:** `app/src/main/AndroidManifest.xml`
- **Found:** `android:allowBackup="true"`
- **Why it matters:** allowBackup defaults to true. App data — including tokens and local databases — can be pulled off the device with adb backup or synced to the user's cloud.
- **Fix:** Set android:allowBackup="false", or keep backup and add android:dataExtractionRules that exclude credential and database files.
- **Reference:** <https://developer.android.com/guide/topics/data/autobackup>

### `MEDIUM` Cleartext HTTP traffic is explicitly allowed

- **Where:** `app/src/main/AndroidManifest.xml`
- **Found:** `android:usesCleartextTraffic="true"`
- **Why it matters:** Anything the app sends over http:// can be read and modified on any network the device joins.
- **Fix:** Remove android:usesCleartextTraffic, move endpoints to https, and if one host truly needs cleartext, allow only that host in a network security config.
- **Reference:** <https://developer.android.com/privacy-and-security/security-config>

### `MEDIUM` Network security config permits cleartext traffic

- **Where:** `app/src/main/res/xml/network_security_config.xml:3`
- **Found:** `cleartextTrafficPermitted="true"`
- **Why it matters:** The config re-enables plain HTTP for the domains in this scope.
- **Fix:** Remove cleartextTrafficPermitted="true", or scope it to a single dev host and exclude it from release builds.
- **Reference:** <https://developer.android.com/privacy-and-security/security-config>

### `MEDIUM` Credential-shaped value written to the log

- **Where:** `app/src/main/java/com/demo/MainActivity.kt:16`
- **Found:** `Log.d("auth", "user token = $secretKey")`
- **Why it matters:** Logcat is readable by adb and by crash/analytics SDKs. Tokens printed here leak to places you did not intend.
- **Fix:** Remove the log line, or log only a short non-reversible fingerprint of the value.
- **Reference:** <https://developer.android.com/privacy-and-security/security-tips#StoringData>

### `MEDIUM` Possible hard-coded credential assigned to 'secretKey'

- **Where:** `app/src/main/java/com/demo/MainActivity.kt:10`
- **Found:** `secretKey = sk_liv…h2Jd`
- **Why it matters:** A high-entropy literal assigned to a credential-shaped name. If this is a real key it is extractable from the shipped package.
- **Fix:** If it is real: rotate it and move it server-side. If it is not a secret, rename the variable so this stops being flagged.
- **Reference:** <https://developer.android.com/privacy-and-security/security-tips#Credentials>

### `MEDIUM` Possible hard-coded credential assigned to 'API_KEY'

- **Where:** `app/src/main/java/com/demo/MainActivity.kt:6`
- **Found:** `API_KEY = AIzaSy…MBWY`
- **Why it matters:** A high-entropy literal assigned to a credential-shaped name. If this is a real key it is extractable from the shipped package.
- **Fix:** If it is real: rotate it and move it server-side. If it is not a secret, rename the variable so this stops being flagged.
- **Reference:** <https://developer.android.com/privacy-and-security/security-tips#Credentials>

### `LOW` R8 shrinking/obfuscation is off for release

- **Where:** `app/build.gradle`
- **Found:** `release { isMinifyEnabled = false }`
- **Why it matters:** Without R8 the shipped code keeps original class, method and field names, so reading your logic — including any client-side check — takes minutes.
- **Fix:** Set isMinifyEnabled = true (and isShrinkResources = true) in the release build type, then test the release build once for reflection breakage.
- **Reference:** <https://developer.android.com/build/shrink-code>

### `LOW` minSdk 19 keeps the app on unpatched Android versions

- **Where:** `app/build.gradle`
- **Found:** `minSdk = 19`
- **Why it matters:** Below API 21 you inherit an old TLS stack and platform bugs that no longer receive fixes, and modern security config is unavailable.
- **Fix:** Raise minSdk to 21 or higher unless a measured share of your users is below it.
- **Reference:** <https://developer.android.com/studio/publish/app-signing>

### `LOW` Plain http:// endpoint in code

- **Where:** `app/src/main/java/com/demo/MainActivity.kt:7`
- **Found:** `const val BACKEND = "http://api.demo.example/v1"`
- **Why it matters:** Requests to this host are readable and modifiable on any shared network.
- **Fix:** Move the endpoint to https. If it is a local dev server, keep it out of release builds.
- **Reference:** <https://developer.android.com/privacy-and-security/security-ssl>

### `LOW` Signing config 'keyAlias' is hard-coded in the build file

- **Where:** `app/build.gradle:17`
- **Found:** `keyAlias = up****`
- **Why it matters:** Not a secret by itself, but it points at the keystore and confirms the alias, which is half of what an attacker needs. It also means the build only works on machines where that exact path exists.
- **Fix:** Move signing values into a gitignored keystore.properties or environment variables, and if the file was ever pushed, treat the keystore as burned and enroll in Play App Signing with a fresh upload key.
- **Reference:** <https://developer.android.com/studio/publish/app-signing>

## Inputs read

- `app/build.gradle`
- `app/src/main/AndroidManifest.xml`
- `playgate.toml`

---

Checks run against a fixed rule set. Absence of a finding means the rule did not match, not that the app is secure or that Play will approve it.
