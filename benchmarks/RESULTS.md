# playgate benchmark — v0.2.0

Synthetic corpus modelled on the vulnerability classes of well-known intentionally-insecure
apps. Written alongside the rules, so these numbers are a **regression guarantee**, not an
independent accuracy claim — see README for the external benchmark procedure.

- **Recall:** 87/87 expected findings detected (100%)
- **False positives on benign projects:** 0
- **Rule coverage:** 50/50 rules exercised

| Case | Modelled on | Expected | Detected | Result |
| --- | --- | --- | --- | --- |
| hardcoded-secrets | DIVA: hardcoding issues / insecure logging | 5 | 5 | ✓ |
| exposed-components | InsecureBankv2: exported content provider, backup, debuggable | 5 | 5 | ✓ |
| platform-hygiene | AndroGoat: unprotected components, task hijacking | 3 | 3 | ✓ |
| weak-crypto-storage | InsecureBankv2: weak crypto, insecure storage | 4 | 4 | ✓ |
| webview-tls | OVAA: insecure WebView, broken TLS | 6 | 6 | ✓ |
| taint-flows | OVAA: deep link → WebView, intent redirection, path traversal | 6 | 6 | ✓ |
| platform-apis | OVAA: FileProvider root-path, unverified app links, mutable PendingIntent | 6 | 6 | ✓ |
| release-build | Common: debuggable release, no R8, committed signing secrets | 5 | 5 | ✓ |
| play-policy | Play Console: common rejection reasons | 13 | 13 | ✓ |
| families-ad-id | Play Families policy: advertising ID in a kids app | 1 | 1 | ✓ |
| no-listing | Scanner coverage: store-side checks need a listing | 1 | 1 | ✓ |
| unity-game | Mobile games: client-side economy, Mono, no ARM64 | 4 | 4 | ✓ |
| godot-export | Godot: sensitive permissions, debug signing | 4 | 4 | ✓ |
| cloud-open | Firebase test mode, Supabase without RLS, Cloudflare | 4 | 4 | ✓ |
| cloud-unverifiable | Firebase / Supabase used, security config only server-side | 4 | 4 | ✓ |
| ios-app | App Store review: ATS, purpose strings, privacy manifest, UIWebView, ATT | 6 | 6 | ✓ |
| vulnerable-deps | Supply chain: Log4Shell, vulnerable npm transitive | 1 | 1 | ✓ |
| compiled-apk | Compiled package: API usage read from DEX | 9 | 9 | ✓ |
| clean-android | Well-configured app | 0 (benign) | 0 | ✓ clean |
| clean-safe-patterns | Safe versions of every flagged pattern | 0 (benign) | 0 | ✓ clean |
| clean-cloud | Locked-down Firebase rules and Supabase with RLS | 0 (benign) | 0 | ✓ clean |
| clean-ios | App Store-ready iOS project | 0 (benign) | 0 | ✓ clean |
