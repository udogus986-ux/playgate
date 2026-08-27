# playgate

Pre-flight checks for Android apps: **security issues** and **Google Play rejection risk**, before you upload.

Works on Kotlin/Java Gradle projects, Unity, Godot 4, React Native and Flutter projects, and compiled `.apk` / `.aab` files. No dependencies, no API keys, no network calls — it reads your files and tells you what it found.

```
$ playgate scan .

playgate — /home/u/projects/aegis
project type: godot

findings: CRITICAL:1  HIGH:3  MEDIUM:4  LOW:2  INFO:0
play rejection risk: CRITICAL (85/100)
  At least one issue here blocks the upload or risks removal. Fix before submitting.

GOOGLE PLAY POLICY
------------------------------------------------------------
  [CRITICAL] targetSdk 33 is below the required API 36
      where : app/build.gradle
      found : targetSdk = 33
      why   : Play requires new apps and updates to target Android 16 (API 36).
              Uploads below that are refused. Deadline: 31 August 2026.
      fix   : Set targetSdk = 36, then work through the behaviour changes for
              every API level you skipped …
```

## Why

Two different things stop an Android release, and normal tooling covers neither well:

1. **Security issues** you cannot see by reading your own code — an exported provider, a key that survived into the release build, a WebView bridge, a game economy the client can rewrite.
2. **Play policy** — target API level, restricted permissions, Data Safety contradictions, account deletion, listing text. These are mechanical rules, and they are the most common reason an upload is refused.

playgate checks both, in one pass, and every finding comes with the exact fix.

## Install

```bash
pip install playgate                 # once published
# or, from a clone:
pip install -e .
```

Python 3.11 or newer. Nothing else.

## Use

```bash
playgate scan .                      # a project directory
playgate scan build/app-release.apk  # a compiled package (.apk or .aab)
playgate scan . --format md -o report.md
playgate scan . --format json        # for CI or other tools
playgate scan . --format sarif       # upload to GitHub code scanning
playgate scan . --baseline prev.json # show only findings new since prev.json
playgate rules                       # list every check
playgate ui                          # open the local web interface
playgate mcp                         # run as an MCP server (see "Dynamic agents")
```

### The web interface

`playgate ui` starts a local server (127.0.0.1 only, standard library only — still
no dependencies) and opens a page where you can browse to a project folder or an
`.apk`/`.aab`, scan it, filter the findings by severity and category, expand each
one for the why/fix, and download the report as JSON or Markdown. It can also
write the `playgate.toml` template for you when one is missing.

```bash
playgate ui --port 9000 --no-browser   # options, if you need them
```

### Standalone Windows app (`playgate.exe`)

For a no-terminal, no-Python experience you can build a single-file executable.
Double-clicked, it opens the web interface in the browser; run with arguments it
is the full CLI (`playgate.exe scan .`, `playgate.exe mcp`, …).

```bash
pip install pyinstaller
./packaging/build.ps1          # → dist/playgate.exe  (~8 MB, self-contained)
```

The build bundles `ui.html`, so the one file is all you need to ship. Nothing
about it phones home — it is the same offline scanner behind a window.

Exit code is `1` when a finding at or above `--fail-on` (default `high`) exists, so it drops straight into CI:

```yaml
- run: pip install playgate
- run: playgate scan . --fail-on critical
```

### The listing file

playgate cannot read Play Console, so about half the policy checks need you to write down what your store entry says:

```bash
playgate init          # writes a commented playgate.toml
```

```toml
title = "Aegis Tower Defense"
privacy_policy_url = "https://example.com/privacy"
account_creation = true
in_app_account_deletion = false
sells_digital_goods = true
uses_play_billing = true
data_safety_declared = ["advertising_id", "app_activity"]
developer_account_type = "personal"
first_release = true
```

Leave anything you are unsure about unset — the check is skipped rather than answered wrongly. Then playgate cross-checks it against your manifest: a permission with no matching Data Safety entry, an account-creating app with no deletion route, a title that will bounce at submission.

### Suppressing findings you have accepted

Findings you have consciously decided to accept can be silenced in `playgate.toml` so they stop failing CI, without hiding everything at that severity:

```toml
ignore = [
  "CODE-HTTP-URL:src/debug",        # a debug-only http endpoint
  "SEC-GENERIC:app/BuildConfig.kt", # a public identifier, not a secret
]
```

Each entry is a rule id, optionally scoped to a path substring so it only silences that one place. Run `playgate rules` for the ids. Suppressed findings are counted in a note, so the report stays honest about what was hidden.

### Only failing on new findings

For an existing project you do not want to fix in one go, record a baseline and then fail only on regressions:

```bash
playgate scan . --format json -o playgate-baseline.json   # once, commit this
playgate scan . --baseline playgate-baseline.json         # in CI: only new findings
```

## What it checks

**Security**

| Area | Examples |
| --- | --- |
| Manifest | debuggable, exported components with no permission guard, missing `android:exported` on API 31+, auto-backup with no exclusions, cleartext traffic, missing `foregroundServiceType` |
| Secrets | Google/AWS/Stripe/OpenAI/GitHub/Twilio/SendGrid/Mailgun/Google-OAuth keys, Sentry DSNs, Firebase DB & Supabase URLs, private key blocks, service-account JSON, JWTs, keystore passwords — **git-aware**: a value's severity depends on whether git actually tracks the file, and lookups (`getProperty()`, `getenv()`) are not mistaken for literals |
| Code | WebView JavaScript bridges and file access, disabled TLS validation, world-readable files, ECB/DES/RC4, MD5/SHA-1, credentials in logs, `http://` endpoints |
| Build | debuggable release, R8 disabled, very old `minSdk` |
| Cloud / BaaS | open Firebase Firestore/RTDB/Storage rules (incl. "test mode"), Supabase migrations that never enable RLS, and **coverage findings** when a service is used but its security config lives server-side and can't be seen locally |
| Unity | Mono backend, missing ARM64, game currency in `PlayerPrefs`, IAP with no receipt validation |
| Godot | sensitive export permissions, missing release keystore, unsigned exports |

**Google Play**

Target API level · restricted permissions that need a declaration (all-files access, `QUERY_ALL_PACKAGES`, SMS/call log, accessibility, device admin, background location, exact alarms, usage access, overlays, install packages) · privacy policy · account deletion · Data Safety vs manifest contradictions · advertising ID · Play Billing · title/description limits, emoji, promotional claims, keyword stuffing · closed-testing requirement for new personal accounts.

Compiled packages get the same treatment: an `.apk`'s binary-XML manifest and an `.aab`'s protobuf manifest are both decoded in-process (no `aapt`, no `bundletool`, no `androguard`), and string literals are pulled out of `classes.dex` so a key that only exists after the build is still found.

### The rejection score

A weighted sum of the policy findings, capped at 100, shown as `NONE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`.

It **ranks your work**. It is not a probability, and a clean report is not an approval — the rule set is fixed and finite, and Google reviews things no static tool can see (screenshots, whether your app actually works, whether your Data Safety form is honest).

## Dynamic agents

playgate's regex rules find *shapes*; they cannot find *intent* — the client-side trust flaw that drains a game's economy, a Data Safety form that quietly contradicts the SDK list, a key that is technically public but unrestricted. That judgement needs a model. playgate keeps the two apart on purpose: the deterministic checks stay in the CLI where they are testable and free, and a model is only asked for the things that genuinely need judgement.

The important part: **no API key.** playgate exposes its checks as tools over the [Model Context Protocol](https://modelcontextprotocol.io); your existing subscription — Claude Desktop, an MCP-capable IDE agent, or any other host that speaks MCP — supplies the reasoning. playgate is the hands; your subscription is the brain. Nothing leaves your machine that the client does not send.

### The MCP server

```bash
playgate mcp        # newline-delimited JSON-RPC 2.0 over stdio, stdlib only
```

It exposes four tools: `playgate_scan`, `playgate_detect`, `playgate_list_rules`, and `playgate_init_listing`. To connect **Claude Desktop**, add this to its `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "playgate": { "command": "python", "args": ["-m", "playgate.cli", "mcp"] }
  }
}
```

The repo also ships a `.mcp.json`, so any MCP client that reads one (Claude Code, and others) picks the server up automatically when opened here. Then just ask: *"audit this project before I upload it."*

### The Claude Code plugin

Installed as a plugin, playgate adds skills **and three dynamic agents** that run the scanner and then do the second pass a rule cannot:

- **`playgate-economy-auditor`** — follows every path that grants currency, an unlock, ad-removal or an entitlement, and asks whether a modified client could reach it without a server agreeing.
- **`playgate-secret-triage`** — sorts the flagged keys into live-and-dangerous, client-public-by-design, and placeholder, with a rotation plan for each. Never transmits the secret.
- **`playgate-policy-judge`** — reads the store listing and the real SDK list with a reviewer's eye: permission justification, Data Safety honesty, accessibility/device-admin risk.
- **`playgate-cloud-auditor`** — verifies the server-side config a static scan can't: logs into Firebase/Supabase/Cloudflare through your own CLIs and checks the live rules, RLS and bucket access.

```
/plugin marketplace add udogus986-ux/playgate
/plugin install playgate
```

Then ask, or spawn an agent directly: *"use the economy auditor on this game."*

## What it cannot see (and says so)

playgate reads local files. It does **not** run your app or log into your cloud
providers, so it cannot see:

- **Firebase / Firestore / RTDB / Storage rules**, **Supabase Row Level Security**, **Cloudflare WAF / Access / R2 public-access** — these live in the provider's console, not the repo. An open Firestore rule or a table with no RLS is invisible to a static scan.

Rather than stay quiet and read as a clean bill of health, playgate emits an
explicit **coverage finding** (`COV-FIREBASE-RULES`, `COV-SUPABASE-RLS`,
`COV-CLOUDFLARE`) whenever it detects one of these services but can't verify its
security locally — telling you exactly what to check by hand. To verify the live
config, use the **`playgate-cloud-auditor`** agent, which drives your own
authenticated `firebase` / `supabase` / `wrangler` CLIs (no key ever leaves your
machine).

## Standards & scope

playgate does not *implement* a security standard — it is a static pre-flight linter — but every security finding is **labelled** with the weakness class it maps to, and the labels ride along in the report (text, Markdown, JSON) and in SARIF (`external/cwe/cwe-NNN` tags, so GitHub code scanning shows a CWE badge). Run `playgate standards` to see the full mapping.

- **OWASP MASVS v2** (Mobile App Security Verification Standard) and **MASTG** static test cases
- **OWASP Mobile Top 10 (2024)** — e.g. M1 Improper Credential Usage, M5 Insecure Communication, M8 Security Misconfiguration, M10 Insufficient Cryptography
- **CWE** — e.g. CWE-798 (hard-coded credentials), CWE-295 (improper certificate validation), CWE-327 (broken crypto), CWE-926 (improper component export)
- **Output:** SARIF 2.1.0, with a CVSS-style `security-severity` per finding

What it deliberately is **not** — stated in every report so a clean run is never mistaken for a pass:

- **Not a certified/accredited assessment.** It does not claim MASVS L1/L2 verification.
- **Not DAST.** It does not run the app, so no runtime behaviour is covered.
- **Not SCA/CVE.** It does not scan dependencies for known CVEs.
- **A fixed, finite rule set.** Absence of a finding is *not* evidence of security — the equivalent of MASVS "not tested", not "pass".

## Limits

- It reads code and configuration. It does not run your app, so nothing here covers runtime behaviour.
- Policy requirements move. The target API level and testing rules are current as of **August 2026** and live in `playgate/rules/policy.py` under `REQUIREMENTS`. If Play Console disagrees with playgate, Play Console is right.
- Regex rules find shapes, not intent. Business-logic flaws — the ones that actually drain a game's economy — need a human or the plugin's second pass.
- Scan only what you own or have written permission to test.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The binary-XML and protobuf manifest decoders are tested against manifests built by encoders in `tests/axml_fixture.py` and `tests/proto_fixture.py`, so no sample APK or AAB needs to live in the repo. The MCP server has a full JSON-RPC handshake test in `tests/test_mcp.py`.

Adding a rule: write a function in `playgate/rules/`, decorate it with `@rule("area.name")`, yield `Finding`s. A rule that raises is caught and reported as a note, so it cannot break a scan. Every finding needs `evidence` — a literal quote — so the report can always be checked against the source.

## License

MIT.
