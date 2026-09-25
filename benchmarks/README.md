# Benchmarks

Two different questions, answered two different ways.

## 1. Regression: does every rule still fire, and stay quiet when it should?

`benchmarks/corpus.py` is a labelled synthetic corpus: each vulnerable case
reproduces a vulnerability *class* shown by a well-known intentionally-insecure
app (DIVA, InsecureBankv2, OVAA, AndroGoat) as a minimal project and lists the
finding ids that must fire; benign cases are well-configured projects — including
the *safe* version of every flagged pattern — that must produce nothing.

```bash
python -m benchmarks.run            # print recall, false positives, rule coverage
python -m benchmarks.run --write    # refresh RESULTS.md
```

It runs in CI via `tests/test_benchmark.py`, which fails on any missed finding,
any false positive on a benign case, or any registered rule with no case.

**This is not an accuracy claim.** The corpus was written alongside the rules,
so 100% on it means "nothing regressed", not "playgate finds 100% of real bugs".

## 2. External: how does it do on apps it wasn't written against?

Run playgate on the published vulnerable apps and compare against their own
documented vulnerability lists. Download them yourself from their official
repositories (they are intentionally insecure — install them only on an
emulator):

| App | What it documents |
| --- | --- |
| OWASP MASTG / UnCrackable & MASTG test apps | the MASVS test cases |
| OVAA (Oversecured Vulnerable Android App) | intent redirection, deep links, FileProvider, WebView |
| InsecureBankv2 | exported components, weak crypto, insecure storage, logging |
| DIVA (Damn Insecure and Vulnerable App) | hardcoding, insecure storage, input validation |
| AndroGoat | a broad OWASP Mobile Top 10 sweep |

```bash
playgate scan path/to/ovaa            # the source project, if available
playgate scan path/to/app-release.apk # or the compiled package
playgate scan path/to/app.apk --format json -o ovaa.json
```

For each documented vulnerability, record **found / not found / not applicable
to static analysis** (runtime-only issues, server-side bugs). Report recall only
over the statically-detectable ones, and list every finding that isn't in the
app's documentation as a candidate false positive to review by hand. Publish the
table with the playgate version and the app commit — numbers without those are
not reproducible.
