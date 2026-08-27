---
name: android-audit
description: Audit an Android app — Kotlin/Java, Unity or Godot — for security issues and Google Play rejection risk before uploading. Use when the user asks to check an app for vulnerabilities, review a project before release, ask "will this get rejected", audit an APK/AAB, or prepare a Play submission.
---

# Android pre-release audit

Two passes, in this order. The order matters: the deterministic pass produces
facts, and facts are what the judgement pass reasons over.

## Pass 1 — run the scanner

```bash
playgate scan <path> --format json -o /tmp/playgate.json
```

If `playgate` is not on PATH, run it from the repo: `python3 -m playgate.cli`.
The target can be a project directory, an `.apk` or an `.aab`.

Read the JSON. Every finding carries `evidence` — a literal quote from the
file — so verify each one against the source before repeating it. **If a
finding does not reproduce, say so and drop it.** A security report that cries
wolf is worse than no report.

If the run reports `PLY-NO-LISTING`, roughly half the policy checks were
skipped. Offer to create `playgate.toml` (see the `play-rejection-check`
skill) rather than silently reporting a partial picture.

## Pass 2 — what the scanner structurally cannot see

Regex rules find *shapes*. They cannot find *intent*. Read the code for these,
because they are where the real damage tends to be:

**Client-side trust.** Follow every path that grants something valuable —
currency, an unlock, ad removal, a subscription entitlement, a score
submission. Ask: could a modified client just call this? If the grant happens
without a server confirming it, the check is decorative. This is the single
most common real flaw in indie mobile games, and no static rule finds it.

**Authorisation vs authentication.** The app knows *who* the user is. Does the
backend check *what they may do*? Look for endpoints that take an id from the
client and return the record for it. Trace one such call end-to-end.

**Broken object references.** Any request where an id, a filename or a path
comes from the client is a candidate. Try substituting another user's id
mentally and see what would stop it.

**Rate limiting and cost.** If the app calls a paid API — an LLM, maps,
SMS, push at volume — find where the request is bounded. If nothing bounds it,
an unmetered endpoint is a bill, not a breach, and it arrives faster.

**Third-party SDKs.** List every analytics, ad and crash SDK in the build
files. Each one collects data the developer must declare in Data Safety, and
several collect the advertising id by default.

**WebView content origin.** If a finding mentions a WebView, determine what it
loads. A bundled local page is a different risk from a remote URL, and the
report must say which.

## Reporting

Write the result as a Markdown file next to the project, and keep this shape:

1. **Verdict line** — can this ship, and what is the single thing to fix first.
2. **Blocking** — upload will fail or the listing is at risk.
3. **Should fix before release.**
4. **Worth knowing** — everything else.
5. **Checked and clean** — name what you actively verified and found fine.
   A report with no "clean" section reads as if you only looked for problems.

For each item: where it is, why it matters *for this app*, and the fix as
something the user can paste or apply. Skip generic advice.

## Rules of the road

- Never say "your app is secure" or "this will be approved". Say what was
  checked and what was found. The rule set is fixed and finite; absence of a
  finding is not evidence of absence.
- Severity is about consequence for *this* app. A hard-coded key in a demo
  branch is not the same finding as one in the release build. Adjust and
  explain when you do.
- If the user asks you to fix something, fix it in the code and re-run
  `playgate scan` to confirm the finding is gone.
- Only scan projects the user owns or has permission to test.
