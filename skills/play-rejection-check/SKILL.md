---
name: play-rejection-check
description: Estimate whether a Google Play submission will be rejected, and fix what would cause it. Use when the user asks about Play policy, store listing rules, target API level, Data Safety, permission declarations, closed testing requirements, or says their app was rejected and asks why.
---

# Play rejection check

## 1. Get the declaration file

Most policy rejections come from the store side, which is not in the code.
`playgate.toml` is where the user writes down what Play Console says.

If it does not exist, run `playgate init` and then fill it in **by asking the
user** — do not guess. Ask in one batch, not one question at a time:

- App title, short description, full description (paste from Play Console)
- Privacy policy URL
- Does the app let users create accounts? Is there in-app deletion? A web
  deletion URL?
- Ads? Digital goods or subscriptions? Play Billing integrated?
- Target audience — does it include children?
- Which Data Safety categories are declared
- Personal or organisation developer account; is this the first production
  release from it?

Anything the user does not know, leave unset. An unset field skips its check;
a guessed field produces a wrong answer confidently, which is worse.

## 2. Run the scanner

```bash
playgate scan <path> --format md -o play-review.md
```

The report gives a rejection-risk band and a weighted score. **Explain the
score as ranking, not probability.** It orders the work; it does not predict
Google's decision.

## 3. The checks that need a human read

**Screenshots and feature graphic.** The scanner never sees them. Ask whether
they show real in-app content — no device frames with marketing text, no
screenshots of a different app, no claims baked into the image.

**Functionality.** Broken or thin functionality is a leading rejection cause.
Ask whether every button in the build works, whether the app has content
beyond a wrapped website or PDF, and whether it runs on a fresh install with
no cached state.

**Permission justification.** For each restricted permission the scanner
flagged, ask what feature needs it. Frequently the answer is "an SDK I removed"
or "I was testing" — in which case deleting the permission is the fix, and it
is faster than filing a declaration.

**Accessibility and device-admin apps specifically.** If the app uses
`AccessibilityService` or `DevicePolicyManager`, this is the highest-risk
category on the store. Focus, blocking, parental-control and automation apps
built on AccessibilityService are refused or removed regularly. Be direct with
the user about that before they spend weeks polishing. Where the app is genuinely
an accessibility tool, the requirements are: `isAccessibilityTool="true"`, a
prominent in-app disclosure before the service is enabled, a matching Play
Console declaration, and a demo video.

**Data Safety honesty.** Walk the SDK list from the build files, not the
developer's memory. An analytics or ad SDK collects data whether or not the
developer wrote the collection code, and an inaccurate Data Safety form gets
the app suspended rather than merely rejected.

## 4. Deliver

Order everything by *what stops the upload*, then *what a reviewer rejects*,
then *what a reviewer might question*. For each: the exact change, and where in
Play Console it goes.

If the user has already been rejected, ask for the exact wording of the
rejection email — the policy name in it maps to a specific fix, and guessing
from the app alone wastes an appeal.

## Rules of the road

- Policy requirements move. The target API level, testing rules and declaration
  forms in the rule set carry a date; if the check looks stale against what the
  user sees in Play Console, trust Play Console and tell the user the rule set
  needs updating.
- Never promise approval. Report what was checked.
