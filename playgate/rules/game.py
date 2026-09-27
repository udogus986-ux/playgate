"""Game-profile checks — the risks that are specific to games.

Only run when the project's profile is "game" (see playgate/profile.py). They
are engine-agnostic: Kotlin/Java (native, libGDX), GDScript (Godot), Dart
(Flutter/Flame) and JS. Unity C# has its own rules in unity.py.

What sets games apart: value (currency, unlocks, ad removal) is granted by the
client, so a modified client or an edited save hands it out for free; paid
randomized rewards carry a disclosure duty; young players change the ad rules;
and leaderboards invite cheating.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..models import Category, Finding, Location, ScanContext, Severity, SourceFile
from .base import rule

DOC_LOOTBOX = "https://support.google.com/googleplay/android-developer/answer/9858738"
DOC_FAMILIES_ADS = "https://support.google.com/googleplay/android-developer/answer/9893335"
DOC_BILLING_VERIFY = "https://developer.android.com/google/play/billing/security"
DOC_INTEGRITY = "https://developer.android.com/google/play/integrity"
DOC_CATEGORY = "https://developer.android.com/guide/topics/manifest/application-element#appCategory"

_CODE = (".kt", ".java", ".gd", ".dart", ".js", ".ts")
_VALUE_WORDS = (r"coin|gem|gold|cash|money|diamond|crystal|premium|vip|no_?ads|remove_?ads|unlock"
                r"|lives|energy|currency|credits|tokens?_balance|owned_")

_LOCAL_WRITES = [
    # Android SharedPreferences / DataStore-style putters
    re.compile(rf"""(?i)\bput(?:Int|Long|Float|Boolean|String)\s*\(\s*["']([^"']*(?:{_VALUE_WORDS})[^"']*)["']"""),
    # Flutter shared_preferences
    re.compile(rf"""(?i)\bset(?:Int|Double|Bool|String)\s*\(\s*["']([^"']*(?:{_VALUE_WORDS})[^"']*)["']"""),
    # Godot ConfigFile.set_value(section, key, value)
    re.compile(rf"""(?i)\bset_value\s*\(\s*["'][^"']*["']\s*,\s*["']([^"']*(?:{_VALUE_WORDS})[^"']*)["']"""),
    # Web / Cordova / Capacitor localStorage
    re.compile(rf"""(?i)\blocalStorage\s*\.\s*setItem\s*\(\s*["']([^"']*(?:{_VALUE_WORDS})[^"']*)["']"""),
]

_PURCHASE_HANDLING = re.compile(
    r"onPurchasesUpdated|PurchasesUpdatedListener|purchaseStream|InAppPurchase\.instance"
    r"|purchases_updated|GodotGooglePlayBilling|store\.when\(|acknowledgePurchase|consumeAsync"
)
_SERVER_VERIFY = re.compile(
    r"(?i)(?:verify|validat)\w*\s*\(?[^\n]{0,60}(?:purchase|receipt|token)"
    r"|purchaseToken[^\n]{0,120}(?:https?://|\bpost\b|api|functions|httpsCallable|retrofit|ktor|fetch\()"
    r"|androidpublisher"
)
_LOOTBOX = re.compile(r"(?i)\b\w*(?:loot_?box|gacha|mystery_?box|random_?reward|chest_?roll|lucky_?draw|summon_?pull)\w*\b")
_ADS_SDK = re.compile(
    r"play-services-ads|com\.google\.android\.gms\.ads|com\.unity3d\.ads|applovin|ironsource"
    r"|google_mobile_ads|GoogleMobileAds|MobileAds\.initialize"
)
_CHILD_DIRECTED = re.compile(
    r"setTagForChildDirectedTreatment|TAG_FOR_CHILD_DIRECTED_TREATMENT_TRUE|tagForChildDirectedTreatment"
    r"|setIsAgeRestrictedUser|SetIsAgeRestrictedUser|MAX_AD_CONTENT_RATING_G|maxAdContentRating"
    r"|setTagForUnderAgeOfConsent"
)
_SCORE_SUBMIT = re.compile(r"(?i)submitScore|LeaderboardsClient|postScore|submit_score|leaderboard\w*\.(?:submit|post)")
_INTEGRITY = re.compile(r"IntegrityManager|play-integrity|StandardIntegrity|requestIntegrityToken")
_CHEAT = re.compile(
    r"(?i)\b\w*(?:god_?mode|cheat_?menu|debug_?menu|unlock_?all|infinite_?(?:coins|money|gems|lives)|give_?all)\w*\b"
)


def _is_game(ctx: ScanContext) -> bool:
    return ctx.profile == "game"


def _code_files(ctx: ScanContext) -> Iterator[SourceFile]:
    for f in ctx.files:
        if f.path.suffix.lower() in _CODE and not f.relpath.endswith("(extracted strings)"):
            yield f


def _in_debug_or_test(f: SourceFile) -> bool:
    rel = "/" + f.relpath.replace("\\", "/").lower()
    return any(p in rel for p in ("/debug/", "/test/", "/tests/", "/androidtest/", "/sample"))


def _code_line(f: SourceFile, index: int) -> str:
    n = f.line_of(index)
    return f.lines[n - 1].strip() if n <= len(f.lines) else ""


def _all_text(ctx: ScanContext) -> str:
    return "\n".join(f.text for f in ctx.files if not f.relpath.endswith("(extracted strings)"))


@rule("game.local_currency")
def local_currency(ctx: ScanContext) -> Iterator[Finding]:
    if not _is_game(ctx):
        return
    seen: set[str] = set()
    for f in _code_files(ctx):
        for pattern in _LOCAL_WRITES:
            for m in pattern.finditer(f.text):
                key = m.group(1)
                if key in seen or _code_line(f, m.start()).startswith(("//", "#", "*")):
                    continue
                seen.add(key)
                yield Finding(
                    id="GAME-LOCAL-CURRENCY",
                    title=f"Game value stored only on the device: '{key}'",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    why=(
                        "Currency, unlocks and ad-removal flags saved to local preferences or a save "
                        "file can be edited with freely available tools on any rooted device or "
                        "emulator. If the game trusts this value on load, purchases become free."
                    ),
                    fix=(
                        "Keep the balance and entitlements on a server you control and treat the "
                        "local copy as a cache. If the game must work offline, sign the saved value "
                        "with a Keystore-backed key and re-verify it on load and on every spend."
                    ),
                    location=Location(f.relpath, f.line_of(m.start())),
                    evidence=m.group(0)[:140],
                    refs=(DOC_BILLING_VERIFY,),
                )


@rule("game.iap_verification")
def iap_without_server_check(ctx: ScanContext) -> Iterator[Finding]:
    if not _is_game(ctx):
        return
    handlers = [f for f in _code_files(ctx) if _PURCHASE_HANDLING.search(f.text)]
    if not handlers or _SERVER_VERIFY.search(_all_text(ctx)):
        return
    first = handlers[0]
    m = _PURCHASE_HANDLING.search(first.text)
    yield Finding(
        id="GAME-IAP-NO-SERVER-CHECK",
        title="Purchases are granted without server-side verification",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        why=(
            "The game handles purchase callbacks, but nothing in the project sends the purchase "
            "token to a server for verification. Billing-response spoofing tools are common on "
            "Android; without a server check they unlock paid items for free."
        ),
        fix=(
            "Send the purchaseToken to your backend, verify it with the Google Play Developer API "
            "(purchases.products/subscriptions), grant the item server-side, and only then "
            "acknowledge/consume. The client should never be the authority on what was bought."
        ),
        location=Location(first.relpath, first.line_of(m.start())),
        evidence=_code_line(first, m.start())[:160],
        refs=(DOC_BILLING_VERIFY,),
    )


@rule("game.loot_boxes")
def loot_box_odds(ctx: ScanContext) -> Iterator[Finding]:
    if not _is_game(ctx):
        return
    if ctx.listing and ctx.listing.discloses_loot_box_odds:
        return
    for f in _code_files(ctx):
        m = _LOOTBOX.search(f.text)
        if not m or _code_line(f, m.start()).startswith(("//", "#", "*")):
            continue
        how = ("set discloses_loot_box_odds = true in playgate.toml once they are"
               if ctx.listing else "declare it in playgate.toml (playgate init)")
        yield Finding(
            id="GAME-LOOTBOX-ODDS",
            title="Randomized rewards found — odds must be disclosed before purchase",
            severity=Severity.HIGH,
            category=Category.POLICY,
            why=(
                "The code has loot-box / gacha style rewards. Google Play requires games that sell "
                "randomized virtual items to show the odds of each item clearly before the player "
                "pays. Several regions add stricter rules or age limits for paid loot boxes."
            ),
            fix=(
                "Show per-item drop odds in the purchase screen before payment, keep them accurate "
                f"to the server-side tables, then {how}."
            ),
            location=Location(f.relpath, f.line_of(m.start())),
            evidence=m.group(0)[:80],
            refs=(DOC_LOOTBOX,),
            rejection_weight=20,
        )
        return


@rule("game.ads_children")
def ads_for_young_players(ctx: ScanContext) -> Iterator[Finding]:
    if not _is_game(ctx) or not (ctx.listing and ctx.listing.target_audience_children):
        return
    text = _all_text(ctx)
    ads = _ADS_SDK.search(text)
    if not ads or _CHILD_DIRECTED.search(text):
        return
    yield Finding(
        id="GAME-ADS-CHILDREN",
        title="Ads SDK in a game for children with no child-directed configuration",
        severity=Severity.HIGH,
        category=Category.POLICY,
        why=(
            "The game declares children in its target audience and ships an ads SDK, but never "
            "marks ad requests as child-directed or caps the content rating. Families policy "
            "requires Families-certified ad SDKs, no personalised ads and no advertising ID for "
            "children — violations lead to removal."
        ),
        fix=(
            "Use only Families-certified ad networks, set tagForChildDirectedTreatment / "
            "setTagForUnderAgeOfConsent and a maxAdContentRating of G, disable personalised ads, "
            "and remove the AD_ID permission."
        ),
        location=Location(ctx.listing.source_path),
        evidence=ads.group(0),
        refs=(DOC_FAMILIES_ADS,),
        rejection_weight=25,
    )


@rule("game.score_integrity")
def score_without_integrity(ctx: ScanContext) -> Iterator[Finding]:
    if not _is_game(ctx):
        return
    for f in _code_files(ctx):
        m = _SCORE_SUBMIT.search(f.text)
        if not m:
            continue
        if _INTEGRITY.search(_all_text(ctx)):
            return
        yield Finding(
            id="GAME-SCORE-NO-INTEGRITY",
            title="Scores are submitted with no device/app integrity check",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            why=(
                "Leaderboard scores come straight from the client and nothing checks the request "
                "comes from your unmodified game on a genuine device. Modded builds and emulators "
                "post impossible scores within days of launch."
            ),
            fix=(
                "Attach a Play Integrity token to score submissions, verify it server-side, and "
                "sanity-check scores (max per second, replay data) before accepting them."
            ),
            location=Location(f.relpath, f.line_of(m.start())),
            evidence=_code_line(f, m.start())[:160],
            refs=(DOC_INTEGRITY,),
        )
        return


@rule("game.cheat_leftovers")
def cheat_leftovers(ctx: ScanContext) -> Iterator[Finding]:
    if not _is_game(ctx):
        return
    for f in _code_files(ctx):
        if _in_debug_or_test(f):
            continue
        for m in _CHEAT.finditer(f.text):
            if _code_line(f, m.start()).startswith(("//", "#", "*")):
                continue
            yield Finding(
                id="GAME-CHEAT-LEFTOVER",
                title=f"Cheat or debug hook in shipping code: '{m.group(0)}'",
                severity=Severity.LOW,
                category=Category.SECURITY,
                why=(
                    "Cheat and debug hooks compiled into the release build are easy to find by "
                    "name and to trigger with a memory editor or a patched APK."
                ),
                fix="Move the hook into a debug-only source set or strip it with a build flag.",
                location=Location(f.relpath, f.line_of(m.start())),
                evidence=_code_line(f, m.start())[:160],
                refs=(DOC_INTEGRITY,),
            )
            break


@rule("game.category")
def missing_game_category(ctx: ScanContext) -> Iterator[Finding]:
    if not _is_game(ctx):
        return
    for manifest in ctx.manifests:
        app = manifest.application_attrs
        if (app.get("android:appCategory") or "").lower() == "game":
            continue
        if not manifest.source_path:
            continue
        yield Finding(
            id="GAME-NO-CATEGORY",
            title='Game manifest does not declare android:appCategory="game"',
            severity=Severity.LOW,
            category=Category.POLICY,
            why=(
                "The system uses appCategory to group apps for battery, data and Game Mode "
                "features; without it the game is treated as a generic app."
            ),
            fix='Add android:appCategory="game" to <application>.',
            location=Location(manifest.source_path),
            evidence="<application> without android:appCategory",
            refs=(DOC_CATEGORY,),
            rejection_weight=3,
        )
