"""Google Play policy and rejection-risk rules.

Nothing here talks to Play. The manifest and build files say what the app
*does*; the listing file says what the developer *claims*. Most of these rules
look for a contradiction between the two, plus the hard requirements that are
checked automatically at upload.

Requirement levels are current as of August 2026 and are the part of this file
most likely to age — see REQUIREMENTS below and the linked policy pages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from ..models import Category, Finding, Location, ScanContext, Severity
from .base import rule

DOC_TARGET_API = "https://support.google.com/googleplay/android-developer/answer/11926878"
DOC_PERMISSIONS = "https://support.google.com/googleplay/android-developer/answer/9888170"
DOC_DATA_SAFETY = "https://support.google.com/googleplay/android-developer/answer/10787469"
DOC_ACCOUNT_DELETION = "https://support.google.com/googleplay/android-developer/answer/13327111"
DOC_METADATA = "https://support.google.com/googleplay/android-developer/answer/9898842"
DOC_BILLING = "https://support.google.com/googleplay/android-developer/answer/10281818"
DOC_TESTING = "https://support.google.com/googleplay/android-developer/answer/14151465"
DOC_ACCESSIBILITY = "https://support.google.com/googleplay/android-developer/answer/10964491"
DOC_FAMILIES = "https://support.google.com/googleplay/android-developer/answer/9893335"
DOC_ADID = "https://support.google.com/googleplay/android-developer/answer/6048248"

# Target API level floors. Update these when Play moves the deadline.
REQUIREMENTS = {
    "standard": 36,      # Android 16, required for new apps and updates
    "wear_auto": 35,
    "tv_xr": 34,
    "discoverability": 35,  # existing apps below this lose visibility on new devices
    "deadline": "31 August 2026 (extension possible to 1 November 2026)",
    # Machine-readable: the last day this rule set was known to match Play policy.
    # Past this, requirements have very likely moved; see deadline_note().
    "reviewed_until": "2026-11-01",
}


def deadline_note(today) -> str | None:
    """A staleness warning once the policy horizon in REQUIREMENTS is behind us.

    ``today`` is a ``datetime.date``; injected rather than read here so the
    check is deterministic under test. Returns None while the rule set is fresh.
    """
    from datetime import date

    horizon = date.fromisoformat(REQUIREMENTS["reviewed_until"])
    if today <= horizon:
        return None
    return (
        f"playgate's Google Play rule set was last reviewed for {horizon.isoformat()} and it is "
        f"now {today.isoformat()}. Target API level, testing rules and declaration forms move "
        "over time — treat the policy findings as a starting point and confirm against Play "
        "Console. Update REQUIREMENTS in playgate/rules/policy.py."
    )


@dataclass(frozen=True)
class PermissionPolicy:
    permission: str
    label: str
    severity: Severity
    weight: int
    why: str
    fix: str
    ref: str


PERMISSION_POLICIES: list[PermissionPolicy] = [
    PermissionPolicy(
        "android.permission.QUERY_ALL_PACKAGES", "See all installed apps",
        Severity.HIGH, 25,
        "QUERY_ALL_PACKAGES is a restricted permission. Play only allows it for a short list of "
        "app types (launchers, antivirus, accessibility, file managers) and rejects the rest.",
        "Replace it with a <queries> element naming the specific packages or intents you need. "
        "If you truly qualify, submit the permission declaration in Play Console.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.MANAGE_EXTERNAL_STORAGE", "All files access",
        Severity.HIGH, 25,
        "All-files access is granted only to apps whose core function needs broad file "
        "management. Requesting it for convenience is a standard rejection.",
        "Use the Storage Access Framework or scoped MediaStore access instead, and remove the "
        "permission.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.READ_SMS", "Read SMS", Severity.HIGH, 30,
        "SMS and Call Log permissions are limited to the app the user has set as the default "
        "handler for that function. Everything else is rejected.",
        "Use the SMS Retriever API for OTP flows — it needs no permission at all.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.RECEIVE_SMS", "Receive SMS", Severity.HIGH, 30,
        "Part of the restricted SMS group; allowed only for a default SMS handler.",
        "Use the SMS Retriever API for verification codes.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.READ_CALL_LOG", "Read call log", Severity.HIGH, 30,
        "Part of the restricted Call Log group; allowed only for a default phone/dialer handler.",
        "Remove the permission unless the app is genuinely a dialer and you file the declaration.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.BIND_ACCESSIBILITY_SERVICE", "Accessibility service",
        Severity.HIGH, 30,
        "Play allows AccessibilityService only where it serves users with disabilities. Using it "
        "to automate, monitor or block other apps is one of the most consistently rejected and "
        "retroactively removed patterns on the store.",
        "If the app is an accessibility tool, add a clear in-app disclosure, fill the "
        "IsAccessibilityTool declaration and the Play Console form, and record a demo video. "
        "If it is a focus/blocker/automation app, expect rejection and design around "
        "UsageStatsManager plus user-initiated actions instead.",
        DOC_ACCESSIBILITY,
    ),
    PermissionPolicy(
        "android.permission.BIND_DEVICE_ADMIN", "Device admin / device owner",
        Severity.HIGH, 25,
        "Device administration APIs are restricted to genuine enterprise management use, and "
        "Play scrutinises consumer apps that ask for lock/wipe powers.",
        "Document the enterprise use case in the Play Console declaration, and make sure the "
        "listing clearly presents the app as a device management tool.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.PACKAGE_USAGE_STATS", "Usage access",
        Severity.MEDIUM, 15,
        "Usage access reveals which apps the user opens and for how long. It is permitted, but "
        "requires a prominent disclosure and a matching Data Safety entry.",
        "Add an in-app disclosure before sending the user to the usage-access settings screen, "
        "and declare 'App activity' in Data Safety.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.SYSTEM_ALERT_WINDOW", "Draw over other apps",
        Severity.MEDIUM, 15,
        "Overlays are a common abuse vector, so Play reviews them closely and rejects overlays "
        "that obscure consent, ads or system UI.",
        "Only draw overlays after an explicit user action, never over permission dialogs or ads, "
        "and explain the use in the listing.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.SCHEDULE_EXACT_ALARM", "Exact alarms",
        Severity.MEDIUM, 15,
        "From Android 13 exact alarms need a Play declaration; the permission is intended for "
        "alarm clocks, calendars and similar user-facing timing.",
        "If timing can be approximate, use setInexactRepeating or WorkManager and drop the "
        "permission. Otherwise file the exact-alarm declaration.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.REQUEST_INSTALL_PACKAGES", "Install other apps",
        Severity.HIGH, 25,
        "Only a narrow set of app types may install other packages; for most apps this reads as "
        "sideloading and is rejected.",
        "Remove it and distribute any additional components through Play.",
        DOC_PERMISSIONS,
    ),
    PermissionPolicy(
        "android.permission.ACCESS_BACKGROUND_LOCATION", "Background location",
        Severity.HIGH, 25,
        "Background location requires a declaration and a demo video, and is refused when the "
        "feature works with foreground location alone.",
        "Ask for foreground location only, or file the background-location declaration with a "
        "video showing the in-app disclosure and the feature that needs it.",
        DOC_PERMISSIONS,
    ),
]

PROMOTIONAL_TERMS = re.compile(
    r"(?i)\b(?:#1|no\.?\s*1|best|top\s+rated|free\s+download|download\s+now|100%\s*free"
    r"|guaranteed|new\b.{0,4}\bnew|sale|discount|cheap)\b"
)
EMOJI = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF←-⇿⬀-⯿]"
)

TITLE_MAX = 30
SHORT_DESC_MAX = 80
FULL_DESC_MAX = 4000

# permission -> Data Safety category it implies
DATA_SAFETY_IMPLICATIONS = {
    "android.permission.ACCESS_FINE_LOCATION": "location",
    "android.permission.ACCESS_COARSE_LOCATION": "location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "location",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.RECORD_AUDIO": "audio",
    "android.permission.CAMERA": "photos_videos",
    "android.permission.READ_MEDIA_IMAGES": "photos_videos",
    "android.permission.READ_MEDIA_VIDEO": "photos_videos",
    "android.permission.READ_CALENDAR": "calendar",
    "android.permission.PACKAGE_USAGE_STATS": "app_activity",
    "android.permission.BODY_SENSORS": "health_fitness",
    "android.permission.ACTIVITY_RECOGNITION": "health_fitness",
    "com.google.android.gms.permission.AD_ID": "advertising_id",
}


def _all_permissions(ctx: ScanContext) -> set[str]:
    perms: set[str] = set()
    for manifest in ctx.manifests:
        perms.update(manifest.permissions)
    return perms


@rule("policy.target_api")
def target_api_level(ctx: ScanContext) -> Iterator[Finding]:
    target = ctx.build.target_sdk
    if target is None:
        yield Finding(
            id="PLY-TARGET-UNKNOWN",
            title="Target SDK level could not be determined",
            severity=Severity.MEDIUM,
            category=Category.POLICY,
            why=(
                "Target API level is the single most common automatic upload rejection. playgate "
                "could not find targetSdk in the build files it read."
            ),
            fix=(
                "Confirm the effective value with `./gradlew :app:dependencies` or "
                "`aapt dump badging app.apk | grep targetSdk`, and set it explicitly."
            ),
            location=Location(ctx.build.source_path),
            refs=(DOC_TARGET_API,),
            rejection_weight=10,
        )
        return

    required = REQUIREMENTS["standard"]
    if target >= required:
        return

    if target < REQUIREMENTS["discoverability"]:
        severity, weight = Severity.CRITICAL, 45
        extra = (
            f" Below API {REQUIREMENTS['discoverability']} the app also stops being discoverable "
            "to new users on newer Android versions."
        )
    else:
        severity, weight = Severity.HIGH, 35
        extra = ""

    yield Finding(
        id="PLY-TARGET-API",
        title=f"targetSdk {target} is below the required API {required}",
        severity=severity,
        category=Category.POLICY,
        why=(
            f"Play requires new apps and updates to target Android 16 (API {required}). Uploads "
            f"below that are refused. Deadline: {REQUIREMENTS['deadline']}." + extra
        ),
        fix=(
            f"Set targetSdk = {required}, then work through the behaviour changes for every API "
            "level you skipped — foreground service types, photo picker, predictive back and "
            "exact alarms are the usual breakages. Request the extension in Play Console if you "
            "need more time."
        ),
        location=Location(ctx.build.source_path),
        evidence=f"targetSdk = {target}",
        refs=(DOC_TARGET_API,),
        rejection_weight=weight,
    )


@rule("policy.restricted_permissions")
def restricted_permissions(ctx: ScanContext) -> Iterator[Finding]:
    perms = _all_permissions(ctx)
    short = {p.rsplit(".", 1)[-1] for p in perms}
    for policy in PERMISSION_POLICIES:
        if policy.permission.rsplit(".", 1)[-1] not in short:
            continue
        yield Finding(
            id=f"PLY-PERM-{policy.permission.rsplit('.', 1)[-1]}",
            title=f"Restricted permission requires a Play declaration: {policy.label}",
            severity=policy.severity,
            category=Category.POLICY,
            why=policy.why,
            fix=policy.fix,
            location=Location(ctx.manifests[0].source_path if ctx.manifests else None),
            evidence=policy.permission,
            refs=(policy.ref,),
            rejection_weight=policy.weight,
        )


@rule("policy.privacy_policy")
def privacy_policy(ctx: ScanContext) -> Iterator[Finding]:
    listing = ctx.listing
    if listing is None:
        return
    url = (listing.privacy_policy_url or "").strip()
    if url.startswith("https://"):
        return
    yield Finding(
        id="PLY-PRIVACY-POLICY",
        title="No valid privacy policy URL declared",
        severity=Severity.CRITICAL,
        category=Category.POLICY,
        why=(
            "Every app on Play must link a privacy policy, whether or not it collects data. A "
            "missing, http-only or dead link is an automatic block."
        ),
        fix=(
            "Publish a policy at a stable https URL that names your app, states what is "
            "collected and how it is deleted, and add it in Play Console > App content."
        ),
        location=Location(listing.source_path),
        evidence=f"privacy_policy_url = {url or '(missing)'}",
        refs=(DOC_DATA_SAFETY,),
        rejection_weight=30,
    )


@rule("policy.account_deletion")
def account_deletion(ctx: ScanContext) -> Iterator[Finding]:
    listing = ctx.listing
    if listing is None or not listing.account_creation:
        return
    has_in_app = bool(listing.in_app_account_deletion)
    has_web = bool((listing.account_deletion_url or "").strip().startswith("https://"))
    if has_in_app and has_web:
        return
    missing = []
    if not has_in_app:
        missing.append("an in-app deletion path")
    if not has_web:
        missing.append("a publicly reachable web deletion URL")
    yield Finding(
        id="PLY-ACCOUNT-DELETION",
        title="App creates accounts without a complete deletion route",
        severity=Severity.HIGH,
        category=Category.POLICY,
        why=(
            "Apps that let users create an account must offer deletion both inside the app and "
            "through a web link that works without installing the app. Missing "
            + " and ".join(missing) + "."
        ),
        fix=(
            "Add a delete-account screen in the app, publish a web deletion request page, and "
            "enter both in Play Console > App content > Data deletion."
        ),
        location=Location(listing.source_path),
        refs=(DOC_ACCOUNT_DELETION,),
        rejection_weight=25,
    )


@rule("policy.data_safety_consistency")
def data_safety_consistency(ctx: ScanContext) -> Iterator[Finding]:
    listing = ctx.listing
    if listing is None or not listing.data_safety_declared:
        return
    declared = {d.strip().lower().replace(" ", "_") for d in listing.data_safety_declared}
    perms = _all_permissions(ctx)
    short_map = {p.rsplit(".", 1)[-1]: p for p in perms}

    for permission, category in DATA_SAFETY_IMPLICATIONS.items():
        short = permission.rsplit(".", 1)[-1]
        if short not in short_map:
            continue
        if category in declared:
            continue
        yield Finding(
            id="PLY-DATA-SAFETY-GAP",
            title=f"'{category}' is not declared in Data Safety but {short} is requested",
            severity=Severity.HIGH,
            category=Category.POLICY,
            why=(
                "Play cross-checks the Data Safety form against what the app can actually do. A "
                "permission with no matching declaration is treated as an inaccurate disclosure, "
                "which suspends the app rather than just rejecting the update."
            ),
            fix=(
                f"Either declare '{category}' in the Data Safety form with an accurate purpose, "
                f"or remove {short} from the manifest if the feature was dropped. Remember that "
                "third-party SDKs count as collection too."
            ),
            location=Location(ctx.manifests[0].source_path if ctx.manifests else None),
            evidence=permission,
            refs=(DOC_DATA_SAFETY,),
            rejection_weight=20,
        )


@rule("policy.ad_id")
def advertising_id(ctx: ScanContext) -> Iterator[Finding]:
    listing = ctx.listing
    perms = _all_permissions(ctx)
    has_ad_id = any(p.endswith("AD_ID") for p in perms)
    target = ctx.build.target_sdk or 0

    if listing is not None and listing.uses_ads and not has_ad_id and target >= 33:
        yield Finding(
            id="PLY-ADID-MISSING",
            title="App declares ads but no AD_ID permission",
            severity=Severity.MEDIUM,
            category=Category.POLICY,
            why=(
                "Targeting API 33+, an app must declare com.google.android.gms.permission.AD_ID "
                "to receive the advertising ID. Without it the ad SDK silently gets a zeroed ID "
                "and fill rate collapses."
            ),
            fix=(
                "Add <uses-permission android:name=\"com.google.android.gms.permission.AD_ID\"/> "
                "and declare advertising ID use in Data Safety."
            ),
            location=Location(ctx.manifests[0].source_path if ctx.manifests else None),
            refs=(DOC_ADID,),
            rejection_weight=10,
        )

    if listing is not None and listing.target_audience_children and has_ad_id:
        yield Finding(
            id="PLY-ADID-CHILDREN",
            title="Advertising ID requested in an app targeted at children",
            severity=Severity.CRITICAL,
            category=Category.POLICY,
            why=(
                "Apps whose target audience includes children must not transmit the advertising "
                "ID. Under Families policy this is a removal, not a warning."
            ),
            fix=(
                "Remove the AD_ID permission, and use only ad SDKs certified for the Families "
                "programme with personalised ads disabled."
            ),
            location=Location(ctx.manifests[0].source_path if ctx.manifests else None),
            evidence="com.google.android.gms.permission.AD_ID",
            refs=(DOC_FAMILIES,),
            rejection_weight=35,
        )


@rule("policy.billing")
def play_billing(ctx: ScanContext) -> Iterator[Finding]:
    listing = ctx.listing
    if listing is None or not listing.sells_digital_goods:
        return
    if listing.uses_play_billing:
        return
    yield Finding(
        id="PLY-BILLING",
        title="Digital goods are sold without Google Play Billing",
        severity=Severity.CRITICAL,
        category=Category.POLICY,
        why=(
            "In-app digital content and subscriptions must go through Play Billing. Routing them "
            "to an external processor is one of the fastest ways to lose the listing."
        ),
        fix=(
            "Integrate the Play Billing Library for anything consumed inside the app. Physical "
            "goods and services consumed outside the app are the exception."
        ),
        location=Location(listing.source_path),
        refs=(DOC_BILLING,),
        rejection_weight=35,
    )


@rule("policy.listing_text")
def listing_text(ctx: ScanContext) -> Iterator[Finding]:
    listing = ctx.listing
    if listing is None:
        return
    loc = Location(listing.source_path)

    title = (listing.title or "").strip()
    if title:
        if len(title) > TITLE_MAX:
            yield Finding(
                id="PLY-TITLE-LENGTH",
                title=f"App title is {len(title)} characters (limit {TITLE_MAX})",
                severity=Severity.MEDIUM,
                category=Category.POLICY,
                why="Titles longer than 30 characters are rejected outright at submission.",
                fix=f"Trim the title to {TITLE_MAX} characters; move the descriptive part to the short description.",
                location=loc,
                evidence=title,
                refs=(DOC_METADATA,),
                rejection_weight=15,
            )
        if EMOJI.search(title):
            yield Finding(
                id="PLY-TITLE-EMOJI",
                title="App title contains emoji or decorative symbols",
                severity=Severity.MEDIUM,
                category=Category.POLICY,
                why="Play's metadata policy bans emoji, repeated punctuation and decorative characters in the title.",
                fix="Remove the symbols and keep the title to plain text.",
                location=loc,
                evidence=title,
                refs=(DOC_METADATA,),
                rejection_weight=15,
            )
        if title.isupper() and len(title) > 4:
            yield Finding(
                id="PLY-TITLE-CAPS",
                title="App title is entirely uppercase",
                severity=Severity.LOW,
                category=Category.POLICY,
                why="All-caps titles are treated as attention-grabbing formatting and are refused unless the name is a real acronym.",
                fix="Use normal capitalisation.",
                location=loc,
                evidence=title,
                refs=(DOC_METADATA,),
                rejection_weight=8,
            )

    for field_name, value, limit in (
        ("short_description", listing.short_description, SHORT_DESC_MAX),
        ("full_description", listing.full_description, FULL_DESC_MAX),
    ):
        text = (value or "").strip()
        if text and len(text) > limit:
            yield Finding(
                id=f"PLY-{field_name.upper().replace('_', '-')}-LENGTH",
                title=f"{field_name.replace('_', ' ')} is {len(text)} characters (limit {limit})",
                severity=Severity.MEDIUM,
                category=Category.POLICY,
                why="The field is rejected at submission when it exceeds the limit.",
                fix=f"Cut it to {limit} characters.",
                location=loc,
                refs=(DOC_METADATA,),
                rejection_weight=10,
            )

    blob = " ".join(x for x in (title, listing.short_description, listing.full_description) if x)
    promo = {m.group(0).lower() for m in PROMOTIONAL_TERMS.finditer(blob)}
    if promo:
        yield Finding(
            id="PLY-PROMO-TERMS",
            title="Store listing uses promotional or ranking claims",
            severity=Severity.LOW,
            category=Category.POLICY,
            why=(
                "Play's metadata policy forbids performance claims, price/promotion text and "
                "ranking assertions in the listing: " + ", ".join(sorted(promo))
            ),
            fix="Describe what the app does instead. Move any promotion into the app itself.",
            location=loc,
            evidence=", ".join(sorted(promo))[:160],
            refs=(DOC_METADATA,),
            rejection_weight=8,
        )

    full = (listing.full_description or "").lower()
    if full:
        words = re.findall(r"[a-zçğıöşü]{4,}", full)
        if len(words) >= 25:
            top, count = max(((w, words.count(w)) for w in set(words)), key=lambda x: x[1])
            # Both conditions matter: a high ratio alone trips on short text,
            # a high count alone trips on a long, legitimately repetitive one.
            if count >= 5 and count / len(words) > 0.05:
                yield Finding(
                    id="PLY-KEYWORD-STUFFING",
                    title=f"Full description repeats '{top}' {count} times",
                    severity=Severity.LOW,
                    category=Category.POLICY,
                    why=(
                        f"'{top}' is {count / len(words):.0%} of the description. Repeating a "
                        "keyword to influence search is explicitly listed as prohibited metadata."
                    ),
                    fix="Rewrite so the keyword appears naturally a handful of times.",
                    location=loc,
                    refs=(DOC_METADATA,),
                    rejection_weight=8,
                )


@rule("policy.closed_testing")
def closed_testing(ctx: ScanContext) -> Iterator[Finding]:
    listing = ctx.listing
    if listing is None:
        return
    if (listing.developer_account_type or "").lower() != "personal":
        return
    if not listing.first_release:
        return
    yield Finding(
        id="PLY-CLOSED-TESTING",
        title="First release from a personal account needs a closed test first",
        severity=Severity.HIGH,
        category=Category.POLICY,
        why=(
            "Personal developer accounts created recently must run a closed test with at least "
            "12 testers who stay opted in for 14 continuous days before production access is "
            "granted. Testers dropping out resets the clock."
        ),
        fix=(
            "Start the closed test now — the 14 days are the long pole. Recruit more than 12 so "
            "attrition does not restart it, and use the closed track, not internal testing."
        ),
        location=Location(listing.source_path),
        refs=(DOC_TESTING,),
        rejection_weight=20,
    )


@rule("policy.listing_missing")
def listing_missing(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.listing is not None:
        return
    yield Finding(
        id="PLY-NO-LISTING",
        title="No listing declaration file — store-side policy checks were skipped",
        severity=Severity.INFO,
        category=Category.POLICY,
        why=(
            "playgate cannot read Play Console. Without a playgate.toml describing your title, "
            "descriptions, privacy policy and declarations, roughly half of the rejection "
            "checks cannot run."
        ),
        fix="Run `playgate init` to write a template playgate.toml, then fill it in.",
        location=Location(),
        refs=(DOC_METADATA,),
    )
