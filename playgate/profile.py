"""Decide whether a project is a *game* or an *app*.

The two ship to the same stores but fail for different reasons: a game's value
lives in a client-side economy, purchases, loot boxes and ads aimed at young
players; an app's in accounts, reviewer access, data handling and whether it is
more than a wrapped website. Rules and reports use the profile to focus on the
right risks.

Order of precedence: an explicit override (CLI ``--profile`` or ``app_type`` in
playgate.toml), then evidence. Every decision records its signals so the report
can say *why* a project was treated as a game.
"""

from __future__ import annotations

import re

from .models import ProjectKind, ScanContext

_GAME_DEPS = {
    "com.google.android.gms:play-services-games": "Play Games Services dependency",
    "com.badlogicgames.gdx": "libGDX dependency",
    "org.cocos2dx": "Cocos2d-x dependency",
    "com.unity3d": "Unity library dependency",
}
_GAME_JS_DEPS = ("phaser", "pixi.js", "babylonjs", "@babylonjs/core", "three", "cocos-creator", "kaboom")
_GAME_DART_DEPS = ("flame", "bonfire", "forge2d")


def detect_profile(ctx: ScanContext, override: str = "auto") -> tuple[str, list[str]]:
    if override in {"game", "app"}:
        return override, [f"forced with --profile {override}"]
    listing = ctx.listing
    if listing and (listing.app_type or "").strip().lower() in {"game", "app"}:
        kind = listing.app_type.strip().lower()
        return kind, [f"app_type = \"{kind}\" in playgate.toml"]

    signals: list[str] = []
    if ctx.kind is ProjectKind.UNITY:
        signals.append("Unity project")
    elif ctx.kind is ProjectKind.GODOT:
        signals.append("Godot project")

    for manifest in ctx.manifests:
        app = manifest.application_attrs
        if (app.get("android:appCategory") or "").lower() == "game":
            signals.append('manifest android:appCategory="game"')
        if (app.get("android:isGame") or "").lower() == "true":
            signals.append('manifest android:isGame="true"')

    for f in ctx.files:
        name = f.path.name.lower()
        if name.endswith(".uproject"):
            signals.append("Unreal Engine project (.uproject)")
        elif name == "game.project":
            signals.append("Defold project (game.project)")
        elif name in {"build.gradle", "build.gradle.kts"} or name.endswith(".versions.toml"):
            low = f.text.lower()
            for dep, label in _GAME_DEPS.items():
                if dep in low and label not in signals:
                    signals.append(label)
        elif name == "package.json" and "node_modules" not in f.relpath:
            for dep in _GAME_JS_DEPS:
                if re.search(rf'"{re.escape(dep)}"\s*:', f.text):
                    signals.append(f"JS game engine dependency ({dep})")
        elif name == "pubspec.yaml":
            for dep in _GAME_DART_DEPS:
                if re.search(rf"(?m)^\s+{re.escape(dep)}\s*:", f.text):
                    signals.append(f"Flutter game engine dependency ({dep})")

    signals = list(dict.fromkeys(signals))
    return ("game", signals) if signals else ("app", ["no game engine or game category signals"])


# --------------------------------------------------------------------------
# Profile-specific risk areas, for reports: the same findings grouped by what
# matters for this kind of project. An id ending in "-" matches as a prefix.
# --------------------------------------------------------------------------

AREAS = {
    "game": [
        ("Economy & save data", ("UNI-PLAYERPREFS-ECONOMY", "GAME-LOCAL-CURRENCY", "CODE-PREFS-PLAINTEXT")),
        ("Purchases", ("UNI-IAP-NOVALIDATION", "GAME-IAP-NO-SERVER-CHECK", "PLY-BILLING")),
        ("Loot boxes & monetisation policy", ("GAME-LOOTBOX-ODDS",)),
        ("Ads & young players", ("GAME-ADS-CHILDREN", "PLY-ADID-CHILDREN", "DEX-ADID-READ")),
        ("Cheating & leaderboards", ("GAME-SCORE-NO-INTEGRITY", "GAME-CHEAT-LEFTOVER")),
        ("Binary hardening", ("UNI-MONO-BACKEND", "UNI-NO-ARM64", "BLD-NO-MINIFY", "DEX-DYNAMIC-CODE",
                              "BLD-DEBUGGABLE", "AND-DEBUGGABLE")),
        ("Secrets & supply chain", ("SEC-", "DEP-VULNERABLE")),
        ("Store setup", ("GAME-NO-CATEGORY", "PLY-TARGET-API", "GDT-", "PLY-REVIEW-ACCESS")),
    ],
    "app": [
        ("Accounts & reviewer access", ("PLY-REVIEW-ACCESS", "PLY-ACCOUNT-DELETION", "CODE-BIOMETRIC-NO-CRYPTO")),
        ("Data & privacy", ("PLY-DATA-SAFETY-GAP", "PLY-PRIVACY-POLICY", "APP-HEALTH-DECLARATION",
                            "AND-BACKUP", "CODE-PREFS-PLAINTEXT", "CODE-LOG-SECRET", "PLY-ADID-")),
        ("Network & WebView", ("CODE-TLS-", "AND-CLEARTEXT", "AND-NETSEC-CLEARTEXT", "CODE-HTTP-URL",
                               "CODE-WEBVIEW-", "DEX-WEBVIEW-", "TAINT-WEBVIEW-URL", "TAINT-JS-INJECTION")),
        ("Components & deep links", ("AND-EXPORTED-", "AND-DEEPLINK-NO-AUTOVERIFY", "TAINT-INTENT-REDIRECT",
                                     "AND-PENDINGINTENT-MUTABLE", "AND-BROADCAST-SENSITIVE", "AND-FILEPROVIDER-")),
        ("Store functionality & permissions", ("APP-WEBVIEW-WRAPPER", "PLY-PERM-", "PLY-TARGET-API")),
        ("Secrets & supply chain", ("SEC-", "DEP-VULNERABLE")),
    ],
}


def _matches(fid: str, pattern: str) -> bool:
    return fid.startswith(pattern) if pattern.endswith("-") else fid == pattern


def profile_areas(report) -> list[dict]:
    """[{area, status: 'clean'|'issues', findings: [ids]}] for the report's profile."""
    out = []
    ids = [f.id for f in report.sorted_findings()]
    for area, patterns in AREAS.get(report.profile, AREAS["app"]):
        hits = [i for i in ids if any(_matches(i, p) for p in patterns)]
        out.append({"area": area, "status": "issues" if hits else "clean", "findings": hits})
    return out
