"""App-profile checks, plus review-access for any project with a login.

Apps are rejected for different reasons than games: the reviewer can't get past
the login screen, the "app" is a website in a WebView, or it touches a regulated
data type (health) without the declaration. The WebView-wrapper and health
checks run for the app profile; reviewer access applies to games with accounts
too.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..models import Category, Finding, Location, ProjectKind, ScanContext, Severity
from .base import rule

DOC_ACCESS = "https://support.google.com/googleplay/android-developer/answer/15748846"
DOC_WEBVIEW_SPAM = "https://support.google.com/googleplay/android-developer/answer/9899034"
DOC_HEALTH = "https://support.google.com/googleplay/android-developer/answer/12991134"

_LOGIN = re.compile(
    r"signInWith\w*|FirebaseAuth|GoogleSignIn|CredentialManager|AuthUI|loginWith\w*"
    r"|supabase\.auth|\.auth\.signIn|Amplify\.Auth|OAuth2?Client",
)
_REMOTE_LOAD = re.compile(r"""\.loadUrl\s*\(\s*["'](https://[^"']+)["']""")


def _launcher_classes(ctx: ScanContext) -> set[str]:
    """Simple class names of MAIN/LAUNCHER activities."""
    from xml.etree import ElementTree as ET

    a = "{http://schemas.android.com/apk/res/android}"
    out: set[str] = set()
    for manifest in ctx.manifests:
        try:
            root = ET.fromstring(manifest.raw or "")
        except ET.ParseError:
            continue
        app = root.find("application")
        for node in (app.findall("activity") + app.findall("activity-alias")) if app is not None else []:
            for flt in node.findall("intent-filter"):
                cats = {c.get(f"{a}name") for c in flt.findall("category")}
                if "android.intent.category.LAUNCHER" in cats:
                    target = node.get(f"{a}targetActivity") or node.get(f"{a}name") or ""
                    out.add(target.rsplit(".", 1)[-1])
    return out


def _login_evidence(ctx: ScanContext) -> Location | None:
    for manifest in ctx.manifests:
        for c in manifest.components:
            short = c.name.rsplit(".", 1)[-1].lower()
            if c.kind in {"activity", "activity-alias"} and any(w in short for w in ("login", "signin", "auth")):
                return Location(manifest.source_path, c.line)
    for f in ctx.files:
        if f.path.suffix.lower() not in (".kt", ".java", ".dart", ".js", ".ts", ".swift"):
            continue
        m = _LOGIN.search(f.text)
        if m:
            return Location(f.relpath, f.line_of(m.start()))
    return None


@rule("app.review_access")
def reviewer_access(ctx: ScanContext) -> Iterator[Finding]:
    listing = ctx.listing
    if listing is None or listing.review_access_provided:
        return  # no listing → the release gate reports NEEDS-INFO instead
    where = _login_evidence(ctx)
    if where is None:
        return
    yield Finding(
        id="PLY-REVIEW-ACCESS",
        title="App has a login but no reviewer access is declared",
        severity=Severity.MEDIUM,
        category=Category.POLICY,
        why=(
            "The app requires signing in. If the reviewer can't get past the login screen, the "
            "submission is rejected with \"we could not access your app\" — one of the most "
            "common avoidable rejections."
        ),
        fix=(
            "In Play Console → App content → App access, provide a working test account (and any "
            "2FA/OTP bypass or instructions), then set review_access_provided = true in playgate.toml."
        ),
        location=where,
        evidence="login flow detected; review_access_provided not set",
        refs=(DOC_ACCESS,),
        rejection_weight=15,
    )


@rule("app.webview_wrapper")
def webview_wrapper(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.profile != "app" or ctx.kind is not ProjectKind.GRADLE:
        return
    code = [f for f in ctx.files
            if f.path.suffix.lower() in (".kt", ".java")
            and "/test/" not in "/" + f.relpath.replace("\\", "/").lower()
            and "/androidtest/" not in "/" + f.relpath.replace("\\", "/").lower()]
    if not code or len(code) > 4 or sum(len(f.lines) for f in code) > 250:
        return
    launchers = _launcher_classes(ctx)
    for f in code:
        m = _REMOTE_LOAD.search(f.text)
        if not m:
            continue
        # Only a wrapper if the *entry screen* is the website — a help page opened
        # from somewhere inside a real app is fine.
        if not any(re.search(rf"\bclass\s+{re.escape(name)}\b", f.text) for name in launchers):
            continue
        yield Finding(
            id="APP-WEBVIEW-WRAPPER",
            title="The app looks like a website wrapped in a WebView",
            severity=Severity.MEDIUM,
            category=Category.POLICY,
            why=(
                f"The project has {len(code)} source file(s) and loads {m.group(1)} into a WebView. "
                "Play's Minimum Functionality and Webview Spam policies reject apps whose main "
                "purpose is to display a website, unless the app adds real native value."
            ),
            fix=(
                "Add genuine app functionality (offline content, native features, notifications "
                "the site can't offer) or ship a Trusted Web Activity for a site you own. If this "
                "is a false positive, add APP-WEBVIEW-WRAPPER to ignore in playgate.toml."
            ),
            location=Location(f.relpath, f.line_of(m.start())),
            evidence=m.group(0)[:140],
            refs=(DOC_WEBVIEW_SPAM,),
            rejection_weight=20,
        )
        return


@rule("app.health_data")
def health_connect(ctx: ScanContext) -> Iterator[Finding]:
    perms = sorted({p for m in ctx.manifests for p in m.permissions if p.startswith("android.permission.health.")})
    if not perms:
        return
    yield Finding(
        id="APP-HEALTH-DECLARATION",
        title=f"Health Connect permissions require a Play declaration ({len(perms)} requested)",
        severity=Severity.MEDIUM,
        category=Category.POLICY,
        why=(
            "Reading or writing Health Connect data needs a completed Health Connect declaration "
            "in Play Console, a privacy policy covering health data, and use limited to the "
            "declared purposes. Requesting data types the app doesn't use is rejected."
        ),
        fix=(
            "Request only the data types a feature actually needs, fill the Health apps "
            "declaration (App content → Health apps), and declare Health and fitness in Data Safety."
        ),
        location=Location(ctx.manifests[0].source_path),
        evidence=", ".join(p.rsplit(".", 1)[-1] for p in perms[:6]),
        refs=(DOC_HEALTH,),
        rejection_weight=15,
    )
