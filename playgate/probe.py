"""`playgate probe` — turn the manifest into a dynamic test plan.

Static analysis says a component is *exported*; only running it says whether it
is actually reachable and what it does with a hostile intent. This module
generates the adb commands to try each exported surface on the developer's own
emulator or device. It never runs them: execution is a deliberate step for the
developer (or the playgate-dynamic-tester agent acting for them).
"""

from __future__ import annotations

import json
import shlex
from dataclasses import asdict, dataclass
from xml.etree import ElementTree as ET

from .models import Manifest, ScanContext

_A = "{http://schemas.android.com/apk/res/android}"


@dataclass
class Probe:
    kind: str            # activity | service | receiver | provider | deeplink
    component: str       # fully-qualified name (or URI for a deep link)
    guarded_by: str | None
    command: str
    expect: str          # what a *safe* result looks like


def _fqcn(package: str | None, name: str) -> str:
    if name.startswith(".") and package:
        return package + name
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def _exported(component, min_sdk: int | None) -> bool:
    if component.exported is not None:
        return component.exported
    if component.kind == "provider":
        return (min_sdk or 0) < 17
    return component.has_intent_filter


def _deep_links(manifest: Manifest) -> list[tuple[str, str]]:
    """(activity, sample URI) for every VIEW+BROWSABLE intent filter."""
    out: list[tuple[str, str]] = []
    if not manifest.raw:
        return out
    try:
        root = ET.fromstring(manifest.raw)
    except ET.ParseError:
        return out
    app = root.find("application")
    if app is None:
        return out
    for node in app.findall("activity") + app.findall("activity-alias"):
        for flt in node.findall("intent-filter"):
            actions = {a.get(f"{_A}name") for a in flt.findall("action")}
            cats = {c.get(f"{_A}name") for c in flt.findall("category")}
            if "android.intent.action.VIEW" not in actions or "android.intent.category.BROWSABLE" not in cats:
                continue
            for data in flt.findall("data"):
                scheme = data.get(f"{_A}scheme")
                if not scheme:
                    continue
                host = data.get(f"{_A}host") or "example"
                path = data.get(f"{_A}path") or data.get(f"{_A}pathPrefix") or "/"
                uri = f"{scheme}://{host}{path}"
                out.append((node.get(f"{_A}name") or "?", uri + ("&" if "?" in uri else "?") + "playgate_probe=1"))
    return out


def build_plan(ctx: ScanContext) -> list[Probe]:
    probes: list[Probe] = []
    min_sdk = ctx.build.min_sdk
    for manifest in ctx.manifests:
        pkg = manifest.package
        for c in manifest.components:
            if not _exported(c, min_sdk):
                continue
            name = _fqcn(pkg, c.name)
            target = shlex.quote(f"{pkg}/{name}") if pkg else shlex.quote(name)
            if c.kind in {"activity", "activity-alias"}:
                cmd = f"adb shell am start -W -n {target} --es playgate_probe unexpected_value"
                expect = "Launches only if it is a real entry point; must not skip auth or crash on odd extras."
            elif c.kind == "service":
                cmd = f"adb shell am start-foreground-service -n {target} --es playgate_probe 1"
                expect = "Permission Denial (guarded), or a no-op — never privileged work for an unknown caller."
            elif c.kind == "receiver":
                cmd = f"adb shell am broadcast -n {target} --es playgate_probe 1"
                expect = "Permission Denial, or the receiver ignores the unauthenticated broadcast."
            else:  # provider
                authority = (c.extra.get("android:authorities") or "").split(";")[0]
                if not authority:
                    continue
                cmd = f"adb shell content query --uri {shlex.quote('content://' + authority + '/')}"
                expect = "Permission Denial or SecurityException — returning rows means any app can read them."
            probes.append(Probe(c.kind, name, c.permission, cmd, expect))
        for activity, uri in _deep_links(manifest):
            probes.append(Probe(
                "deeplink", uri, None,
                f"adb shell am start -W -a android.intent.action.VIEW -d {shlex.quote(uri)}"
                + (f" {shlex.quote(pkg)}" if pkg else ""),
                f"Opens {activity} with the link validated; unknown parameters are ignored, not trusted.",
            ))
    return probes


def to_text(ctx: ScanContext, probes: list[Probe]) -> str:
    pkg = next((m.package for m in ctx.manifests if m.package), None) or "<package>"
    lines = [
        "",
        f"playgate probe — dynamic test plan for {pkg}",
        "Run these against YOUR app on an emulator or test device you control.",
        "Install the build first:  adb install -r app-debug.apk   (or the release build you are checking)",
        "",
    ]
    if not probes:
        lines.append("Nothing is exported — there is no external surface to probe.")
        return "\n".join(lines) + "\n"
    for p in probes:
        guard = f"guarded by {p.guarded_by}" if p.guarded_by else "NO permission guard"
        lines.append(f"[{p.kind}] {p.component}   ({guard})")
        lines.append(f"  $ {p.command}")
        lines.append(f"  safe result: {p.expect}")
        lines.append("")
    lines.append("Watch `adb logcat` while running them; a crash or a stack trace is a finding too.")
    return "\n".join(lines) + "\n"


def to_json(probes: list[Probe]) -> str:
    return json.dumps([asdict(p) for p in probes], indent=2)
