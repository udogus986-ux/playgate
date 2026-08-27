"""Security rules that read AndroidManifest."""

from __future__ import annotations

import re
from typing import Iterator

from ..models import Category, Finding, Location, Manifest, ManifestComponent, ScanContext, Severity
from .base import rule

DOC_EXPORTED = "https://developer.android.com/guide/topics/manifest/activity-element#exported"
DOC_API31 = "https://developer.android.com/about/versions/12/behavior-changes-12#exported"
DOC_NETSEC = "https://developer.android.com/privacy-and-security/security-config"
DOC_BACKUP = "https://developer.android.com/guide/topics/data/autobackup"
DOC_FGS = "https://developer.android.com/about/versions/14/changes/fgs-types-required"


def _effective_exported(component: ManifestComponent, min_sdk: int | None) -> bool:
    if component.exported is not None:
        return component.exported
    if component.kind == "provider":
        # Providers defaulted to exported before API 17.
        return (min_sdk or 0) < 17
    return component.has_intent_filter


def _loc(manifest: Manifest, component: ManifestComponent | None = None) -> Location:
    return Location(
        path=manifest.source_path,
        line=component.line if component else None,
    )


@rule("manifest.debuggable")
def debuggable(ctx: ScanContext) -> Iterator[Finding]:
    for manifest in ctx.manifests:
        value = manifest.application_attrs.get("android:debuggable", "").lower()
        if value == "true":
            yield Finding(
                id="AND-DEBUGGABLE",
                title="Application is marked debuggable",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                why=(
                    "A debuggable build lets anyone with the device attach a debugger, read "
                    "process memory and run code as your app. Play rejects debuggable uploads."
                ),
                fix='Remove android:debuggable="true" from <application>. Let the build type set it.',
                location=_loc(manifest),
                evidence='android:debuggable="true"',
                refs=(DOC_EXPORTED,),
            )


@rule("manifest.exported")
def exported_components(ctx: ScanContext) -> Iterator[Finding]:
    min_sdk = ctx.build.min_sdk
    target_sdk = ctx.build.target_sdk
    for manifest in ctx.manifests:
        for component in manifest.components:
            explicit_missing = (
                component.exported is None
                and component.has_intent_filter
                and (target_sdk or 0) >= 31
            )
            if explicit_missing:
                yield Finding(
                    id="AND-EXPORTED-UNSET",
                    title=f"{component.kind} '{component.name}' has an intent filter but no android:exported",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    why=(
                        "From API 31 every component with an intent filter must declare "
                        "android:exported explicitly. Without it the build fails or the "
                        "component is exported by accident."
                    ),
                    fix=(
                        f'Add android:exported="false" to <{component.kind}> unless another app '
                        "genuinely needs to start it."
                    ),
                    location=_loc(manifest, component),
                    evidence=f"<{component.kind} android:name=\"{component.name}\">",
                    refs=(DOC_API31,),
                )
                continue

            if not _effective_exported(component, min_sdk):
                continue
            if component.permission:
                continue
            # A launcher activity is exported on purpose.
            if component.kind in {"activity", "activity-alias"} and component.has_intent_filter:
                continue

            severity = Severity.HIGH if component.kind in {"provider", "service"} else Severity.MEDIUM
            yield Finding(
                id="AND-EXPORTED-OPEN",
                title=f"Exported {component.kind} '{component.name}' has no permission guard",
                severity=severity,
                category=Category.SECURITY,
                why=(
                    "Any installed app can reach this component. For providers that can mean "
                    "reading or writing your data; for services, triggering privileged work."
                ),
                fix=(
                    f'Set android:exported="false", or add android:permission="..." with a '
                    "signature-level permission if another app of yours must call it."
                ),
                location=_loc(manifest, component),
                evidence=f"<{component.kind} android:name=\"{component.name}\" android:exported=\"true\">",
                refs=(DOC_EXPORTED,),
            )


@rule("manifest.backup")
def allow_backup(ctx: ScanContext) -> Iterator[Finding]:
    for manifest in ctx.manifests:
        attrs = manifest.application_attrs
        value = attrs.get("android:allowBackup")
        if value is not None and value.lower() == "false":
            continue
        has_rules = "android:fullBackupContent" in attrs or "android:dataExtractionRules" in attrs
        if has_rules:
            continue
        yield Finding(
            id="AND-BACKUP",
            title="Auto-backup is on with no exclusion rules",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            why=(
                "allowBackup defaults to true. App data — including tokens and local databases — "
                "can be pulled off the device with adb backup or synced to the user's cloud."
            ),
            fix=(
                'Set android:allowBackup="false", or keep backup and add '
                "android:dataExtractionRules that exclude credential and database files."
            ),
            location=_loc(manifest),
            evidence=f'android:allowBackup="{value or "(unset, defaults to true)"}"',
            refs=(DOC_BACKUP,),
        )


@rule("manifest.cleartext")
def cleartext_traffic(ctx: ScanContext) -> Iterator[Finding]:
    for manifest in ctx.manifests:
        attrs = manifest.application_attrs
        value = attrs.get("android:usesCleartextTraffic", "").lower()
        if value == "true":
            yield Finding(
                id="AND-CLEARTEXT",
                title="Cleartext HTTP traffic is explicitly allowed",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                why=(
                    "Anything the app sends over http:// can be read and modified on any "
                    "network the device joins."
                ),
                fix=(
                    "Remove android:usesCleartextTraffic, move endpoints to https, and if one "
                    "host truly needs cleartext, allow only that host in a network security config."
                ),
                location=_loc(manifest),
                evidence='android:usesCleartextTraffic="true"',
                refs=(DOC_NETSEC,),
            )

    pattern = re.compile(r'cleartextTrafficPermitted\s*=\s*"true"')
    for f in ctx.files:
        if "network_security_config" not in f.path.name and "network-security" not in f.relpath:
            continue
        for match in pattern.finditer(f.text):
            yield Finding(
                id="AND-NETSEC-CLEARTEXT",
                title="Network security config permits cleartext traffic",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                why="The config re-enables plain HTTP for the domains in this scope.",
                fix="Remove cleartextTrafficPermitted=\"true\", or scope it to a single dev host and exclude it from release builds.",
                location=Location(f.relpath, f.line_of(match.start())),
                evidence=match.group(),
                refs=(DOC_NETSEC,),
            )


@rule("manifest.foreground_service_type")
def foreground_service_type(ctx: ScanContext) -> Iterator[Finding]:
    target = ctx.build.target_sdk or 0
    if target < 34:
        return
    for manifest in ctx.manifests:
        if not manifest.has_permission("android.permission.FOREGROUND_SERVICE"):
            continue
        for component in manifest.components:
            if component.kind != "service":
                continue
            if "android:foregroundServiceType" in component.extra:
                continue
            yield Finding(
                id="AND-FGS-TYPE",
                title=f"Service '{component.name}' declares no foregroundServiceType",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                why=(
                    "Targeting API 34+, a foreground service without a declared type throws "
                    "MissingForegroundServiceTypeException at runtime, and Play requires a "
                    "justification for each type."
                ),
                fix=(
                    "Add android:foregroundServiceType to the <service> and the matching "
                    "FOREGROUND_SERVICE_* permission, then fill in the Play Console declaration."
                ),
                location=_loc(manifest, component),
                evidence=f'<service android:name="{component.name}">',
                refs=(DOC_FGS,),
            )


@rule("manifest.task_hijack")
def task_hijack(ctx: ScanContext) -> Iterator[Finding]:
    min_sdk = ctx.build.min_sdk
    if (min_sdk or 0) >= 29:
        return
    for manifest in ctx.manifests:
        for component in manifest.components:
            if component.kind not in {"activity", "activity-alias"}:
                continue
            if not _effective_exported(component, min_sdk):
                continue
            launch_mode = component.extra.get("android:launchMode", "")
            if launch_mode not in {"singleTask", "singleInstance"}:
                continue
            if component.extra.get("android:taskAffinity") == "":
                continue
            yield Finding(
                id="AND-TASK-AFFINITY",
                title=f"Exported activity '{component.name}' uses {launch_mode} without an empty taskAffinity",
                severity=Severity.LOW,
                category=Category.SECURITY,
                why=(
                    "On Android 9 and below a malicious app can insert itself into the task "
                    "stack (task hijacking / StrandHogg) and show its own screen in your flow."
                ),
                fix='Add android:taskAffinity="" to the activity, or raise minSdk to 29+.',
                location=_loc(manifest, component),
                evidence=f'android:launchMode="{launch_mode}"',
                refs=(DOC_EXPORTED,),
            )
