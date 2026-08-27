"""Cloud / Backend-as-a-Service checks: Firebase, Supabase, Cloudflare.

playgate is a static, local-file scanner. The dangerous part of these services
lives *server-side* — Firestore/RTDB/Storage security rules, Supabase Row Level
Security, Cloudflare WAF/Access/R2-public-access — and often is not in the repo
at all. Two jobs here:

1. Check the security config that *is* local (rules files, RLS in migrations).
2. When a service is used but its security config cannot be seen locally, emit a
   loud "cannot verify — lives server-side" coverage finding, so a report never
   reads as a clean bill of health for cloud configuration.

Dynamic verification (querying the live project) is out of scope for the
deterministic core; that belongs to the ``playgate-cloud-auditor`` agent, which
drives the developer's own authenticated firebase/supabase/wrangler CLIs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

from ..models import Category, Finding, Location, ScanContext, Severity, SourceFile
from .base import rule

DOC_FIREBASE_RULES = "https://firebase.google.com/docs/rules/basics"
DOC_SUPABASE_RLS = "https://supabase.com/docs/guides/database/postgres/row-level-security"
DOC_CLOUDFLARE = "https://developers.cloudflare.com/r2/buckets/public-buckets/"

# Provider URLs only trusted inside actual application code, so scanning
# playgate's own source (which merely *mentions* these hosts) doesn't trip it.
_CODE_SUFFIXES = {".kt", ".java", ".cs", ".gd", ".js", ".ts", ".dart", ".swift", ".m", ".mm"}

_FIREBASE_URL = re.compile(r"[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app|firebaseapp\.com)")
_SUPABASE_URL = re.compile(r"[a-z0-9]{16,}\.supabase\.(?:co|in)")
_WORKERS_URL = re.compile(r"[a-z0-9-]+\.workers\.dev")

_RULES_NAMES = {"firestore.rules", "storage.rules", "database.rules.json"}

# Firestore/Storage rules that grant access unconditionally, or with the
# console's time-limited "test mode" (open until a date).
_CEL_OPEN = re.compile(r"allow\s+[\w,\s]+:\s*if\s+true\b", re.IGNORECASE)
_CEL_TESTMODE = re.compile(r"allow\s+[\w,\s]+:\s*if\s+request\.time\s*<", re.IGNORECASE)
# RTDB JSON rules opened to the world.
_RTDB_OPEN = re.compile(r'"\.(?:read|write)"\s*:\s*(?:true|"true"|"auth\s*!=\s*null"\s*==\s*true)')


@dataclass
class _Detected:
    firebase: bool = False
    supabase: bool = False
    cloudflare: bool = False
    firebase_rules: list[SourceFile] = field(default_factory=list)
    supabase_migrations: list[SourceFile] = field(default_factory=list)
    wrangler: list[SourceFile] = field(default_factory=list)
    evidence: dict[str, str] = field(default_factory=dict)

    def note(self, service: str, ev: str) -> None:
        self.evidence.setdefault(service, ev)


def _detect(ctx: ScanContext) -> _Detected:
    d = _Detected()
    dep_blob_parts: list[str] = []

    for f in ctx.files:
        name = f.path.name.lower()
        rel = f.relpath.replace("\\", "/").lower()
        suffix = f.path.suffix.lower()

        if name in {"package.json", "pubspec.yaml", "build.gradle", "build.gradle.kts"}:
            dep_blob_parts.append(f.text.lower())

        # Firebase config / rules files.
        if name in _RULES_NAMES:
            d.firebase = True
            d.firebase_rules.append(f)
            d.note("firebase", f.relpath)
        elif name == "firebase.json" or name == "google-services.json" or name == "googleservice-info.plist":
            d.firebase = True
            d.note("firebase", f.relpath)

        # Supabase config / migrations.
        if "supabase/" in rel and (suffix == ".sql" or name == "config.toml"):
            d.supabase = True
            if suffix == ".sql" and "migrations" in rel:
                d.supabase_migrations.append(f)
            d.note("supabase", f.relpath)

        # Cloudflare wrangler config.
        if name in {"wrangler.toml", "wrangler.jsonc", "wrangler.json"}:
            d.cloudflare = True
            d.wrangler.append(f)
            d.note("cloudflare", f.relpath)

        # Provider URLs, but only inside real app code.
        if suffix in _CODE_SUFFIXES:
            if not d.firebase and _FIREBASE_URL.search(f.text):
                d.firebase = True
                d.note("firebase", f.relpath)
            if not d.supabase and _SUPABASE_URL.search(f.text):
                d.supabase = True
                d.note("supabase", f.relpath)
            if not d.cloudflare and _WORKERS_URL.search(f.text):
                d.cloudflare = True
                d.note("cloudflare", f.relpath)

    deps = "\n".join(dep_blob_parts)
    if "com.google.firebase" in deps or '"firebase' in deps or "firebase_core" in deps:
        d.firebase = True
        d.note("firebase", "dependency declaration")
    if "@supabase/" in deps or "supabase_flutter" in deps or "supabase-" in deps:
        d.supabase = True
        d.note("supabase", "dependency declaration")
    if "@cloudflare/" in deps or '"wrangler"' in deps or "workers-types" in deps:
        d.cloudflare = True
        d.note("cloudflare", "dependency declaration")

    return d


@rule("cloud.firebase")
def firebase(ctx: ScanContext) -> Iterator[Finding]:
    d = _detect(ctx)
    if not d.firebase:
        return

    for f in d.firebase_rules:
        is_rtdb = f.path.name.lower() == "database.rules.json"
        pattern = _RTDB_OPEN if is_rtdb else _CEL_OPEN
        for match in pattern.finditer(f.text):
            yield Finding(
                id="CLD-FIREBASE-OPEN",
                title=f"Firebase security rules grant public access ({f.path.name})",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                why=(
                    "This rule lets any client read or write the data without authentication. "
                    "The database URL and API key ship in the app, so anyone who unzips it can "
                    "reach everything these rules cover."
                ),
                fix=(
                    "Scope each rule to an authenticated, authorised user "
                    "(`allow read, write: if request.auth != null && ...`). Never ship the "
                    "console's open 'test mode' default."
                ),
                location=Location(f.relpath, f.line_of(match.start())),
                evidence=match.group(0).strip()[:120],
                refs=(DOC_FIREBASE_RULES,),
            )
        if not is_rtdb:
            for match in _CEL_TESTMODE.finditer(f.text):
                yield Finding(
                    id="CLD-FIREBASE-TESTMODE",
                    title=f"Firebase rules are in time-limited 'test mode' ({f.path.name})",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    why=(
                        "A `request.time < ...` rule is the console's test mode: fully open until "
                        "the date, then fully closed. Either way it is not real access control."
                    ),
                    fix="Replace it with auth-based conditions before release.",
                    location=Location(f.relpath, f.line_of(match.start())),
                    evidence=match.group(0).strip()[:120],
                    refs=(DOC_FIREBASE_RULES,),
                )

    if not d.firebase_rules:
        yield Finding(
            id="COV-FIREBASE-RULES",
            title="Firebase is used but its security rules are not in the repo — unverifiable",
            severity=Severity.INFO,
            category=Category.SECURITY,
            why=(
                "playgate found Firebase in this project but no firestore.rules / "
                "database.rules.json / storage.rules file to check. Those rules live in the "
                "Firebase console; if they are still the open 'test mode' default, your entire "
                "database is world-readable and playgate cannot see it."
            ),
            fix=(
                "Pull and commit your rules so they are reviewed and version-controlled, and open "
                "Console → Firestore/Realtime Database/Storage → Rules to confirm there is no "
                "`allow read, write: if true`. The playgate-cloud-auditor agent can verify the "
                "live rules with your Firebase login."
            ),
            location=Location(d.evidence.get("firebase")),
            evidence=f"detected via {d.evidence.get('firebase', 'project files')}",
            refs=(DOC_FIREBASE_RULES,),
        )


@rule("cloud.supabase")
def supabase(ctx: ScanContext) -> Iterator[Finding]:
    d = _detect(ctx)
    if not d.supabase:
        return

    if d.supabase_migrations:
        joined = "\n".join(f.text for f in d.supabase_migrations)
        creates = re.findall(r"(?i)\bcreate\s+table\b", joined)
        has_rls = re.search(r"(?i)enable\s+row\s+level\s+security", joined)
        if creates and not has_rls:
            first = d.supabase_migrations[0]
            yield Finding(
                id="CLD-SUPABASE-NO-RLS",
                title=f"Supabase migrations create {len(creates)} table(s) but never enable RLS",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                why=(
                    "No migration runs `enable row level security`. Unless RLS was turned on in "
                    "the dashboard, the anon key — which ships in the client — can read and write "
                    "every table directly, bypassing your app entirely."
                ),
                fix=(
                    "Add `alter table <t> enable row level security;` plus policies scoped to "
                    "`auth.uid()` for each table, and keep the service_role key server-side only."
                ),
                location=Location(first.relpath),
                evidence="create table present; no 'enable row level security' in migrations",
                refs=(DOC_SUPABASE_RLS,),
            )
        return  # migrations were present and checked

    yield Finding(
        id="COV-SUPABASE-RLS",
        title="Supabase is used but RLS cannot be verified from local files",
        severity=Severity.INFO,
        category=Category.SECURITY,
        why=(
            "Row Level Security and its policies live in the Supabase project database, not in "
            "the repo. The public anon key ships in the app; without RLS it reads and writes "
            "every table. playgate cannot see the live RLS state."
        ),
        fix=(
            "Enable RLS on every table with policies scoped to auth.uid(), and never ship the "
            "service_role key. Verify in the dashboard, with `supabase db`, or via the "
            "playgate-cloud-auditor agent using your Supabase login."
        ),
        location=Location(d.evidence.get("supabase")),
        evidence=f"detected via {d.evidence.get('supabase', 'project files')}",
        refs=(DOC_SUPABASE_RLS,),
    )


@rule("cloud.cloudflare")
def cloudflare(ctx: ScanContext) -> Iterator[Finding]:
    d = _detect(ctx)
    if not d.cloudflare:
        return
    yield Finding(
        id="COV-CLOUDFLARE",
        title="Cloudflare is used — WAF, Access, and R2 public access cannot be verified locally",
        severity=Severity.INFO,
        category=Category.SECURITY,
        why=(
            "Cloudflare's security-relevant configuration — WAF rules, Access policies, R2 bucket "
            "public-access and CORS, and secret bindings — is set in the dashboard, not in "
            "wrangler config. A public R2 bucket or an unprotected Worker route is invisible to a "
            "static scan of these files."
        ),
        fix=(
            "Confirm no R2 bucket is public unless intended, Access policies protect internal "
            "routes, and secrets use `wrangler secret put` rather than `[vars]`. Verify with the "
            "`wrangler` CLI / the dashboard, or the playgate-cloud-auditor agent."
        ),
        location=Location(d.evidence.get("cloudflare")),
        evidence=f"detected via {d.evidence.get('cloudflare', 'project files')}",
        refs=(DOC_CLOUDFLARE,),
    )
