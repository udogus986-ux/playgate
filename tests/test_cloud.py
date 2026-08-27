"""Cloud / BaaS checks: local security config + server-side coverage findings."""

from __future__ import annotations

from pathlib import Path

from playgate.models import Severity
from playgate.scan import scan

from .conftest import ids, write


def _base(root: Path) -> None:
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 36 } }\n")


# --------------------------------------------------------------------------
# Firebase
# --------------------------------------------------------------------------

def test_open_firestore_rules_is_high(tmp_path: Path) -> None:
    root = tmp_path / "p"
    _base(root)
    write(
        root / "firestore.rules",
        "rules_version = '2';\nservice cloud.firestore {\n"
        "  match /databases/{db}/documents {\n"
        "    match /{doc=**} { allow read, write: if true; }\n  }\n}\n",
    )
    finding = next(f for f in scan(root).findings if f.id == "CLD-FIREBASE-OPEN")
    assert finding.severity is Severity.HIGH


def test_rtdb_open_rules_flagged(tmp_path: Path) -> None:
    root = tmp_path / "p"
    _base(root)
    write(root / "database.rules.json", '{\n  "rules": { ".read": true, ".write": true }\n}\n')
    assert "CLD-FIREBASE-OPEN" in ids(scan(root))


def test_firestore_testmode_flagged(tmp_path: Path) -> None:
    root = tmp_path / "p"
    _base(root)
    write(
        root / "firestore.rules",
        "service cloud.firestore {\n  match /d/{x} {\n"
        "    allow read, write: if request.time < timestamp.date(2026, 12, 31);\n  }\n}\n",
    )
    assert "CLD-FIREBASE-TESTMODE" in ids(scan(root))


def test_closed_firestore_rules_are_quiet(tmp_path: Path) -> None:
    root = tmp_path / "p"
    _base(root)
    write(
        root / "firestore.rules",
        "service cloud.firestore {\n  match /d/{x} {\n"
        "    allow read, write: if request.auth != null;\n  }\n}\n",
    )
    found = ids(scan(root))
    assert "CLD-FIREBASE-OPEN" not in found
    assert "COV-FIREBASE-RULES" not in found  # rules present and checked → no coverage gap


def test_firebase_without_rules_gets_coverage_finding(tmp_path: Path) -> None:
    root = tmp_path / "p"
    _base(root)
    write(root / "app" / "src" / "main" / "java" / "A.kt",
          'val db = "https://demo-app.firebaseio.com"\n')
    finding = next(f for f in scan(root).findings if f.id == "COV-FIREBASE-RULES")
    assert finding.severity is Severity.INFO


# --------------------------------------------------------------------------
# Supabase
# --------------------------------------------------------------------------

def test_supabase_migrations_without_rls(tmp_path: Path) -> None:
    root = tmp_path / "p"
    _base(root)
    write(root / "supabase" / "migrations" / "001_init.sql",
          "create table public.notes (id uuid primary key, body text);\n")
    finding = next(f for f in scan(root).findings if f.id == "CLD-SUPABASE-NO-RLS")
    assert finding.severity is Severity.MEDIUM


def test_supabase_migrations_with_rls_are_quiet(tmp_path: Path) -> None:
    root = tmp_path / "p"
    _base(root)
    write(root / "supabase" / "migrations" / "001_init.sql",
          "create table public.notes (id uuid primary key, body text);\n"
          "alter table public.notes enable row level security;\n")
    found = ids(scan(root))
    assert "CLD-SUPABASE-NO-RLS" not in found


def test_supabase_url_without_migrations_gets_coverage(tmp_path: Path) -> None:
    root = tmp_path / "p"
    _base(root)
    write(root / "app" / "src" / "main" / "java" / "A.kt",
          'val url = "https://abcdefghijklmnop.supabase.co"\n')
    assert "COV-SUPABASE-RLS" in ids(scan(root))


# --------------------------------------------------------------------------
# Cloudflare
# --------------------------------------------------------------------------

def test_cloudflare_wrangler_gets_coverage(tmp_path: Path) -> None:
    root = tmp_path / "p"
    _base(root)
    write(root / "wrangler.toml", 'name = "api"\nmain = "src/index.ts"\n[[r2_buckets]]\nbinding = "B"\n')
    finding = next(f for f in scan(root).findings if f.id == "COV-CLOUDFLARE")
    assert finding.severity is Severity.INFO


# --------------------------------------------------------------------------
# No false positives on a plain project
# --------------------------------------------------------------------------

def test_plain_project_has_no_cloud_findings(gradle_project) -> None:
    found = ids(scan(gradle_project()))
    assert not any(i.startswith(("CLD-", "COV-FIRE", "COV-SUPA", "COV-CLOUD")) for i in found)
