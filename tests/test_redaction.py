"""Output-safety invariant: a secret playgate finds is never printed in full.

A security tool that leaks the credential it just flagged — into a report, a log,
a CI artifact — is its own vulnerability. Every render path must redact.
"""

from __future__ import annotations

from pathlib import Path

from playgate.report import to_json, to_markdown, to_sarif, to_text
from playgate.scan import scan

from .conftest import write

# Built by concatenation so this test file itself contains no provider-format
# literal (keeps secret scanners quiet); the value written to disk is contiguous.
STRIPE = "sk_live_" + "51H8kQpLmNvBxWzYt3RfGh2Jd"
AWS = "AKIA" + "IOSFODNN7EXAMPLE1"[:16]
GENERIC = "Xq7$pL2mNv8ZrT4wKb1Hs9Dc"


def _scan_with_secrets(tmp_path: Path):
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 36 } }\n")
    write(
        root / "app" / "src" / "main" / "java" / "Keys.kt",
        f'val a = "{STRIPE}"\nval b = "{AWS}"\nval apiSecret = "{GENERIC}"\n',
    )
    return scan(root)


def test_full_secret_never_appears_in_any_format(tmp_path: Path) -> None:
    report = _scan_with_secrets(tmp_path)
    outputs = {
        "text": to_text(report, color=False),
        "markdown": to_markdown(report),
        "json": to_json(report),
        "sarif": to_sarif(report),
    }
    for fmt, text in outputs.items():
        for secret in (STRIPE, AWS, GENERIC):
            assert secret not in text, f"{fmt} leaked a full secret"


def test_secret_is_actually_detected_and_redacted(tmp_path: Path) -> None:
    report = _scan_with_secrets(tmp_path)
    ids = {f.id for f in report.findings}
    assert "SEC-STRIPE-LIVE" in ids
    assert "SEC-AWS-KEY" in ids
    # The redacted evidence still identifies the secret without revealing it.
    stripe = next(f for f in report.findings if f.id == "SEC-STRIPE-LIVE")
    assert stripe.evidence and stripe.evidence != STRIPE
    assert "…" in stripe.evidence or "*" in stripe.evidence
