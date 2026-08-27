"""Map each finding id to the security standards it corresponds to.

playgate does not *implement* any standard — it is a static pre-flight linter.
But its findings map cleanly onto well-known weakness classes, and labelling
them makes reports legible to security tooling (GitHub code scanning reads the
``external/cwe/cwe-NNN`` SARIF tag and shows a CWE badge).

Kept as a central table so the rule functions stay focused on detection. Each
entry is keyed by finding id, with a prefix fallback for the whole SEC-* family.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# OWASP Mobile Top 10 (2024) titles, for rendering.
OWASP_MOBILE_2024 = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}


@dataclass(frozen=True)
class Standards:
    cwe: tuple[int, ...] = ()
    masvs: tuple[str, ...] = ()          # e.g. ("MASVS-NETWORK",)
    owasp_mobile: str | None = None      # e.g. "M5"

    def labels(self) -> list[str]:
        """Short human labels: ['OWASP M5', 'MASVS-NETWORK', 'CWE-295']."""
        out: list[str] = []
        if self.owasp_mobile:
            out.append(f"OWASP {self.owasp_mobile}")
        out.extend(self.masvs)
        out.extend(f"CWE-{n}" for n in self.cwe)
        return out

    def sarif_tags(self) -> list[str]:
        tags = ["security"]
        tags += [f"external/cwe/cwe-{n}" for n in self.cwe]
        if self.owasp_mobile:
            tags.append(f"OWASP-Mobile-2024-{self.owasp_mobile}")
        tags += [m for m in self.masvs]
        return tags

    def to_dict(self) -> dict:
        data: dict = {}
        if self.cwe:
            data["cwe"] = [f"CWE-{n}" for n in self.cwe]
        if self.masvs:
            data["masvs"] = list(self.masvs)
        if self.owasp_mobile:
            data["owasp_mobile_top10_2024"] = self.owasp_mobile
        return data


# Common shapes reused below.
_HARDCODED = Standards(cwe=(798,), masvs=("MASVS-STORAGE",), owasp_mobile="M1")
_TLS = Standards(cwe=(295,), masvs=("MASVS-NETWORK",), owasp_mobile="M5")
_CLEARTEXT = Standards(cwe=(319,), masvs=("MASVS-NETWORK",), owasp_mobile="M5")
_EXPORTED = Standards(cwe=(926,), masvs=("MASVS-PLATFORM",), owasp_mobile="M8")
_DEBUG = Standards(cwe=(489,), masvs=("MASVS-RESILIENCE",), owasp_mobile="M8")
_ACCESS = Standards(cwe=(284,), masvs=("MASVS-AUTH",), owasp_mobile="M8")
_CLIENT_TRUST = Standards(cwe=(602,), masvs=("MASVS-CODE",), owasp_mobile="M4")
_PRIVACY = Standards(cwe=(359,), masvs=("MASVS-PRIVACY",), owasp_mobile="M6")

STANDARDS_MAP: dict[str, Standards] = {
    # Manifest
    "AND-DEBUGGABLE": _DEBUG,
    "AND-EXPORTED-UNSET": _EXPORTED,
    "AND-EXPORTED-OPEN": _EXPORTED,
    "AND-BACKUP": Standards(cwe=(312,), masvs=("MASVS-STORAGE",), owasp_mobile="M9"),
    "AND-CLEARTEXT": _CLEARTEXT,
    "AND-NETSEC-CLEARTEXT": _CLEARTEXT,
    "AND-FGS-TYPE": Standards(masvs=("MASVS-PLATFORM",), owasp_mobile="M8"),
    "AND-TASK-AFFINITY": Standards(cwe=(1021,), masvs=("MASVS-PLATFORM",), owasp_mobile="M8"),
    # Build
    "BLD-DEBUGGABLE": _DEBUG,
    "BLD-NO-MINIFY": Standards(cwe=(656,), masvs=("MASVS-RESILIENCE",), owasp_mobile="M7"),
    "BLD-OLD-MINSDK": Standards(masvs=("MASVS-PLATFORM",), owasp_mobile="M8"),
    # Secrets (SEC-* default is _HARDCODED; overrides below)
    "SEC-SIGNING": Standards(cwe=(798, 321), masvs=("MASVS-STORAGE",), owasp_mobile="M1"),
    "SEC-KEYSTORE-FILE": Standards(cwe=(798, 321), masvs=("MASVS-STORAGE",), owasp_mobile="M1"),
    "SEC-PRIVATE-KEY": Standards(cwe=(798, 321), masvs=("MASVS-STORAGE",), owasp_mobile="M1"),
    "SEC-SERVICE-ACCOUNT": Standards(cwe=(798, 321), masvs=("MASVS-STORAGE",), owasp_mobile="M1"),
    "SEC-FIREBASE-DB": Standards(cwe=(668,), masvs=("MASVS-STORAGE",), owasp_mobile="M8"),
    "SEC-SUPABASE-URL": _ACCESS,
    # Code
    "CODE-WEBVIEW-JSBRIDGE": Standards(cwe=(749,), masvs=("MASVS-PLATFORM",), owasp_mobile="M8"),
    "CODE-WEBVIEW-FILEACCESS": Standards(cwe=(668,), masvs=("MASVS-PLATFORM",), owasp_mobile="M8"),
    "CODE-WEBVIEW-DEBUG": Standards(cwe=(489,), masvs=("MASVS-RESILIENCE",), owasp_mobile="M7"),
    "CODE-TLS-TRUSTALL": _TLS,
    "CODE-TLS-VERIFY-TRUE": _TLS,
    "CODE-WORLD-PERMS": Standards(cwe=(732,), masvs=("MASVS-STORAGE",), owasp_mobile="M9"),
    "CODE-WEAK-CIPHER": Standards(cwe=(327,), masvs=("MASVS-CRYPTO",), owasp_mobile="M10"),
    "CODE-WEAK-HASH": Standards(cwe=(328,), masvs=("MASVS-CRYPTO",), owasp_mobile="M10"),
    "CODE-LOG-SECRET": Standards(cwe=(532,), masvs=("MASVS-STORAGE",), owasp_mobile="M9"),
    "CODE-HTTP-URL": _CLEARTEXT,
    "CODE-EXTERNAL-STORAGE": Standards(cwe=(312,), masvs=("MASVS-STORAGE",), owasp_mobile="M9"),
    # Unity
    "UNI-MONO-BACKEND": Standards(cwe=(656,), masvs=("MASVS-RESILIENCE",), owasp_mobile="M7"),
    "UNI-PLAYERPREFS-ECONOMY": _CLIENT_TRUST,
    "UNI-IAP-NOVALIDATION": Standards(cwe=(602, 345), masvs=("MASVS-CODE",), owasp_mobile="M4"),
    # Cloud / BaaS
    "CLD-FIREBASE-OPEN": _ACCESS,
    "CLD-FIREBASE-TESTMODE": _ACCESS,
    "CLD-SUPABASE-NO-RLS": _ACCESS,
    "COV-FIREBASE-RULES": _ACCESS,
    "COV-SUPABASE-RLS": _ACCESS,
    "COV-CLOUDFLARE": _ACCESS,
    # Play policy that is genuinely a privacy control
    "PLY-PRIVACY-POLICY": _PRIVACY,
    "PLY-DATA-SAFETY-GAP": _PRIVACY,
    "PLY-ADID-MISSING": _PRIVACY,
    "PLY-ADID-CHILDREN": _PRIVACY,
}


def standards_for(finding_id: str) -> Standards | None:
    hit = STANDARDS_MAP.get(finding_id)
    if hit is not None:
        return hit
    # Any provider secret we didn't list explicitly is still a hard-coded
    # credential (SEC-STRIPE-LIVE, SEC-AWS-KEY, SEC-GENERIC, …).
    if finding_id.startswith("SEC-"):
        return _HARDCODED
    return None


# A one-paragraph statement of what standards playgate's findings map to and,
# just as importantly, what it deliberately is not — surfaced in every report.
SCOPE = {
    "maps_to": [
        "OWASP MASVS v2 (Mobile App Security Verification Standard)",
        "OWASP MASTG (static test cases)",
        "OWASP Mobile Top 10 (2024)",
        "CWE (Common Weakness Enumeration)",
    ],
    "output_format": "SARIF 2.1.0 (GitHub code scanning), with CVSS-style security-severity",
    "not": [
        "Not a certified/accredited assessment — it does not claim MASVS L1/L2 verification.",
        "Not DAST — it does not run the app, so no runtime behaviour is covered.",
        "Not SCA/CVE — it does not scan dependencies for known CVEs.",
        "A fixed, finite rule set: absence of a finding is not evidence of security "
        "(equivalent to MASVS 'not tested', not 'pass').",
    ],
}
