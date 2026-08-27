"""Core data types for playgate."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable


class Severity(enum.IntEnum):
    """Ordered so that comparisons and sorting are meaningful."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown severity: {value!r}") from exc

    @property
    def label(self) -> str:
        return self.name

    @property
    def icon(self) -> str:
        return {
            Severity.CRITICAL: "!!",
            Severity.HIGH: "!",
            Severity.MEDIUM: "~",
            Severity.LOW: "-",
            Severity.INFO: "i",
        }[self]


class Category(enum.Enum):
    SECURITY = "security"
    POLICY = "policy"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(frozen=True)
class Location:
    """Where a finding was observed."""

    path: str | None = None
    line: int | None = None

    def render(self) -> str:
        if not self.path:
            return "-"
        if self.line:
            return f"{self.path}:{self.line}"
        return self.path


@dataclass
class Finding:
    """A single detected issue.

    ``evidence`` should be a literal quote from the scanned artifact, so the
    report can always be checked against the source. ``fix`` must be concrete
    enough to act on without further research.
    """

    id: str
    title: str
    severity: Severity
    category: Category
    why: str
    fix: str
    location: Location = field(default_factory=Location)
    evidence: str | None = None
    refs: tuple[str, ...] = ()
    # Policy findings carry an extra weight used by the rejection-risk model.
    rejection_weight: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["category"] = self.category.value
        data["location"] = self.location.render()
        data["refs"] = list(self.refs)
        data["fingerprint"] = self.fingerprint()
        return data

    def sort_key(self) -> tuple:
        return (-int(self.severity), self.category.value, self.id, self.location.render())

    def fingerprint(self) -> str:
        """Stable identity for baseline/diff and suppression.

        Deliberately excludes line number and evidence: a finding that moves a
        few lines down, or whose redaction changes, is still the same finding.
        """
        return f"{self.id}|{self.location.path or ''}|{self.title}"


class ProjectKind(enum.Enum):
    GRADLE = "gradle"
    UNITY = "unity"
    GODOT = "godot"
    REACT_NATIVE = "react-native"
    FLUTTER = "flutter"
    APK = "apk"
    UNKNOWN = "unknown"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    @property
    def uses_gradle(self) -> bool:
        """Kinds whose Android build is a normal Gradle module."""
        return self in {
            ProjectKind.GRADLE,
            ProjectKind.REACT_NATIVE,
            ProjectKind.FLUTTER,
        }


@dataclass
class SourceFile:
    """A text file pulled into the scan, read once and shared by all rules."""

    path: Path
    relpath: str
    text: str

    @property
    def lines(self) -> list[str]:
        cached = self.__dict__.get("_lines")
        if cached is None:
            cached = self.text.splitlines()
            self.__dict__["_lines"] = cached
        return cached

    def line_of(self, index: int) -> int:
        """Convert a character offset into a 1-based line number."""
        return self.text.count("\n", 0, index) + 1


@dataclass
class ManifestComponent:
    kind: str  # activity | service | receiver | provider
    name: str
    exported: bool | None
    has_intent_filter: bool
    permission: str | None
    line: int | None = None
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class Manifest:
    """Normalised view of an AndroidManifest, from source XML or binary AXML."""

    package: str | None = None
    permissions: list[str] = field(default_factory=list)
    components: list[ManifestComponent] = field(default_factory=list)
    application_attrs: dict[str, str] = field(default_factory=dict)
    uses_sdk: dict[str, str] = field(default_factory=dict)
    source_path: str | None = None
    raw: str | None = None

    def has_permission(self, name: str) -> bool:
        short = name.rsplit(".", 1)[-1]
        return any(p.rsplit(".", 1)[-1] == short for p in self.permissions)


@dataclass
class BuildConfig:
    """Build settings gathered from Gradle, Unity or Godot project files."""

    target_sdk: int | None = None
    min_sdk: int | None = None
    compile_sdk: int | None = None
    minify_enabled: bool | None = None
    shrink_resources: bool | None = None
    debuggable_release: bool | None = None
    version_name: str | None = None
    version_code: int | None = None
    scripting_backend: str | None = None  # Unity: Mono2x / IL2CPP
    source_path: str | None = None


@dataclass
class ListingMeta:
    """Play Console listing + declarations, supplied by the developer.

    Everything here is self-declared: playgate cannot read Play Console. The
    point is to catch contradictions between what the app *does* (manifest,
    code) and what the developer says it does.
    """

    title: str | None = None
    short_description: str | None = None
    full_description: str | None = None
    privacy_policy_url: str | None = None
    account_creation: bool | None = None
    account_deletion_url: str | None = None
    in_app_account_deletion: bool | None = None
    uses_ads: bool | None = None
    target_audience_children: bool | None = None
    content_rating: str | None = None
    collects_data: list[str] = field(default_factory=list)
    data_safety_declared: list[str] = field(default_factory=list)
    sells_digital_goods: bool | None = None
    uses_play_billing: bool | None = None
    developer_account_type: str | None = None  # personal | organization
    first_release: bool | None = None
    # Findings the developer has consciously accepted. Each entry is a rule id,
    # optionally followed by ":<path-substring>" to scope it.
    ignore: list[str] = field(default_factory=list)
    source_path: str | None = None


@dataclass
class ScanContext:
    """Everything the rules get to look at. Built once per scan."""

    root: Path
    kind: ProjectKind
    files: list[SourceFile] = field(default_factory=list)
    manifests: list[Manifest] = field(default_factory=list)
    build: BuildConfig = field(default_factory=BuildConfig)
    listing: ListingMeta | None = None
    notes: list[str] = field(default_factory=list)

    def files_with_suffix(self, *suffixes: str) -> Iterable[SourceFile]:
        wanted = {s.lower() for s in suffixes}
        for f in self.files:
            if f.path.suffix.lower() in wanted:
                yield f

    def files_named(self, *names: str) -> Iterable[SourceFile]:
        wanted = {n.lower() for n in names}
        for f in self.files:
            if f.path.name.lower() in wanted:
                yield f


@dataclass
class Report:
    root: str
    kind: ProjectKind
    findings: list[Finding]
    notes: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts(self) -> dict[str, int]:
        out = {s.name: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.name] += 1
        return out

    def by_category(self, category: Category) -> list[Finding]:
        return [f for f in self.sorted_findings() if f.category is category]

    def rejection_score(self) -> int:
        """0-100. Sum of policy weights, capped.

        This is a heuristic ordering aid, not a probability. It exists so that
        two runs can be compared, and so the worst item is obvious.
        """
        total = sum(f.rejection_weight for f in self.findings if f.category is Category.POLICY)
        return min(100, total)

    def rejection_band(self) -> str:
        score = self.rejection_score()
        if score >= 60:
            return "CRITICAL"
        if score >= 35:
            return "HIGH"
        if score >= 15:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NONE"
