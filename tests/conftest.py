from __future__ import annotations

from pathlib import Path

import pytest

MANIFEST_HEAD = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.test">\n'
)


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def gradle_project(tmp_path: Path):
    """Build a minimal Gradle project; callers override individual files."""

    def _make(
        manifest_body: str = "<application/>\n",
        gradle: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> Path:
        root = tmp_path / "proj"
        write(root / "settings.gradle", "include ':app'\n")
        write(
            root / "app" / "build.gradle",
            gradle
            if gradle is not None
            else (
                "android {\n"
                "  defaultConfig { minSdk 24\n    targetSdk 36 }\n"
                "  buildTypes { release { minifyEnabled true } }\n"
                "}\n"
            ),
        )
        write(root / "app" / "src" / "main" / "AndroidManifest.xml",
              MANIFEST_HEAD + manifest_body + "</manifest>\n")
        for rel, content in (extra or {}).items():
            write(root / rel, content)
        return root

    return _make


def ids(report) -> set[str]:
    return {f.id for f in report.findings}
