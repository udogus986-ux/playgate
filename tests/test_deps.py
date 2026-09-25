"""Offline SCA: declared dependency versions vs the bundled advisory list."""

from __future__ import annotations

import json

from playgate.models import Severity
from playgate.rules.deps import ADVISORIES, is_vulnerable
from playgate.scan import scan

from .conftest import ids, write


def _adv(eco: str, pkg: str):
    return ADVISORIES[(eco, pkg)][0]


def test_version_line_logic() -> None:
    ws = _adv("npm", "ws")  # fixed on 5.2.4 / 6.2.3 / 7.5.10 / 8.17.1
    assert is_vulnerable("7.4.0", ws)
    assert not is_vulnerable("7.5.10", ws)
    assert is_vulnerable("8.17.0", ws)
    assert not is_vulnerable("8.18.0", ws)
    assert is_vulnerable("4.0.0", ws)       # older than every fixed line
    assert not is_vulnerable("^8.17.1", ws)  # range prefix is stripped


def test_log4j_backport_lines() -> None:
    log4j = _adv("maven", "org.apache.logging.log4j:log4j-core")
    assert is_vulnerable("2.14.1", log4j)
    assert not is_vulnerable("2.12.4", log4j)  # Java 7 backport
    assert not is_vulnerable("2.17.1", log4j)
    assert not is_vulnerable("1.2.17", log4j)  # before `introduced`


def test_gradle_coordinate_flagged(gradle_project) -> None:
    root = gradle_project(gradle=(
        "android { defaultConfig { targetSdk 36 } }\n"
        "dependencies {\n"
        '  implementation "org.apache.logging.log4j:log4j-core:2.14.1"\n'
        '  implementation("com.google.code.gson:gson:2.10.1")\n'
        "}\n"))
    report = scan(root)
    hits = [f for f in report.findings if f.id == "DEP-VULNERABLE"]
    assert len(hits) == 1
    assert "log4j-core" in hits[0].title
    assert hits[0].severity is Severity.CRITICAL


def test_gradle_variable_resolved(gradle_project) -> None:
    root = gradle_project(gradle=(
        'def textVersion = "1.9"\n'
        "android { defaultConfig { targetSdk 36 } }\n"
        'dependencies { implementation "org.apache.commons:commons-text:$textVersion" }\n'))
    assert "DEP-VULNERABLE" in ids(scan(root))


def test_version_catalog(gradle_project) -> None:
    root = gradle_project(extra={"gradle/libs.versions.toml": (
        '[versions]\nsnake = "1.33"\n\n'
        '[libraries]\nsnakeyaml = { module = "org.yaml:snakeyaml", version.ref = "snake" }\n'
        'jsoup = "org.jsoup:jsoup:1.17.2"\n')})
    hits = [f for f in scan(root).findings if f.id == "DEP-VULNERABLE"]
    assert [h.evidence for h in hits] == ["org.yaml:snakeyaml:1.33"]


def test_package_json_and_dev_downgrade(tmp_path) -> None:
    root = tmp_path / "web"
    write(root / "package.json", json.dumps({
        "dependencies": {"lodash": "^4.17.20"},
        "devDependencies": {"minimist": "1.2.5"},
    }))
    hits = {f.evidence: f for f in scan(root).findings if f.id == "DEP-VULNERABLE"}
    assert hits["lodash:^4.17.20"].severity is Severity.HIGH
    assert hits["minimist:1.2.5"].severity is Severity.HIGH  # critical, downgraded for dev


def test_package_lock_includes_transitive(tmp_path) -> None:
    root = tmp_path / "web"
    write(root / "package.json", json.dumps({"dependencies": {"express": "^4.0.0"}}))
    write(root / "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "web"},
            "node_modules/express": {"version": "4.19.2"},
            "node_modules/semver": {"version": "7.5.1"},
        },
    }))
    hits = [f for f in scan(root).findings if f.id == "DEP-VULNERABLE"]
    assert [h.evidence for h in hits] == ["semver:7.5.1"]


def test_patched_versions_are_quiet(gradle_project) -> None:
    root = gradle_project(gradle=(
        "android { defaultConfig { targetSdk 36 } }\n"
        'dependencies { implementation "com.google.code.gson:gson:2.11.0" }\n'))
    assert "DEP-VULNERABLE" not in ids(scan(root))
