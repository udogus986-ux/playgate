"""Structural validation of SARIF output against the 2.1.0 spec's required
shape — without a jsonschema dependency."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from benchmarks.corpus import cases
from playgate.report import to_sarif
from playgate.scan import scan

LEVELS = {"none", "note", "warning", "error"}


def _validate(doc: dict) -> None:
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert isinstance(doc["runs"], list) and doc["runs"]
    for run in doc["runs"]:
        driver = run["tool"]["driver"]
        assert isinstance(driver["name"], str) and driver["name"]
        rule_ids = [r["id"] for r in driver.get("rules", [])]
        assert len(rule_ids) == len(set(rule_ids)), "rule ids must be unique"
        for rule in driver.get("rules", []):
            assert rule["shortDescription"]["text"]
            assert rule["defaultConfiguration"]["level"] in LEVELS
            sev = rule["properties"]["security-severity"]
            assert isinstance(sev, str) and 0.0 <= float(sev) <= 10.0
            for tag in rule["properties"]["tags"]:
                assert isinstance(tag, str)
                if tag.startswith("external/cwe/"):
                    assert re.fullmatch(r"external/cwe/cwe-\d+", tag)
            if "helpUri" in rule:
                assert rule["helpUri"].startswith("https://")
        for result in run["results"]:
            assert result["ruleId"] in rule_ids
            assert result["level"] in LEVELS
            assert result["message"]["text"]
            for loc in result.get("locations", []):
                phys = loc["physicalLocation"]
                uri = phys["artifactLocation"]["uri"]
                assert "\\" not in uri and not re.match(r"^[A-Za-z]:", uri), "uri must be relative, /-separated"
                if "region" in phys:
                    assert isinstance(phys["region"]["startLine"], int) and phys["region"]["startLine"] >= 1


def test_sarif_is_valid_for_every_corpus_case() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        for case in cases():
            doc = json.loads(to_sarif(scan(case.materialise(Path(tmp)))))
            _validate(doc)
