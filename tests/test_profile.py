"""Game vs app profile: detection, overrides, and per-profile reporting."""

from __future__ import annotations

import json
from pathlib import Path

from playgate.cli import main
from playgate.report import release_json, to_json, to_text
from playgate.scan import scan

from .conftest import ids, write


def test_plain_android_project_is_an_app(gradle_project) -> None:
    report = scan(gradle_project())
    assert report.profile == "app"


def test_game_category_in_manifest(gradle_project) -> None:
    report = scan(gradle_project(manifest_body='<application android:appCategory="game"/>\n'))
    assert report.profile == "game"
    assert any("appCategory" in s for s in report.profile_signals)


def test_engine_dependencies_mean_game(tmp_path: Path, gradle_project) -> None:
    assert scan(gradle_project(gradle=(
        "android { defaultConfig { targetSdk 36 } }\n"
        'dependencies { implementation "com.google.android.gms:play-services-games-v2:20.0.0" }\n'
    ))).profile == "game"
    web = tmp_path / "web"
    write(web / "package.json", '{"dependencies": {"phaser": "^3.80.0"}}')
    assert scan(web).profile == "game"


def test_unity_and_godot_are_games(tmp_path: Path) -> None:
    unity = tmp_path / "u"
    write(unity / "ProjectSettings" / "ProjectSettings.asset", "PlayerSettings:\n  AndroidTargetSdkVersion: 36\n")
    godot = tmp_path / "g"
    write(godot / "project.godot", "config_version=5\n")
    assert scan(unity).profile == "game"
    assert scan(godot).profile == "game"


def test_overrides(gradle_project) -> None:
    root = gradle_project(extra={"playgate.toml": 'privacy_policy_url = "https://x/p"\napp_type = "game"\n'})
    assert scan(root).profile == "game"
    assert scan(root, profile="app").profile == "app"  # CLI beats the file


def test_game_rules_do_not_run_for_apps(gradle_project) -> None:
    code = {"app/src/main/java/A.kt": 'prefs.edit().putInt("coins", 5).apply()\nfun enableGodMode() {}\n'}
    assert not {i for i in ids(scan(gradle_project(extra=code))) if i.startswith("GAME-")}
    game = scan(gradle_project(extra=code), profile="game")
    assert {"GAME-LOCAL-CURRENCY", "GAME-CHEAT-LEFTOVER"} <= ids(game)


def test_cheats_in_debug_source_set_are_ignored(gradle_project) -> None:
    root = gradle_project(extra={"app/src/debug/java/Cheats.kt": "fun enableGodMode() {}\n"})
    assert "GAME-CHEAT-LEFTOVER" not in ids(scan(root, profile="game"))


def test_reports_show_profile_areas(gradle_project) -> None:
    report = scan(gradle_project(extra={"app/src/main/java/A.kt": 'prefs.edit().putInt("coins", 5).apply()\n'}),
                  profile="game")
    text = to_text(report, color=False)
    assert "profile: game" in text and "GAME RISK AREAS" in text
    data = json.loads(to_json(report))
    economy = next(a for a in data["profile"]["areas"] if a["area"] == "Economy & save data")
    assert economy["status"] == "issues"
    phases = [p["phase"] for p in release_json(report)[0]["phases"]]
    assert any(p.startswith("Game policy") for p in phases)


def test_app_release_has_app_access_phase(gradle_project) -> None:
    phases = [p["phase"] for p in release_json(scan(gradle_project()))[0]["phases"]]
    assert any(p.startswith("App access") for p in phases)


def test_profile_flag_on_cli(gradle_project, capsys) -> None:
    assert main(["scan", str(gradle_project()), "--profile", "game", "--no-color", "--fail-on", "never"]) == 0
    assert "profile: game" in capsys.readouterr().out
