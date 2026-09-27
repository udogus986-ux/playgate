"""Importing this package registers every rule module."""

from . import (  # noqa: F401
    android_extra, app_profile, build, cloud, code, deps, dex_api, game, godot, ios, manifest, policy,
    secrets, taint, unity,
)
from .base import all_rules, run_all  # noqa: F401

__all__ = ["all_rules", "run_all"]
