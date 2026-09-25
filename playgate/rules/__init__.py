"""Importing this package registers every rule module."""

from . import android_extra, build, cloud, code, godot, ios, manifest, policy, secrets, taint, unity  # noqa: F401
from .base import all_rules, run_all  # noqa: F401

__all__ = ["all_rules", "run_all"]
