"""Importing this package registers every rule module."""

from . import build, cloud, code, godot, manifest, policy, secrets, unity  # noqa: F401
from .base import all_rules, run_all  # noqa: F401

__all__ = ["all_rules", "run_all"]
