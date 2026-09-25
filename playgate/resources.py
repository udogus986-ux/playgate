"""Locate data files bundled inside the package, in both a normal install and
the PyInstaller one-file build (where data lives under ``sys._MEIPASS``)."""

from __future__ import annotations

import sys
from pathlib import Path


def data_path(*parts: str) -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidate = Path(base, "playgate", *parts)
        if candidate.exists():
            return candidate
    return Path(__file__).parent.joinpath(*parts)
