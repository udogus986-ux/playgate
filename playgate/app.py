"""Entry point for the packaged desktop app (playgate.exe).

Double-clicked with no arguments, playgate opens its local web interface in the
browser — the "app" experience. Run from a terminal with arguments, it behaves
exactly like the ``playgate`` CLI (scan, init, rules, ui, mcp).
"""

from __future__ import annotations

import sys


def main() -> int:
    argv = sys.argv[1:]
    if argv:
        from .cli import main as cli_main

        return cli_main(argv)

    # No arguments: act like an app and open the web UI.
    from .webui import serve

    print("=" * 56)
    print("  playgate — Android güvenlik & Google Play ön kontrolü")
    print("=" * 56)
    print("  Arayüz tarayıcıda açılıyor…")
    print("  Kapatmak için bu pencereyi kapat ya da Ctrl+C.")
    print("=" * 56)
    try:
        return serve()
    except KeyboardInterrupt:  # pragma: no cover
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
