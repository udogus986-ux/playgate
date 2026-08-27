"""PyInstaller entry script. Builds into playgate.exe.

Kept tiny on purpose: it only hands control to :func:`playgate.app.main`, which
opens the web UI when double-clicked and behaves as the CLI when given
arguments.
"""

import sys

from playgate.app import main

if __name__ == "__main__":
    sys.exit(main())
