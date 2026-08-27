"""Local web interface: ``playgate ui``.

Standard library only, like the rest of the tool. The server binds
127.0.0.1 and refuses requests whose Host/Origin is not local, so nothing is
exposed beyond the developer's own machine. The page itself is a single
self-contained HTML file shipped inside the package (``ui.html``).
"""

from __future__ import annotations

import json
import os
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from .collect import LISTING_FILENAMES, detect_kind
from .report import to_json, to_markdown
from .rules import all_rules
from .scan import scan

MAX_BODY_BYTES = 1 * 1024 * 1024

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _ui_html() -> bytes:
    return (Path(__file__).parent / "ui.html").read_bytes()


def _drives() -> list[str]:
    if os.name != "nt":
        return []
    import string

    return [f"{c}:\\" for c in string.ascii_uppercase if Path(f"{c}:\\").exists()]


def _api_meta() -> dict:
    return {
        "version": __version__,
        "home": str(Path.home()),
        "cwd": str(Path.cwd()),
        "sep": os.sep,
        "drives": _drives(),
    }


def _api_rules() -> list[dict]:
    out = []
    for name, func in sorted(all_rules()):
        doc = (func.__doc__ or "").strip().splitlines()
        out.append({"name": name, "doc": doc[0] if doc else ""})
    return out


def _api_browse(payload: dict) -> tuple[int, dict]:
    raw = str(payload.get("path") or Path.home())
    try:
        path = Path(raw).expanduser().resolve()
    except OSError as exc:
        return 400, {"error": f"unreadable path: {exc}"}
    if not path.exists():
        return 400, {"error": f"no such path: {path}"}
    if path.is_file():
        path = path.parent

    dirs: list[str] = []
    packages: list[str] = []
    try:
        for child in sorted(path.iterdir(), key=lambda p: p.name.lower()):
            try:
                if child.is_dir():
                    dirs.append(child.name)
                elif child.suffix.lower() in {".apk", ".aab"}:
                    packages.append(child.name)
            except OSError:
                continue
    except OSError as exc:
        return 400, {"error": f"cannot list {path}: {exc}"}

    parent = str(path.parent) if path.parent != path else None
    return 200, {
        "path": str(path),
        "parent": parent,
        "dirs": dirs,
        "packages": packages,
        "kind": detect_kind(path).value,
        "has_listing": any((path / n).exists() for n in LISTING_FILENAMES),
    }


def _api_scan(payload: dict) -> tuple[int, dict]:
    raw = str(payload.get("target") or "").strip()
    if not raw:
        return 400, {"error": "no target given"}
    target = Path(raw).expanduser()
    if not target.exists():
        return 400, {"error": f"no such path: {target}"}
    listing = str(payload.get("listing") or "").strip()
    try:
        report = scan(target, listing_path=Path(listing) if listing else None)
    except (ValueError, RuntimeError) as exc:
        return 400, {"error": str(exc)}
    data = json.loads(to_json(report))
    data["markdown"] = to_markdown(report)
    return 200, data


def _api_init(payload: dict) -> tuple[int, dict]:
    from .cli import TEMPLATE  # cli does not import webui at module level

    raw = str(payload.get("path") or "").strip()
    if not raw:
        return 400, {"error": "no path given"}
    directory = Path(raw).expanduser()
    if directory.is_file():
        directory = directory.parent
    if not directory.is_dir():
        return 400, {"error": f"not a directory: {directory}"}
    target = directory / "playgate.toml"
    if target.exists() and not payload.get("force"):
        return 409, {"error": f"{target} already exists", "path": str(target)}
    try:
        target.write_text(TEMPLATE, encoding="utf-8")
    except OSError as exc:
        return 400, {"error": f"cannot write {target}: {exc}"}
    return 200, {"path": str(target)}


class Handler(BaseHTTPRequestHandler):
    server_version = f"playgate/{__version__}"

    def log_message(self, fmt: str, *args) -> None:  # keep the terminal quiet
        pass

    # -- helpers ----------------------------------------------------------

    def _local_request(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
        if host not in _LOCAL_HOSTS:
            return False
        origin = self.headers.get("Origin")
        if origin:
            try:
                origin_host = origin.split("//", 1)[1].rsplit(":", 1)[0].lower()
            except IndexError:
                return False
            if origin_host not in _LOCAL_HOSTS:
                return False
        return True

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    # -- routes -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._local_request():
            self._json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
            return
        if self.path in {"/", "/index.html"}:
            self._send(200, _ui_html(), "text/html; charset=utf-8")
        elif self.path == "/api/meta":
            self._json(_api_meta())
        elif self.path == "/api/rules":
            self._json(_api_rules())
        else:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._local_request():
            self._json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            self._json({"error": "request too large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json({"error": "invalid JSON body"}, HTTPStatus.BAD_REQUEST)
            return
        if not isinstance(payload, dict):
            self._json({"error": "expected a JSON object"}, HTTPStatus.BAD_REQUEST)
            return

        routes = {"/api/browse": _api_browse, "/api/scan": _api_scan, "/api/init": _api_init}
        handler = routes.get(self.path)
        if handler is None:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        try:
            code, body = handler(payload)
        except Exception as exc:  # noqa: BLE001 - surface, don't kill the server
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
            return
        self._json(body, code)


def make_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def serve(port: int = 8765, open_browser: bool = True) -> int:
    try:
        httpd = make_server(port=port)
    except OSError as exc:
        print(f"playgate: cannot listen on port {port}: {exc}")
        return 2
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"playgate ui: {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.4, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nplaygate ui: stopped")
    finally:
        httpd.server_close()
    return 0
