"""The local web interface: routes, guards and the scan round-trip."""

from __future__ import annotations

import json
import threading
from http.client import HTTPConnection
from pathlib import Path

import pytest

from playgate.webui import make_server

from .conftest import write


@pytest.fixture(scope="module")
def server():
    httpd = make_server(port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def request(server, method: str, path: str, body: dict | None = None, headers: dict | None = None):
    conn = HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    payload = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=payload, headers=headers or {})
    res = conn.getresponse()
    data = json.loads(res.read() or b"{}") if "json" in res.getheader("Content-Type", "") else res.read()
    conn.close()
    return res.status, data


def test_index_serves_the_page(server) -> None:
    conn = HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request("GET", "/")
    res = conn.getresponse()
    body = res.read()
    conn.close()
    assert res.status == 200
    assert b"playgate" in body


def test_meta_and_rules(server) -> None:
    status, meta = request(server, "GET", "/api/meta")
    assert status == 200
    assert meta["version"]
    status, rules = request(server, "GET", "/api/rules")
    assert status == 200
    assert any(r["name"] == "policy.target_api" for r in rules)


def test_scan_roundtrip(server, tmp_path: Path) -> None:
    root = tmp_path / "proj"
    write(root / "settings.gradle", "include ':app'\n")
    write(root / "app" / "build.gradle", "android { defaultConfig { targetSdk 30 } }\n")
    status, data = request(server, "POST", "/api/scan", {"target": str(root)})
    assert status == 200
    assert data["rejection_band"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert any(f["id"] == "PLY-TARGET-API" for f in data["findings"])
    assert "# playgate report" in data["markdown"]


def test_scan_bad_target_is_400(server) -> None:
    status, data = request(server, "POST", "/api/scan", {"target": "Z:/no/such/place/xyz"})
    assert status == 400
    assert "no such path" in data["error"]


def test_browse_lists_dirs_and_packages(server, tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "app.apk").write_bytes(b"PK")
    status, data = request(server, "POST", "/api/browse", {"path": str(tmp_path)})
    assert status == 200
    assert "sub" in data["dirs"]
    assert "app.apk" in data["packages"]


def test_init_writes_template_and_refuses_overwrite(server, tmp_path: Path) -> None:
    status, data = request(server, "POST", "/api/init", {"path": str(tmp_path)})
    assert status == 200
    assert (tmp_path / "playgate.toml").exists()
    status, data = request(server, "POST", "/api/init", {"path": str(tmp_path)})
    assert status == 409
    assert "already exists" in data["error"]


def test_foreign_host_header_is_refused(server) -> None:
    status, data = request(server, "GET", "/api/meta", headers={"Host": "evil.example.com"})
    assert status == 403


def test_foreign_origin_is_refused(server, tmp_path: Path) -> None:
    status, data = request(
        server, "POST", "/api/scan", {"target": str(tmp_path)},
        headers={"Origin": "https://evil.example.com", "Host": "127.0.0.1"},
    )
    assert status == 403
