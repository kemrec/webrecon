"""Standard-library HTTP server exposing servicescan over a local JSON API.

Routes
------
GET  /api/health      -> {"ok": true, "service": "webrecon-ui"}
POST /api/scan        -> ScanResult.to_dict()   (body: a JSON scan request)
POST /api/scan.sarif  -> SARIF 2.1.0 document    (same body)

The POST body is a JSON object; only an allowlisted subset of ScanConfig fields
is honoured (see _ALLOWED), so a request can never set, e.g., an arbitrary
nmap_path or output directory. Scanning itself is delegated to run_scan(), a
module-level indirection the tests monkeypatch so they never touch the network.

Bind to 127.0.0.1 unless you really mean to expose the console: the API runs
scans against whatever target the caller names, so it must not be reachable by
untrusted clients.
"""
from __future__ import annotations

import asyncio
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from servicescan import formats, fingerprint
from servicescan.config import ScanConfig
from servicescan.orchestrator import run as _orchestrator_run

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Only these files are ever served from disk; there is no directory walk and no
# user-supplied path reaches the filesystem, so path traversal is impossible.
_STATIC = {
    "/":           ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
}

# Largest POST body we will read (a scan request is tiny; this just caps abuse).
MAX_BODY = 64 * 1024

# JSON request field -> (ScanConfig attribute, coercer). Anything not listed is
# ignored, so the web surface can never reach sensitive/local-only config such
# as nmap_path, nmap_args, outdir, or realm injection.
def _as_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def _as_ports(v) -> str:
    # nmap -p spec: a plain string; reject anything exotic.
    s = str(v).strip()
    return s or "-"


_ALLOWED = {
    "ports":       ("ports", _as_ports),
    "use_nmap":    ("use_nmap", _as_bool),
    "top_ports":   ("top_ports", lambda v: int(v) if v not in (None, "") else None),
    "udp":         ("udp", _as_bool),
    "nse":         ("nse", _as_bool),
    "fingerprint": ("fingerprint", _as_bool),
    "fp_all":      ("fp_all", _as_bool),
    "cve":         ("cve", _as_bool),
    "min_cvss":    ("min_cvss", lambda v: float(v) if v not in (None, "") else 0.0),
    "kev_high_only": ("kev_high_only", _as_bool),
    "exploits":    ("exploits", _as_bool),
    "timeout":     ("timeout", lambda v: float(v)),
    "concurrency": ("concurrency", lambda v: int(v)),
}


class BadRequest(ValueError):
    """Raised for a malformed scan request (mapped to HTTP 400)."""


def build_config(payload: dict) -> ScanConfig:
    """Map a JSON request object to a ScanConfig (allowlisted fields only).

    `target` is required and may be a string ("10.0.0.0/24 host2") or a list of
    tokens. Raises BadRequest on anything unusable.
    """
    if not isinstance(payload, dict):
        raise BadRequest("request body must be a JSON object")

    raw = payload.get("target", "")
    if isinstance(raw, list):
        tokens = [str(t).strip() for t in raw if str(t).strip()]
    else:
        tokens = str(raw).split()
    if not tokens:
        raise BadRequest("'target' is required")

    cfg = ScanConfig(target=" ".join(tokens), targets=tokens)
    for key, (attr, coerce) in _ALLOWED.items():
        if key in payload:
            try:
                setattr(cfg, attr, coerce(payload[key]))
            except (TypeError, ValueError):
                raise BadRequest(f"invalid value for '{key}'")
    return cfg


def run_scan(cfg: ScanConfig):
    """Run one scan to completion and return the ScanResult.

    Module-level so tests can monkeypatch it (webrecon_ui.server.run_scan) to
    avoid any real network activity.
    """
    return asyncio.run(_orchestrator_run(cfg))


class Handler(BaseHTTPRequestHandler):
    server_version = "webrecon-ui"
    protocol_version = "HTTP/1.1"

    # -- helpers ----------------------------------------------------------
    def _send_json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, code: int, message: str) -> None:
        self._send_json(code, {"error": message})

    def _send_bytes(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _serve_static(self, name: str, ctype: str) -> None:
        try:
            with open(os.path.join(STATIC_DIR, name), "rb") as fh:
                body = fh.read()
        except OSError:
            self._error(404, "not found")
            return
        self._send_bytes(200, body, ctype)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise BadRequest("empty request body")
        if length > MAX_BODY:
            raise BadRequest("request body too large")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise BadRequest("request body is not valid JSON")

    # -- routing ----------------------------------------------------------
    def do_GET(self):  # noqa: N802
        if self.path == "/api/health":
            self._send_json(200, {"ok": True, "service": "webrecon-ui"})
            return
        if self.path == "/favicon.ico":
            self._send_bytes(204, b"", "image/x-icon")
            return
        if self.path == "/api/alert-ids":
            # The source of truth for which script ids are unauthenticated-breach
            # alerts (vs informational) lives in Python; the UI fetches it to
            # colour exposure findings, so the two never drift.
            self._send_json(200, {"alert_ids": sorted(fingerprint.EXPOSURE_ALERT_IDS)})
            return
        static = _STATIC.get(self.path)
        if static is not None:
            self._serve_static(*static)
            return
        self._error(404, "not found")

    def do_POST(self):  # noqa: N802
        if self.path not in ("/api/scan", "/api/scan.sarif"):
            self._error(404, "not found")
            return
        try:
            payload = self._read_json_body()
            cfg = build_config(payload)
        except BadRequest as e:
            self._error(400, str(e))
            return

        try:
            result = run_scan(cfg)
        except Exception as e:  # noqa: BLE001
            self._error(500, f"scan failed: {e}")
            return

        if self.path == "/api/scan.sarif":
            self._send_json(200, formats.build_sarif(result))
        else:
            self._send_json(200, result.to_dict())

    def log_message(self, fmt, *args):  # silence default stderr access log
        pass


def make_server(host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    """Create (but do not start) the UI server bound to host:port."""
    return ThreadingHTTPServer((host, port), Handler)


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="webrecon-ui",
        description="Local web UI for servicescan (localhost operator console).")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default 127.0.0.1; do NOT expose publicly)")
    p.add_argument("--port", type=int, default=8787, help="bind port (default 8787)")
    a = p.parse_args(argv)

    httpd = make_server(a.host, a.port)
    if a.host not in ("127.0.0.1", "::1", "localhost"):
        print(f"WARNING: binding {a.host} exposes a scan-launching API to the "
              "network; prefer 127.0.0.1.")
    print(f"webrecon-ui on http://{a.host}:{a.port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
