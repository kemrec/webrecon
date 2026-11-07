"""Tiny on-disk JSON cache for CVE/enrichment lookups.

API responses (NVD per-CPE, OSV, EPSS per-CVE, the CISA KEV catalog) are stable
for hours and are the slowest, most rate-limited part of a scan. Caching them
to ``~/.cache/servicescan`` makes re-runs over the same hosts near-instant and
keeps big ranges under the NVD rate limit.

Each entry is a small JSON file named by a hash of its key, holding a timestamp
and the value. Reads honour a TTL; everything is best-effort (a broken/locked
cache never breaks a scan).
"""
from __future__ import annotations

import hashlib
import json
import os
import time

from webrecon import utils


def default_dir() -> str:
    base = (os.environ.get("XDG_CACHE_HOME")
            or os.path.join(os.path.expanduser("~"), ".cache"))
    return os.path.join(base, "servicescan")


class Cache:
    """File-backed key/value cache with per-read TTL. Disable with enabled=False."""

    def __init__(self, enabled: bool = True, ttl: int = 86400,
                 root: str | None = None):
        self.enabled = enabled
        self.ttl = ttl
        self.root = root or default_dir()
        if self.enabled:
            try:
                os.makedirs(self.root, exist_ok=True)
            except OSError as e:
                utils.debug(f"cache dir: {e}")
                self.enabled = False

    def _path(self, key: str) -> str:
        h = hashlib.sha1(key.encode("utf-8")).hexdigest()
        return os.path.join(self.root, f"{h}.json")

    def get(self, key: str, ttl: int | None = None):
        """Return the cached value, or None if missing/expired/disabled."""
        if not self.enabled:
            return None
        ttl = self.ttl if ttl is None else ttl
        path = self._path(key)
        try:
            with open(path, encoding="utf-8") as fh:
                blob = json.load(fh)
        except (OSError, ValueError):
            return None
        if ttl >= 0 and (time.time() - blob.get("ts", 0)) > ttl:
            return None
        return blob.get("v")

    def set(self, key: str, value) -> None:
        if not self.enabled:
            return
        path = self._path(key)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"ts": time.time(), "key": key, "v": value}, fh)
            os.replace(tmp, path)
        except (OSError, TypeError) as e:
            utils.debug(f"cache write {key}: {e}")
            try:
                os.remove(tmp)
            except OSError:
                pass
