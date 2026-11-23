"""Cooperative pause / stop control for a running scan.

A :class:`ScanControl` is a tiny thread-safe signal object: the scan runs in one
thread (the asyncio worker) while pause / resume / stop requests arrive on other
threads (HTTP request handlers). The scan calls ``await control.checkpoint()`` at
safe boundaries -- between hosts, before the long CVE step, before the web chain,
and inside the crawl worker loop. At a checkpoint the scan:

  * raises :class:`ScanStopped` if a stop was requested (the caller unwinds
    gracefully and returns the partial result -- no crash, no cancelled task), or
  * blocks cooperatively (``await asyncio.sleep``) while paused, until it is
    resumed or stopped.

The flags are plain booleans; under CPython a bool read/write is atomic, so no
lock is needed for this one-way signalling. Control is always optional: pass
``None`` (the default everywhere) and the scan behaves exactly as before.
"""
from __future__ import annotations

import asyncio


class ScanStopped(Exception):
    """Raised at a checkpoint when a stop has been requested."""


class ScanControl:
    def __init__(self) -> None:
        self._stopped = False
        self._paused = False

    # -- signals (called from any thread) --------------------------------
    def stop(self) -> None:
        self._stopped = True
        self._paused = False          # a stop supersedes a pause

    def pause(self) -> None:
        if not self._stopped:
            self._paused = True

    def resume(self) -> None:
        self._paused = False

    @property
    def stopped(self) -> bool:
        return self._stopped

    @property
    def paused(self) -> bool:
        return self._paused and not self._stopped

    def state(self) -> str:
        if self._stopped:
            return "stopped"
        return "paused" if self._paused else "running"

    # -- checkpoint (called from the scan's async code) ------------------
    async def checkpoint(self, poll: float = 0.15) -> None:
        """Honour a pending stop/pause at a safe boundary.

        Raises :class:`ScanStopped` on stop; otherwise returns once the scan is
        running (sleeping in small increments while paused so a later resume or
        stop takes effect promptly without busy-spinning)."""
        if self._stopped:
            raise ScanStopped
        while self._paused:
            await asyncio.sleep(poll)
            if self._stopped:
                raise ScanStopped
