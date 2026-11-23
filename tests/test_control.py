"""ScanControl: the cooperative pause / stop primitive. A checkpoint raises
ScanStopped on stop and blocks (without busy-spinning) while paused until a
resume or a stop. All async, no network."""
import asyncio

import pytest

from webrecon.control import ScanControl, ScanStopped


def test_initial_state_running():
    c = ScanControl()
    assert c.state() == "running"
    assert not c.stopped and not c.paused


def test_pause_resume_state():
    c = ScanControl()
    c.pause()
    assert c.paused and c.state() == "paused"
    c.resume()
    assert not c.paused and c.state() == "running"


def test_stop_supersedes_pause():
    c = ScanControl()
    c.pause()
    c.stop()
    assert c.stopped and c.state() == "stopped"
    assert c.paused is False          # a stop clears the paused view
    # a pause after a stop is ignored (stop is terminal)
    c.pause()
    assert c.state() == "stopped"


def test_checkpoint_running_returns():
    async def go():
        await ScanControl().checkpoint()
    asyncio.run(asyncio.wait_for(go(), timeout=2))   # returns promptly


def test_checkpoint_stopped_raises():
    async def go():
        c = ScanControl()
        c.stop()
        await c.checkpoint()
    with pytest.raises(ScanStopped):
        asyncio.run(asyncio.wait_for(go(), timeout=2))


def test_checkpoint_blocks_while_paused_then_resumes():
    async def go():
        c = ScanControl()
        c.pause()
        t = asyncio.ensure_future(c.checkpoint(poll=0.01))
        await asyncio.sleep(0.05)
        assert not t.done()          # still blocked while paused
        c.resume()
        await t                      # unblocks on resume, no exception
    asyncio.run(asyncio.wait_for(go(), timeout=2))


def test_checkpoint_paused_then_stopped_raises():
    async def go():
        c = ScanControl()
        c.pause()
        t = asyncio.ensure_future(c.checkpoint(poll=0.01))
        await asyncio.sleep(0.05)
        c.stop()                     # stop while paused -> checkpoint raises
        await t
    with pytest.raises(ScanStopped):
        asyncio.run(asyncio.wait_for(go(), timeout=2))
