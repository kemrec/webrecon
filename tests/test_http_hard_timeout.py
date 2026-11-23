"""A server that sends headers then never finishes the body (slow-trickle)
would hang a fetch forever under httpx's per-read timeout. The hard total cap
(request_hard_timeout) must abandon it and return a failed Response, bounded."""
import asyncio
import time

from webrecon.config import Config
from webrecon.http_client import HTTPClient


async def _hang_body(reader, writer):
    """Answer with a Content-Length that promises 100 bytes, send only 1, then
    hold the connection briefly without ever sending the rest."""
    try:
        await reader.read(4096)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nX")
        await writer.drain()
        await asyncio.sleep(5)           # hang: never send the remaining 99 bytes
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def test_fetch_hard_timeout_abandons_trickling_body():
    async def run():
        server = await asyncio.start_server(_hang_body, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        cfg = Config(target="http://x/", timeout=12.0, retries=0,
                     request_hard_timeout=1.0, concurrency=1)
        http = HTTPClient(cfg)
        t0 = time.monotonic()
        r = await http.fetch(f"http://127.0.0.1:{port}/")
        elapsed = time.monotonic() - t0
        await http.close()
        server.close()                   # don't wait_closed: the handler sleeps
        return r, elapsed

    r, elapsed = asyncio.run(asyncio.wait_for(run(), timeout=10))
    # the per-read timeout is 12s; the 1s hard cap must fire well before it
    assert not r.ok
    assert elapsed < 5.0, f"fetch took {elapsed:.1f}s, hard cap did not fire"
