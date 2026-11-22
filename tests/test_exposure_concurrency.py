"""run_exposure_checks fires its host-level UDP probes concurrently, not serially.

The four host-level probes (WS-Discovery 3702, SNMP 161, IPMI 623, SSDP 1900)
each wait out a UDP timeout on a silent host; running them sequentially made even
a one-port scan pay their *sum*. They are independent, so they must run at once.
This guards against anyone re-serialising them.
"""
import asyncio

import pytest

from servicescan import fingerprint
from servicescan.config import ScanConfig
from servicescan.models import Service


def test_host_udp_probes_run_concurrently(monkeypatch):
    # Each stubbed probe records that it STARTED, then blocks until all four have
    # started. Concurrent dispatch lets all four start together -> the gate opens
    # -> everything returns at once. Serial dispatch would leave the first probe
    # blocked (the others never start to open the gate), so the outer 5s wait_for
    # would fire -> the test fails. No real timeouts elapse on the happy path.
    started = []
    gate = asyncio.Event()

    def make():
        async def probe(host, port, timeout):
            started.append(port)
            if len(started) == 4:
                gate.set()
            await asyncio.wait_for(gate.wait(), timeout=30)
            return None            # no finding
        return probe

    for name in ("wsdiscovery_probe", "snmp_probe",
                 "ipmi_cipher_zero_probe", "ssdp_probe"):
        monkeypatch.setattr(fingerprint, name, make())

    # keep the per-service exposure check out of it (no network)
    async def _noop(cfg, host, svc):
        return None
    monkeypatch.setattr(fingerprint, "check_exposure", _noop)

    cfg = ScanConfig(target="h", targets=["h"], concurrency=50, timeout=8.0)
    # one open service so the host-level probes run at all (empty -> early return)
    svcs = [Service(port=80, proto="tcp", state="open", name="http")]

    async def run():
        await asyncio.wait_for(
            fingerprint.run_exposure_checks(cfg, "127.0.0.1", svcs), timeout=5)

    try:
        asyncio.run(run())
    except asyncio.TimeoutError:
        pytest.fail("host-level UDP probes did not run concurrently (serial dispatch?)")

    # all four fired (ports identify them), proving they were dispatched together
    assert sorted(started) == [161, 623, 1900, 3702]
