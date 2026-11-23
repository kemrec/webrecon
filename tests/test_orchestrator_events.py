"""servicescan.orchestrator.run on_event milestones (drives the web UI's SSE).

Runs the real orchestrator on the no-nmap fallback path (seeded common ports)
with fingerprint/CVE off and the web chain stubbed, so no network is touched;
only the event sequence is asserted.
"""
import asyncio

from servicescan import orchestrator, chain
from servicescan.config import ScanConfig


def _cfg(**kw):
    base = dict(target="127.0.0.1", targets=["127.0.0.1"], use_nmap=False,
                fingerprint=False, cve=False)
    base.update(kw)
    return ScanConfig(**base)


def _run(cfg):
    events = []
    result = asyncio.run(orchestrator.run(cfg, on_event=events.append))
    return events, result


def test_emits_start_and_per_host():
    events, _ = _run(_cfg())
    types = [e["type"] for e in events]
    assert types[0] == "start"
    assert events[0]["nhosts"] >= 1
    assert "host" in types
    # a host event carries the full host dict (seeded services present)
    host_ev = next(e for e in events if e["type"] == "host")
    assert host_ev["host"]["services"]


def test_no_update_event_without_web_chain():
    events, _ = _run(_cfg(web=False))
    assert "update" not in [e["type"] for e in events]


def test_update_event_after_web_chain(monkeypatch):
    calls = {"n": 0}

    async def stub_chain(cfg, result, control=None):
        calls["n"] += 1          # chain ran; it would enrich svc.web here

    monkeypatch.setattr(chain, "run_web_chain", stub_chain)
    events, _ = _run(_cfg(web=True))
    types = [e["type"] for e in events]
    assert calls["n"] == 1
    assert types[-1] == "update"                 # emitted after the chain
    assert isinstance(events[-1]["hosts"], list)
    assert events[-1]["hosts"]                    # enriched hosts pushed again
