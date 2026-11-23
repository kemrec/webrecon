"""The --web-time-budget knob: CLI mapping (bare = no limit, --full = 600s,
explicit overrides --full) and the servicescan->webrecon chain hands it through
to the per-port WebConfig.time_budget. web_orch.run is monkeypatched (no
network)."""
import asyncio

from servicescan import cli, chain
from servicescan.config import ScanConfig
from servicescan.models import ScanResult, Host, Service
from webrecon import orchestrator as web_orch, report as web_report


def _cfg_from(argv):
    return cli.cfg_from_args(cli.build_parser().parse_args(argv))


def test_cli_default_is_300():
    assert _cfg_from(["10.0.0.5"]).web_time_budget == 300.0


def test_cli_zero_means_no_limit():
    # an explicit 0 opts out of the budget (unlimited crawl)
    assert _cfg_from(["10.0.0.5", "--web", "--web-time-budget", "0"]
                     ).web_time_budget == 0.0


def test_cli_full_sets_600():
    assert _cfg_from(["10.0.0.5", "--full"]).web_time_budget == 600.0


def test_cli_explicit_budget():
    assert _cfg_from(["10.0.0.5", "--web", "--web-time-budget", "45"]
                     ).web_time_budget == 45.0


def test_cli_explicit_overrides_full():
    # an explicit --web-time-budget wins over the --full 600 default, matching
    # how --web-depth / --web-max-pages behave.
    assert _cfg_from(["10.0.0.5", "--full", "--web-time-budget", "30"]
                     ).web_time_budget == 30.0


def test_chain_passes_budget_to_webconfig(monkeypatch, tmp_path):
    seen = {}

    async def fake_run(wcfg, control=None):
        seen["time_budget"] = wcfg.time_budget
        return {"pages": {}, "urls": [], "endpoints": [], "params": {},
                "secrets": [], "vhosts": [], "subdomains": [], "tech": [],
                "forms": []}

    monkeypatch.setattr(web_orch, "run", fake_run)
    monkeypatch.setattr(web_report, "write_all", lambda outdir, data: None)

    svc = Service(port=80, proto="tcp", state="open", name="http")
    host = Host(target="10.0.0.9", ip="10.0.0.9", services=[svc])
    result = ScanResult(target="10.0.0.9", hosts=[host])
    cfg = ScanConfig(target="10.0.0.9", web=True, web_time_budget=120.0,
                     outdir=str(tmp_path))

    asyncio.run(chain.run_web_chain(cfg, result))
    assert seen["time_budget"] == 120.0
