"""Version-unscoped CVE marker: product known but no version -> wildcard CPE
pulls every CVE for the product, so the service is flagged."""
import asyncio
import io
from contextlib import redirect_stdout

from servicescan import cve, report
from servicescan.config import ScanConfig
from servicescan.models import Service, CVE


def _cfg():
    return ScanConfig(target="x", nvd=True, osv=False, epss=False, kev=False,
                      exploits=False, min_cvss=0.0, cve_cache=False)


def _correlate(svc, monkeypatch):
    async def fake_query_nvd(http, cfg, cpe, kw, cache=None, products=None,
                             want_version=""):
        return [CVE(id="CVE-2020-0001", source="nvd", cvss=9.8, severity="CRITICAL")] \
            if (cpe or kw) else []
    monkeypatch.setattr(cve, "query_nvd", fake_query_nvd)
    asyncio.run(cve.correlate(_cfg(), None, [svc]))


def test_versionless_primary_is_flagged(monkeypatch):
    svc = Service(port=8983, name="http", state="open", product="Apache Solr")
    _correlate(svc, monkeypatch)
    assert svc.cves, "expected CVEs from the wildcard lookup"
    assert svc.cve_unscoped is True


def test_versioned_primary_is_not_flagged(monkeypatch):
    svc = Service(port=8983, name="http", state="open", product="Apache Solr",
                  version="8.11.4")
    _correlate(svc, monkeypatch)
    assert svc.cves
    assert svc.cve_unscoped is False


def test_no_product_not_flagged(monkeypatch):
    svc = Service(port=12345, name="unknown", state="open")   # no product
    _correlate(svc, monkeypatch)
    assert svc.cve_unscoped is False


def test_warning_printed_when_flagged():
    svc = Service(port=8983, name="http", state="open", product="Apache Solr")
    svc.cve_unscoped = True
    svc.cves = [CVE(id="CVE-2020-0001", source="nvd", cvss=9.8, severity="CRITICAL")]
    buf = io.StringIO()
    with redirect_stdout(buf):
        report._print_service(svc)
    assert "version unknown" in buf.getvalue()


def test_no_warning_when_versioned():
    svc = Service(port=8983, name="http", state="open", product="Apache Solr",
                  version="8.11.4")
    svc.cves = [CVE(id="CVE-2020-0001", source="nvd", cvss=9.8, severity="CRITICAL")]
    buf = io.StringIO()
    with redirect_stdout(buf):
        report._print_service(svc)
    assert "version unknown" not in buf.getvalue()
