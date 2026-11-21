"""SARIF 2.1.0 output (scan.sarif) -- CVE findings + unauth-exposure alerts."""
import json
import os
import tempfile

from servicescan import formats
from servicescan.models import CVE, Host, Service, ScanResult


def _result():
    svc = Service(port=6379, proto="tcp", state="open", name="redis",
                  product="Redis", version="7.0.0")
    svc.cves = [
        CVE(id="CVE-2022-0543", source="nvd", cvss=10.0, severity="CRITICAL",
            summary="Lua sandbox escape -> RCE", url="https://nvd/cve-2022-0543",
            kev=True, epss=0.9),
        CVE(id="CVE-2021-99999", source="osv", cvss=5.5, severity="MEDIUM",
            summary="a medium issue", url="https://osv/x"),
    ]
    svc.scripts = [
        {"id": "redis-unauth", "output": "Redis reachable WITHOUT authentication."},
        {"id": "grpc-methods", "output": "informational, not a finding"},
    ]
    host = Host(target="10.0.0.5", ip="10.0.0.5",
                services=[svc,
                          Service(port=22, proto="tcp", state="open", name="ssh")])
    return ScanResult(target="10.0.0.5", hosts=[host])


def _write_and_load():
    d = tempfile.mkdtemp()
    formats.write_sarif(d, _result())
    with open(os.path.join(d, "scan.sarif"), encoding="utf-8") as fh:
        return json.load(fh)


def test_sarif_envelope_and_schema():
    doc = _write_and_load()
    assert doc["version"] == "2.1.0"
    assert "sarif" in doc["$schema"]
    assert doc["runs"][0]["tool"]["driver"]["name"] == "servicescan"


def test_sarif_has_cve_and_exposure_results():
    doc = _write_and_load()
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    result_rules = [r["ruleId"] for r in run["results"]]
    # both CVEs and the exposure alert are present...
    assert {"CVE-2022-0543", "CVE-2021-99999", "redis-unauth"} <= rule_ids
    assert "redis-unauth" in result_rules
    # ...but the informational (non-alert) script is NOT a finding
    assert "grpc-methods" not in rule_ids
    assert "grpc-methods" not in result_rules


def test_sarif_levels_and_security_severity():
    doc = _write_and_load()
    run = doc["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    results = {r["ruleId"]: r for r in run["results"]}
    # critical CVE -> error + security-severity from CVSS
    assert results["CVE-2022-0543"]["level"] == "error"
    assert rules["CVE-2022-0543"]["properties"]["security-severity"] == "10.0"
    # medium CVE -> warning
    assert results["CVE-2021-99999"]["level"] == "warning"
    # exposure alert -> error
    assert results["redis-unauth"]["level"] == "error"


def test_sarif_location_and_fingerprint():
    doc = _write_and_load()
    res = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    loc = res["redis-unauth"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "10.0.0.5:6379/tcp"
    fp = res["redis-unauth"]["partialFingerprints"]["servicescan/v1"]
    assert fp == "10.0.0.5:6379:redis-unauth"
    # KEV flag carried through on the CVE result properties
    assert res["CVE-2022-0543"]["properties"]["kev"] is True


def test_sarif_empty_scan_is_valid():
    d = tempfile.mkdtemp()
    formats.write_sarif(d, ScanResult(target="x", hosts=[]))
    with open(os.path.join(d, "scan.sarif"), encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_write_extra_emits_sarif():
    d = tempfile.mkdtemp()
    formats.write_extra(d, _result())
    assert os.path.exists(os.path.join(d, "scan.sarif"))
