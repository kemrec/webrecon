import json
import os
from webrecon import utils


def _result_with_cves():
    from servicescan.models import ScanResult, Host, Service, CVE
    svc = Service(port=8080, name="http", state="open", product="X", version="1")
    svc.cves = [
        CVE(id="CVE-CRIT", source="nvd", cvss=9.8, severity="CRITICAL"),
        CVE(id="CVE-HIGH", source="nvd", cvss=7.5, severity="HIGH"),
        CVE(id="CVE-MED", source="nvd", cvss=5.0, severity="MEDIUM"),
        CVE(id="CVE-MED-KEV", source="nvd", cvss=5.0, severity="MEDIUM", kev=True),
    ]
    return ScanResult(target="10.0.0.5",
                      hosts=[Host(target="10.0.0.5", ip="10.0.0.5",
                                  services=[svc])])


def test_kev_high_filters_reports_but_scanjson_keeps_everything(tmp_path):
    from servicescan import report
    out = str(tmp_path / "o")
    result = _result_with_cves()
    report.write_all(out, result, kev_high_only=True)

    # scan.json is the complete record -- all four CVEs, medium included
    data = json.load(open(os.path.join(out, "scan.json")))
    ids = {c["id"] for h in data["hosts"] for s in h["services"] for c in s["cves"]}
    assert ids == {"CVE-CRIT", "CVE-HIGH", "CVE-MED", "CVE-MED-KEV"}

    # cves.txt (human output) drops the plain medium, keeps crit/high/KEV-medium
    txt = open(os.path.join(out, "cves.txt")).read()
    assert "CVE-CRIT" in txt and "CVE-HIGH" in txt and "CVE-MED-KEV" in txt
    assert "\tCVE-MED\t" not in txt           # the plain medium is hidden
    assert getattr(result, "_kev_high_hidden", 0) == 1


def test_no_filter_shows_all_cves_in_reports(tmp_path):
    from servicescan import report
    out = str(tmp_path / "o")
    result = _result_with_cves()
    report.write_all(out, result)             # default: no kev-high filter
    txt = open(os.path.join(out, "cves.txt")).read()
    assert "\tCVE-MED\t" in txt                # medium visible when unfiltered
    assert getattr(result, "_kev_high_hidden", 0) == 0


def test_target_slug():
    assert utils.target_slug("http://10.0.0.5:8080/app") == "10.0.0.5_8080"
    assert utils.target_slug("https://example.com/a/b?x=1") == "example.com"
    assert utils.target_slug("10.0.0.0/24") == "10.0.0.0_24"
    assert utils.target_slug("scanme.nmap.org") == "scanme.nmap.org"
    assert utils.target_slug("") == "scan"


def test_run_dir_layout(tmp_path):
    base = str(tmp_path / "out")
    d1 = utils.run_dir(base, "http://10.0.0.5/")
    assert os.path.isdir(d1)
    # <base>/10.0.0.5/<timestamp>
    assert os.path.basename(os.path.dirname(d1)) == "10.0.0.5"
    link = os.path.join(base, "10.0.0.5", "latest")
    assert os.path.islink(link)
    assert os.path.realpath(link) == os.path.realpath(d1)


def test_run_dir_never_overwrites(tmp_path):
    base = str(tmp_path / "out")
    a = utils.run_dir(base, "10.0.0.5")
    b = utils.run_dir(base, "10.0.0.5")
    assert a != b                      # second run gets its own directory
    # latest points at the most recent
    link = os.path.join(base, "10.0.0.5", "latest")
    assert os.path.realpath(link) == os.path.realpath(b)


def test_run_dir_flat(tmp_path):
    base = str(tmp_path / "flat")
    d = utils.run_dir(base, "10.0.0.5", flat=True)
    assert d == base
    assert os.path.isdir(base)
