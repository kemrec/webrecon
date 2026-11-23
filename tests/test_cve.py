import asyncio
import json

from servicescan import cve
from servicescan.config import ScanConfig


def test_normalize_version():
    assert cve.normalize_version("4.7p1 Debian 8ubuntu1") == "4.7p1"
    assert cve.normalize_version("5.0.51a-3ubuntu5") == "5.0.51a"
    assert cve.normalize_version("8.3.0 - 8.3.7") == "8.3.0"
    assert cve.normalize_version("2.2.8 (Ubuntu)") == "2.2.8"
    assert cve.normalize_version("") == ""
    assert cve.normalize_version("Coyote") == ""   # must start with a digit


def test_make_cpe():
    assert cve.make_cpe("Apache", "2.4.49") == \
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert cve.make_cpe("OpenSSH", "7.4") == \
        "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
    assert cve.make_cpe("totally-unknown-xyz", "1.0") is None


def test_nginx_maps_to_f5_vendor():
    # NVD reclassified nginx under the "f5" vendor after F5 acquired nginx; the
    # old "nginx:nginx" cpeName returns ZERO from NVD, so the map must target
    # f5 or EVERY nginx CVE is silently missed (false negatives at any version).
    assert cve.make_cpe("nginx", "1.18.0") == \
        "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
    # a real f5:nginx CVE node (CVE-2021-23017: resolver off-by-one, fixed in
    # 1.20.1) must apply to an older nginx and not to a patched one, matched via
    # our "nginx" product token against the CPE's product field.
    obj = _cve(criteria="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
               versionEndExcluding="1.20.1")
    assert cve.version_applies(obj, {"nginx"}, "1.18.0",
                               require_product=True) is True
    assert cve.version_applies(obj, {"nginx"}, "1.30.6",
                               require_product=True) is False


def test_cpe22_to_23():
    assert cve.cpe22_to_23("cpe:/a:apache:http_server:2.4.49") == \
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    # already 2.3 -> unchanged
    v23 = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert cve.cpe22_to_23(v23) == v23
    assert cve.cpe22_to_23(None) is None


def test_vcmp():
    assert cve._vcmp("1.2.3", "1.2.4") == -1
    assert cve._vcmp("1.2.3", "1.2.3") == 0
    assert cve._vcmp("2.0.0", "1.9.9") == 1


def _cve(criteria=None, **bounds):
    m = {"vulnerable": True, "criteria": criteria or
         "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}
    m.update(bounds)
    return {"configurations": [{"nodes": [{"cpeMatch": [m]}]}]}


def test_match_cpe_exact_version():
    m = {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
    assert cve._match_cpe(m, "2.4.49") is True
    assert cve._match_cpe(m, "2.4.50") is False


def test_match_cpe_range():
    m = {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}
    assert cve._match_cpe(m, "2.4.49") is True
    assert cve._match_cpe(m, "2.4.50") is False   # end-excluding
    assert cve._match_cpe(m, "2.3.9") is False    # below start


def test_version_applies_keeps_matching_product_version():
    obj = _cve(criteria="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert cve.version_applies(obj, {"http_server"}, "2.4.49") is True
    assert cve.version_applies(obj, {"http_server"}, "2.4.50") is False


def test_version_applies_wrong_product_keyword_mode_drops():
    obj = _cve(criteria="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    # strict keyword mode: our product never appears -> drop
    assert cve.version_applies(obj, {"grafana"}, "9.0", require_product=True) is False
    # conservative CPE-anchored mode: can't disprove -> keep
    assert cve.version_applies(obj, {"grafana"}, "9.0", require_product=False) is True


def test_keep_kev_or_high_filter():
    from servicescan.models import CVE
    crit = CVE(id="C", source="nvd", cvss=9.8, severity="CRITICAL")
    high = CVE(id="H", source="nvd", cvss=7.5, severity="HIGH")
    med = CVE(id="M", source="nvd", cvss=5.0, severity="MEDIUM")
    med_kev = CVE(id="MK", source="nvd", cvss=5.0, severity="MEDIUM", kev=True)
    # environmentally demoted: canonical 7.4 but effective 0.0/LOW -> must drop
    demoted = CVE(id="D", source="nvd", cvss=7.4, severity="HIGH",
                  effective_cvss=0.0, effective_severity="LOW")
    kept = {c.id for c in cve.keep_kev_or_high([crit, high, med, med_kev, demoted])}
    assert kept == {"C", "H", "MK"}       # critical, high, and the KEV medium
    assert "M" not in kept                # plain medium hidden
    assert "D" not in kept                # demoted-to-LOW judged by disp_cvss


class _NvdResp:
    def __init__(self, text):
        self.text = text
        self.status = 200
        self.ok = True


class _NvdHTTP:
    """Returns one canned NVD payload for any fetch (single page)."""
    def __init__(self, payload):
        self._text = json.dumps(payload)

    async def fetch(self, url, method="GET", headers=None, read_body=True):
        return _NvdResp(self._text)


def _nvd_payload(*cves):
    vulns = [{"cve": {"id": cid, "descriptions": [], "metrics": {},
                      "configurations": confs}} for cid, confs in cves]
    return {"totalResults": len(vulns), "vulnerabilities": vulns}


def _conf(criteria, **bounds):
    m = {"vulnerable": True, "criteria": criteria}
    m.update(bounds)
    return [{"nodes": [{"cpeMatch": [m]}]}]


def test_query_nvd_cpe_path_prunes_wrong_version_defense_in_depth():
    # A cpeName+isVulnerable lookup for http_server 2.4.49 returns two CVEs; NVD
    # mis-included one whose only node starts at 2.5.0. The conservative cpe gate
    # must drop that one while keeping the correctly-scoped hit.
    keep = ("CVE-KEEP",
            _conf("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"))
    drop = ("CVE-DROP",
            _conf("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                  versionStartIncluding="2.5.0"))
    http = _NvdHTTP(_nvd_payload(keep, drop))
    cfg = ScanConfig(target="x")
    out = asyncio.run(cve.query_nvd(
        http, cfg, cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        keyword=None, products={"http_server"}, want_version="2.4.49"))
    ids = {c.id for c in out}
    assert "CVE-KEEP" in ids
    assert "CVE-DROP" not in ids


def test_query_nvd_cpe_path_keeps_product_absent():
    # conservative cpe gate must NOT drop a hit whose CPEs never mention our
    # product (a vendor/product-name mismatch, not a wrong-version row).
    other = ("CVE-OTHER",
             _conf("cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*"))
    http = _NvdHTTP(_nvd_payload(other))
    cfg = ScanConfig(target="x")
    out = asyncio.run(cve.query_nvd(
        http, cfg, cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        keyword=None, products={"http_server"}, want_version="2.4.49"))
    assert {c.id for c in out} == {"CVE-OTHER"}


def test_only_unbounded_match():
    unb = {"configurations":
           _conf("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")}
    assert cve._only_unbounded_match(unb, {"openssh"}) is True
    # a real version bound present -> legitimately scoped, not unbounded
    bounded = {"configurations":
               _conf("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                     versionEndExcluding="9.8")}
    assert cve._only_unbounded_match(bounded, {"openssh"}) is False
    # an explicit version in the CPE field is also a bound
    exact = {"configurations":
             _conf("cpe:2.3:a:openbsd:openssh:4.7p1:*:*:*:*:*:*:*")}
    assert cve._only_unbounded_match(exact, {"openssh"}) is False
    # product never named -> nothing of ours to demote
    other = {"configurations":
             _conf("cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*")}
    assert cve._only_unbounded_match(other, {"openssh"}) is False


def test_query_nvd_demotes_unbounded_wildcard_cve():
    # OpenSSH 9.6p1: a legacy CVE whose only openssh node is an unbounded
    # wildcard (no version range at all) attaches to EVERY build and otherwise
    # reads as a live finding (the 2008-CVE-on-a-2026-SSH false positive). It is
    # demoted to LOW with a caveat but kept as intel; a properly version-scoped
    # CVE on the same product is left untouched.
    legacy = ("CVE-2008-9999",
              _conf("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"))
    scoped = ("CVE-2024-6387",
              _conf("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                    versionEndExcluding="9.8"))
    http = _NvdHTTP(_nvd_payload(legacy, scoped))
    cfg = ScanConfig(target="x")
    out = asyncio.run(cve.query_nvd(
        http, cfg, cpe="cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*",
        keyword=None, products={"openssh"}, want_version="9.6p1"))
    by = {c.id: c for c in out}
    assert set(by) == {"CVE-2008-9999", "CVE-2024-6387"}   # kept, never dropped
    d = by["CVE-2008-9999"]
    assert d.effective_cvss == 0.0
    assert d.disp_severity() == "LOW"
    assert d.env_note                                       # caveat present
    s = by["CVE-2024-6387"]
    assert s.effective_cvss is None and s.env_note == ""    # scoped: untouched


def test_query_nvd_no_demote_when_version_unknown():
    # with no detected version the whole service is flagged unscoped elsewhere;
    # query_nvd must not demote here (nothing to compare against).
    legacy = ("CVE-2008-9999",
              _conf("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"))
    http = _NvdHTTP(_nvd_payload(legacy))
    cfg = ScanConfig(target="x")
    out = asyncio.run(cve.query_nvd(
        http, cfg, cpe="cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        keyword=None, products={"openssh"}, want_version=""))
    assert out[0].env_note == "" and out[0].effective_cvss is None


class _ByProductNvdHTTP:
    """Returns a different NVD payload depending on which product the query is
    for, so the nginx multi-base union is observable. Checks substrings in order."""
    def __init__(self, routes):
        self._routes = routes          # list of (needle, payload-dict)

    async def fetch(self, url, method="GET", headers=None, read_body=True):
        for needle, payload in self._routes:
            if needle in url:
                return _NvdResp(json.dumps(payload))
        return _NvdResp(json.dumps(_nvd_payload()))   # empty


def test_correlate_nginx_unions_open_source_base():
    # NVD split nginx: the legacy "f5:nginx" entry holds only older CVEs, while
    # every 2024+ CVE (CVE-2024-7347 etc.) is filed under "f5:nginx_open_source".
    # correlate must query BOTH bases and union, or recent nginx CVEs are missed.
    from servicescan.models import Service
    old = ("CVE-OLD", _conf("cpe:2.3:a:f5:nginx:1.27.0:*:*:*:*:*:*:*"))
    oss = ("CVE-OSS", _conf("cpe:2.3:a:f5:nginx_open_source:*:*:*:*:*:*:*:*",
                            versionStartIncluding="1.5.13",
                            versionEndExcluding="1.27.1"))
    http = _ByProductNvdHTTP([
        ("nginx_open_source", _nvd_payload(oss)),   # check the longer name first
        ("f5:nginx:", _nvd_payload(old)),
    ])
    cfg = ScanConfig(target="x", nvd=True, osv=False, epss=False, kev=False,
                     min_cvss=0.0, kev_high_only=False, cve_cache=False)
    svc = Service(port=80, proto="tcp", state="open", name="http",
                  product="nginx", version="1.27.0")
    asyncio.run(cve.correlate(cfg, http, [svc]))
    ids = {c.id for c in svc.cves}
    assert ids == {"CVE-OLD", "CVE-OSS"}      # both bases unioned

    # a product with no extra base is unaffected: only its single base is queried
    http2 = _ByProductNvdHTTP([
        ("http_server", _nvd_payload(
            ("CVE-A", _conf("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")))),
        ("nginx_open_source", _nvd_payload(("CVE-X", _conf("x")))),
    ])
    svc2 = Service(port=80, proto="tcp", state="open", name="http",
                   product="apache", version="2.4.49")
    asyncio.run(cve.correlate(cfg, http2, [svc2]))
    assert {c.id for c in svc2.cves} == {"CVE-A"}   # no stray open_source query


def test_correlate_nginx2root_boundary_via_open_source():
    # nginx2root (Nov 2026, CVE-2026-123007 et al.): five HTTP/2/HTTP/3/resolver/
    # mail use-after-free CVEs, all filed under f5:nginx_open_source, affecting up
    # to 1.31.8 and fixed in 1.31.9/1.30.7. A representative one must be matched on
    # an affected version and pruned on the fix -- proving the open_source base +
    # the version range gate together give correct nginx2root coverage.
    from servicescan.models import Service
    n2r = ("CVE-2026-123007",
           _conf("cpe:2.3:a:f5:nginx_open_source:*:*:*:*:*:*:*:*",
                 versionStartIncluding="1.9.5", versionEndExcluding="1.31.9"))
    http = _ByProductNvdHTTP([("nginx_open_source", _nvd_payload(n2r))])
    cfg = ScanConfig(target="x", nvd=True, osv=False, epss=False, kev=False,
                     min_cvss=0.0, kev_high_only=False, cve_cache=False)

    affected = Service(port=80, proto="tcp", state="open", name="http",
                       product="nginx", version="1.27.0")
    asyncio.run(cve.correlate(cfg, http, [affected]))
    assert "CVE-2026-123007" in {c.id for c in affected.cves}

    fixed = Service(port=80, proto="tcp", state="open", name="http",
                    product="nginx", version="1.31.9")
    asyncio.run(cve.correlate(cfg, http, [fixed]))
    assert "CVE-2026-123007" not in {c.id for c in fixed.cves}
