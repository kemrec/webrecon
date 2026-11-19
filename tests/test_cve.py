from servicescan import cve


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
