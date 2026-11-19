from servicescan import report
from servicescan.models import ScanResult, Host, Service


def _targets(hosts):
    r = ScanResult(target="lab")
    r.hosts = hosts
    return report._web_targets(r)


def test_web_targets_basic_scheme_and_port():
    out = _targets([Host(target="10.0.0.5", ip="10.0.0.5", services=[
        Service(port=80, name="http", state="open"),
        Service(port=443, name="https", state="open"),
    ])])
    assert out == ["http://10.0.0.5:80", "https://10.0.0.5:443"]


def test_web_targets_excludes_non_web_and_closed():
    out = _targets([Host(target="h", ip="10.0.0.5", services=[
        Service(port=22, name="ssh", state="open"),          # not web
        Service(port=3306, name="mysql", state="open"),      # not web
        Service(port=8080, name="http", state="closed"),     # closed
        Service(port=80, name="http", state="open"),         # the only hit
    ])])
    assert out == ["http://10.0.0.5:80"]


def test_web_targets_tls_detected_by_cert_or_canonical_port():
    out = _targets([Host(target="h", ip="10.0.0.5", services=[
        Service(port=8443, name="", state="open", tls={"subject_cn": "x"}),
        Service(port=9443, name="", state="open"),           # canonical TLS port
    ])])
    assert out == ["https://10.0.0.5:8443", "https://10.0.0.5:9443"]


def test_web_targets_prefers_hostname_over_ip():
    out = _targets([Host(target="t", ip="10.0.0.5",
                         hostname="app.lab.internal", services=[
        Service(port=443, name="https", state="open"),
    ])])
    assert out == ["https://app.lab.internal:443"]


def test_web_targets_ipv6_is_bracketed():
    out = _targets([Host(target="::1", ip="::1", services=[
        Service(port=8000, name="http", state="open"),
    ])])
    assert out == ["http://[::1]:8000"]


def test_web_targets_sorted_and_deduped_across_hosts():
    out = _targets([
        Host(target="b", ip="10.0.0.6", services=[
            Service(port=80, name="http", state="open")]),
        Host(target="a", ip="10.0.0.5", services=[
            Service(port=80, name="http", state="open"),
            Service(port=80, name="http", state="open")]),   # dup
    ])
    assert out == ["http://10.0.0.5:80", "http://10.0.0.6:80"]
