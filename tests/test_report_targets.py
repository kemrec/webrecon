import os

from servicescan import report
from servicescan.models import ScanResult, Host, Service


def _targets(hosts):
    r = ScanResult(target="lab")
    r.hosts = hosts
    return report._web_targets(r)


def _net(hosts):
    r = ScanResult(target="lab")
    r.hosts = hosts
    return report._network_targets(r)


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


# --- non-web (network) target list -----------------------------------------
def test_network_targets_host_port_no_scheme():
    out = _net([Host(target="h", ip="10.0.0.5", services=[
        Service(port=22, name="ssh", state="open"),
        Service(port=3306, name="mysql", state="open"),
        Service(port=6379, name="redis", state="open"),
    ])])
    assert out == ["10.0.0.5:22", "10.0.0.5:3306", "10.0.0.5:6379"]
    assert all("://" not in t for t in out)          # never a scheme


def test_network_targets_excludes_web_and_closed():
    out = _net([Host(target="h", ip="10.0.0.5", services=[
        Service(port=80, name="http", state="open"),         # web -> excluded
        Service(port=443, name="https", state="open"),       # web -> excluded
        Service(port=21, name="ftp", state="closed"),        # closed -> excluded
        Service(port=22, name="ssh", state="open"),          # the only hit
    ])])
    assert out == ["10.0.0.5:22"]


def test_network_targets_includes_silent_binary_services():
    # distcc(3632)/ajp(8009) are non-web binary services -> network file
    out = _net([Host(target="h", ip="10.0.0.5", services=[
        Service(port=3632, name="distccd", state="open"),
        Service(port=8009, name="ajp13", state="open"),
    ])])
    assert out == ["10.0.0.5:3632", "10.0.0.5:8009"]


def test_network_targets_ipv6_bracketed_and_hostname_preferred():
    out = _net([
        Host(target="::1", ip="::1", services=[
            Service(port=22, name="ssh", state="open")]),
        Host(target="t", ip="10.0.0.5", hostname="db.lab.internal", services=[
            Service(port=5432, name="postgresql", state="open")]),
    ])
    assert out == ["[::1]:22", "db.lab.internal:5432"]


def test_web_and_network_partition_no_overlap():
    hosts = [Host(target="h", ip="10.0.0.5", services=[
        Service(port=443, name="https", state="open"),
        Service(port=22, name="ssh", state="open"),
        Service(port=8009, name="ajp13", state="open"),
    ])]
    web, net = _targets(hosts), _net(hosts)
    assert web == ["https://10.0.0.5:443"]
    assert net == ["10.0.0.5:22", "10.0.0.5:8009"]
    # a service lands in exactly one list
    web_ports = {t.rsplit(":", 1)[1] for t in web}
    net_ports = {t.rsplit(":", 1)[1] for t in net}
    assert web_ports.isdisjoint(net_ports)


# --- nuclei command hint in console summary --------------------------------
def _result_with_both():
    r = ScanResult(target="lab")
    r.hosts = [Host(target="10.0.0.5", ip="10.0.0.5", services=[
        Service(port=80, name="http", state="open"),
        Service(port=22, name="ssh", state="open"),
    ])]
    return r


def test_nuclei_hint_uses_absolute_paths(tmp_path, capsys):
    r = _result_with_both()
    out = str(tmp_path)
    report.write_all(out, r)                     # writes both target files
    report.console_summary(r, out)
    printed = capsys.readouterr().out
    abs_web = os.path.join(os.path.abspath(out), "nuclei-targets.txt")
    abs_net = os.path.join(os.path.abspath(out), "nuclei-targets-net.txt")
    assert abs_web in printed and abs_net in printed
    assert os.path.isabs(abs_web)                # full path, runs from anywhere
    assert "nuclei -l " in printed


def test_nuclei_hint_absent_without_outdir(capsys):
    report.console_summary(_result_with_both())  # no outdir -> no hint
    assert "nuclei -l " not in capsys.readouterr().out
