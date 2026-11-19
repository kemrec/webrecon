"""Regression tests for scope confinement of the attack-surface output.

Guards the fix for the reported bug: urls-all.txt / params-all.txt (and the
per-port urls.txt / endpoints.txt / params.txt) must contain only in-scope
targets. Off-scope public references seen on a target page must never leak into
the lists that feed Burp / ffuf / sqlmap -- actively fuzzing a public host you
were not scoped to is both noise and an authorization problem.
"""
from webrecon.config import Config
from webrecon.orchestrator import _out_scope


def _cfg(**kw):
    c = Config(target="http://10.0.0.5/")
    c.scope_hosts = {"10.0.0.5"}
    c.same_scope_only = True
    c.include_subdomains = True
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def test_in_scope_absolute_url_kept():
    assert _out_scope("http://10.0.0.5:8080/app?q=1", _cfg()) is True


def test_offscope_public_url_dropped():
    cfg = _cfg()
    assert _out_scope("https://github.com/foo/bar.js", cfg) is False
    assert _out_scope("https://cdn.jsdelivr.net/x.js", cfg) is False
    assert _out_scope("https://www.google-analytics.com/a", cfg) is False


def test_relative_endpoint_always_kept():
    # hostless endpoints belong to the target and must survive the filter
    cfg = _cfg()
    assert _out_scope("/api/v1/users", cfg) is True
    assert _out_scope("/static/app.js", cfg) is True


def test_scope_off_keeps_everything():
    cfg = _cfg(same_scope_only=False)
    assert _out_scope("https://github.com/foo", cfg) is True
    assert _out_scope("http://10.0.0.5/app", cfg) is True


def test_hostname_scope_and_subdomains():
    cfg = Config(target="http://app.corp.internal/")
    cfg.scope_hosts = {"app.corp.internal"}
    cfg.same_scope_only = True
    cfg.include_subdomains = True
    assert _out_scope("http://app.corp.internal/x", cfg) is True
    assert _out_scope("http://api.app.corp.internal/x", cfg) is True   # subdomain
    assert _out_scope("http://evil.com/x", cfg) is False


def test_subdomain_excluded_when_flag_off():
    cfg = Config(target="http://app.corp.internal/")
    cfg.scope_hosts = {"app.corp.internal"}
    cfg.same_scope_only = True
    cfg.include_subdomains = False
    assert _out_scope("http://api.app.corp.internal/x", cfg) is False
