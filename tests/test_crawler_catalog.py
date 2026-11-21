"""webrecon crawler feeds the shared catalog (browser-free: the matcher is
pure; _apply_catalog is exercised with canned rendered-page signals)."""
from webrecon.config import Config
from webrecon.crawler import Crawler


def _crawler():
    return Crawler(Config(target="http://x/"), None)


def test_apply_catalog_static_only():
    cr = _crawler()
    # a plain GET (no js_globals/dom_eval): static header sig still fires
    cr._apply_catalog({"server": "Apache/2.4.49"}, "", None, None)
    assert any(t.lower().startswith("apache") for t in cr.result.tech)


def test_apply_catalog_js_global_with_version():
    cr = _crawler()
    cr._apply_catalog({}, "", {"Ember": "", "Ember.VERSION": "4.12.0"}, {})
    assert "Ember.js 4.12.0" in cr.result.tech


def test_apply_catalog_dom_exists():
    cr = _crawler()
    cr._apply_catalog({}, "", {},
                      {"[ng-app='kubernetesDashboard']": {"exists": True}})
    assert "Kubernetes Dashboard" in cr.result.tech


def test_apply_catalog_plain_get_skips_jsdom_apps():
    cr = _crawler()
    cr._apply_catalog({"server": "nginx"}, "<html></html>", None, None)
    assert not any(t.startswith("Kubernetes Dashboard") for t in cr.result.tech)
    assert not any(t.startswith("Ember.js") for t in cr.result.tech)
