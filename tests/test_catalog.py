"""Technology-catalog matching, including the rendered-page js/dom signals."""
from servicescan import fingerprint as fp


def test_catalog_loads_and_has_jsdom_apps():
    cat = fp._load_catalog()
    assert cat, "catalog should load"
    # js/dom-only apps were recovered by the bridge
    for app in ("Angular", "CKEditor", "Ember.js", "Kubernetes Dashboard",
                "MantisBT", "Vtiger"):
        assert app in cat, f"{app} missing from catalog"


def test_js_presence_and_version():
    jg = {"Ember": "", "Ember.VERSION": "3.28.0"}
    hits = dict(fp.match_catalog({}, "", js_globals=jg))
    assert "Ember.js" in hits
    assert hits["Ember.js"] == "3.28.0"


def test_js_presence_only_no_version():
    hits = dict(fp.match_catalog({}, "", js_globals={"Vtiger": ""}))
    assert "Vtiger" in hits and hits["Vtiger"] == ""


def test_dom_exists():
    de = {"[ng-app='kubernetesDashboard']": {"exists": True}}
    hits = dict(fp.match_catalog({}, "", dom_eval=de))
    assert "Kubernetes Dashboard" in hits


def test_dom_attr_version():
    de = {"[ng-version]": {"exists": True, "attrs": {"ng-version": "17.1.2"}}}
    hits = dict(fp.match_catalog({}, "", dom_eval=de))
    assert "Angular" in hits and hits["Angular"] == "17.1.2"


def test_dom_not_present_is_no_hit():
    # selector resolved but did not exist -> no hit
    de = {"[ng-app='kubernetesDashboard']": {"exists": False}}
    hits = dict(fp.match_catalog({}, "", dom_eval=de))
    assert "Kubernetes Dashboard" not in hits


def test_plain_get_skips_jsdom_signals():
    # a non-rendering caller passes neither js_globals nor dom_eval: no crash,
    # and js/dom-only apps never match from body alone.
    hits = dict(fp.match_catalog({"server": "nginx"}, "<html></html>"))
    assert "Kubernetes Dashboard" not in hits
    assert "Ember.js" not in hits


def test_header_signal_still_matches_without_render():
    # regression: the original static path is unchanged
    hits = dict(fp.match_catalog({"server": "Apache/2.4.49"}, ""))
    assert any(k.lower().startswith("apache") for k in hits)


def test_catalog_eval_targets_exposed():
    jsv = fp.catalog_js_vars()
    doms = fp.catalog_dom_specs()
    assert "Ember.VERSION" in jsv
    assert any(sel == "[ng-version]" and mode == "attr" for sel, mode, _ in doms)
