"""The crawl wall-clock time budget stops the loop gracefully and returns the
partial result (no crash, no hang). Browser-free + network-free: HTTP-only crawl
(render off) against a fake client whose pages always link to brand-new in-scope
URLs so the frontier never drains, and a monkeypatched module clock so the
budget trips deterministically."""
import asyncio

from webrecon import crawler as crawler_mod
from webrecon.config import Config
from webrecon.crawler import Crawler


class _Resp:
    def __init__(self, url, html):
        self.url = url
        self.status = 200
        self.final_url = url
        self.headers = {"content-type": "text/html"}
        self.text = html
        self.content_type = "text/html"
        self.length = len(html)
        self.ok = True
        self.error = None


class _FakeHTTP:
    """Every page links to 4 brand-new in-scope URLs, so without a budget the
    crawl runs until it hits max_pages."""

    def __init__(self):
        self._n = 0

    async def fetch(self, url, *a, **k):
        links = []
        for _ in range(4):
            self._n += 1
            links.append(f'<a href="http://x/p{self._n}">p{self._n}</a>')
        return _Resp(url, "<html><body>" + "".join(links) + "</body></html>")


def _cfg(**kw):
    c = Config(target="http://x/", render=False, same_scope_only=True,
               include_subdomains=True, do_secrets=False, do_js_extract=False,
               concurrency=1, max_pages=40, depth=50)
    c.scope_hosts = {"x"}
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def _fake_clock(step=1.0):
    """A monotonic clock that advances by `step` on every call."""
    t = {"v": 0.0}

    def now():
        t["v"] += step
        return t["v"]

    return now


def test_no_budget_crawls_up_to_max_pages():
    cfg = _cfg(time_budget=None, max_pages=25)
    cr = Crawler(cfg, _FakeHTTP())
    result = asyncio.run(cr.run(["http://x/"]))
    # unbounded (by time): fills up to the page cap
    assert len(result.pages) == cfg.max_pages


def test_budget_stops_early_with_partial_result(monkeypatch):
    # clock jumps 1s/call; budget 5s -> loop boundary trips after a few pages,
    # well below the 40-page cap.
    monkeypatch.setattr(crawler_mod, "_monotonic", _fake_clock(step=1.0))
    cfg = _cfg(time_budget=5.0, max_pages=40)
    cr = Crawler(cfg, _FakeHTTP())
    result = asyncio.run(cr.run(["http://x/"]))
    assert 0 < len(result.pages) < cfg.max_pages


def test_budget_run_returns_not_hangs(monkeypatch):
    # even an immediately-expired budget returns a (near-empty) result rather
    # than raising or hanging.
    monkeypatch.setattr(crawler_mod, "_monotonic", _fake_clock(step=100.0))
    cfg = _cfg(time_budget=1.0, max_pages=40)
    cr = Crawler(cfg, _FakeHTTP())
    result = asyncio.run(asyncio.wait_for(cr.run(["http://x/"]), timeout=10))
    assert isinstance(result.pages, dict)
    assert len(result.pages) < cfg.max_pages
