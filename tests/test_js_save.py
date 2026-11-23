"""save_js: the crawler writes every fetched JS body under <outdir>/js with a
provenance manifest, and records which page referenced each JS. Network-free
(fake HTTP), render off."""
import asyncio
import os

from webrecon import crawler as crawler_mod
from webrecon.config import Config
from webrecon.crawler import Crawler, js_filename


class _Resp:
    def __init__(self, url, html, ctype="text/html"):
        self.url = url
        self.status = 200
        self.final_url = url
        self.headers = {"content-type": ctype}
        self.text = html
        self.content_type = ctype
        self.length = len(html)
        self.ok = True
        self.error = None


class _FakeHTTP:
    """Seed page links to one in-scope JS file that carries a GitHub token."""

    async def fetch(self, url, *a, **k):
        if url.endswith(".js"):
            return _Resp(url, 'var k="ghp_' + "A" * 36 + '";',
                         ctype="application/javascript")
        return _Resp(url, '<a href="http://x/app.js">app</a>')

    async def close(self):
        pass


def _cfg(tmp, **kw):
    c = Config(target="http://x/", render=False, same_scope_only=True,
               include_subdomains=True, do_secrets=True, do_js_extract=True,
               save_js=True, outdir=tmp, concurrency=1, max_pages=10, depth=2,
               time_budget=None)
    c.scope_hosts = {"x"}
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def test_save_js_writes_bodies_manifest_and_provenance(tmp_path):
    cfg = _cfg(str(tmp_path))
    cr = Crawler(cfg, _FakeHTTP())
    result = asyncio.run(cr.run(["http://x/"]))

    js_url = "http://x/app.js"
    # provenance: the JS is recorded as referenced from the seed page
    assert "http://x/" in result.js_sources.get(js_url, set())

    # body saved to disk under <outdir>/js with the deterministic name
    js_dir = os.path.join(str(tmp_path), "js")
    saved = os.path.join(js_dir, js_filename(js_url))
    assert os.path.isfile(saved)
    with open(saved, encoding="utf-8") as fh:
        assert "ghp_" in fh.read()

    # manifest maps the saved file back to URL + referencing page
    with open(os.path.join(js_dir, "manifest.tsv"), encoding="utf-8") as fh:
        man = fh.read()
    assert js_filename(js_url) in man
    assert js_url in man
    assert "http://x/" in man

    # the token was still found inline during the crawl
    assert any(f["type"].startswith("GitHub") for f in
               [s.to_dict() for s in result.secret_findings])


def test_save_js_off_by_default_writes_nothing(tmp_path):
    cfg = _cfg(str(tmp_path), save_js=False)
    cr = Crawler(cfg, _FakeHTTP())
    asyncio.run(cr.run(["http://x/"]))
    assert not os.path.isdir(os.path.join(str(tmp_path), "js"))
