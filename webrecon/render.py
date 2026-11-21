"""Shared Playwright helpers for rendered-page technology detection.

Two consumers use this:
  - servicescan's ``--render`` path renders the root of each web port to catch
    apps whose only signal is a JavaScript global or a DOM selector;
  - webrecon's crawler evaluates the same signals on every page it renders.

Both feed the results to ``servicescan.fingerprint.match_catalog`` as its
``js_globals`` / ``dom_eval`` inputs. Playwright is imported lazily so neither
tool gains a hard dependency on it.
"""
from __future__ import annotations

from . import utils

# One page.evaluate does all the DOM/JS work in the browser. It is pure data
# collection: read window globals and resolve selectors, no mutation.
_EVAL_JS = r"""
([jsVars, domSpecs]) => {
  const out = {js: {}, dom: {}};
  for (const path of jsVars) {
    try {
      let cur = window;
      let ok = true;
      for (const part of path.split('.')) {
        if (cur == null) { ok = false; break; }
        cur = cur[part];
      }
      if (ok && cur !== undefined && cur !== null) {
        let v = '';
        try { v = (typeof cur === 'object' || typeof cur === 'function')
                    ? '' : String(cur); } catch (e) { v = ''; }
        out.js[path] = v;
      }
    } catch (e) {}
  }
  for (const spec of domSpecs) {
    const sel = spec[0], mode = spec[1], attr = spec[2];
    try {
      const el = document.querySelector(sel);
      if (!el) continue;
      let rec = out.dom[sel];
      if (!rec) { rec = out.dom[sel] = {exists: true, attrs: {}, text: ''}; }
      if (mode === 'attr' && attr) {
        const a = el.getAttribute(attr);
        if (a !== null) rec.attrs[attr] = a;
      } else if (mode === 'text') {
        rec.text = (el.textContent || '').slice(0, 2000);
      }
    } catch (e) {}
  }
  return out;
}
"""


async def eval_specs(page, js_vars, dom_specs):
    """Evaluate catalog js vars + dom specs on an already-loaded Playwright
    page. Returns (js_globals, dom_eval); ({}, {}) on any failure."""
    if not js_vars and not dom_specs:
        return {}, {}
    try:
        res = await page.evaluate(_EVAL_JS, [list(js_vars),
                                             [list(s) for s in dom_specs]])
        return (res.get("js") or {}), (res.get("dom") or {})
    except Exception as e:  # noqa: BLE001
        utils.debug(f"render eval failed: {type(e).__name__}")
        return {}, {}


class RootRenderer:
    """Launch one headless Chromium, render roots and evaluate catalog specs,
    tear down. Use as an async context manager:

        async with RootRenderer(timeout=...) as r:
            info = await r.eval(url, js_vars, dom_specs)

    ``eval`` returns {status, html, headers, js_globals, dom_eval} or None if
    rendering is unavailable / failed. Safe to use when Playwright is missing:
    the context manager yields a renderer whose ``eval`` returns None."""

    def __init__(self, *, timeout: float = 15.0, user_agent: str = "servicescan",
                 resolve_map: dict | None = None, settle_ms: int = 500):
        self.timeout = timeout
        self.user_agent = user_agent
        self.resolve_map = resolve_map or {}
        self.settle_ms = settle_ms
        self._pw = None
        self._browser = None

    async def __aenter__(self):
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            utils.warn("playwright not installed; --render has no effect")
            return self
        args = ["--no-sandbox", "--disable-dev-shm-usage",
                "--ignore-certificate-errors"]
        if self.resolve_map:
            rules = ",".join(f"MAP {h} {ip}" for h, ip in self.resolve_map.items())
            args.append(f"--host-resolver-rules={rules}")
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=True,
                                                           args=args)
        except Exception as e:  # noqa: BLE001
            utils.warn(f"browser launch failed ({type(e).__name__}); "
                       "--render has no effect")
            self._browser = None
        return self

    async def __aexit__(self, *exc):
        try:
            if self._browser:
                await self._browser.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:  # noqa: BLE001
            pass

    @property
    def available(self) -> bool:
        return self._browser is not None

    async def eval(self, url: str, js_vars, dom_specs):
        if not self._browser:
            return None
        ctx = None
        try:
            ctx = await self._browser.new_context(
                user_agent=self.user_agent, ignore_https_errors=True)
            page = await ctx.new_page()
            resp = await page.goto(url, wait_until="domcontentloaded",
                                   timeout=int(self.timeout * 1000))
            status = resp.status if resp else 0
            headers = {}
            if resp:
                try:
                    headers = dict(resp.headers)
                except Exception:  # noqa: BLE001
                    headers = {}
            try:
                await page.wait_for_timeout(self.settle_ms)
            except Exception:  # noqa: BLE001
                pass
            html = await page.content()
            js_globals, dom_eval = await eval_specs(page, js_vars, dom_specs)
            return {"status": status, "html": html, "headers": headers,
                    "js_globals": js_globals, "dom_eval": dom_eval}
        except Exception as e:  # noqa: BLE001
            utils.debug(f"render {url}: {type(e).__name__}")
            return None
        finally:
            if ctx:
                try:
                    await ctx.close()
                except Exception:  # noqa: BLE001
                    pass
