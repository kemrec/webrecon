import asyncio
import json
from dataclasses import dataclass

from webrecon import openapi


# --- parse_spec (pure) ------------------------------------------------------
def test_parse_openapi3_servers_params_and_templates():
    spec = {
        "openapi": "3.0.1", "info": {"title": "Shop", "version": "2.1"},
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/users": {"get": {"parameters": [
                {"name": "page", "in": "query"},
                {"name": "limit", "in": "query"}]}, "post": {}},
            "/users/{id}": {"get": {"parameters": [
                {"name": "expand", "in": "query"},
                {"name": "id", "in": "path"}]}},   # path param excluded from query
        }}
    eps, ps, us, meta = openapi.parse_spec(spec, "https://h.example/openapi.json")
    assert sorted(eps) == ["/api/v1/users", "/api/v1/users/{id}"]
    assert ps["/api/v1/users"] == {"page", "limit"}
    assert ps["/api/v1/users/{id}"] == {"expand"}    # not 'id' (it is in:path)
    assert "https://h.example/api/v1/users/{id}" in us
    assert meta["title"] == "Shop" and meta["paths"] == 2


def test_parse_swagger2_basepath_and_absolute_server():
    spec = {"swagger": "2.0", "info": {"title": "L"}, "basePath": "/v2",
            "paths": {"/pets": {"get": {"parameters": [
                {"name": "status", "in": "query"}]}}}}
    eps, ps, us, _ = openapi.parse_spec(spec, "http://api.test:8080/v2/api-docs")
    assert eps == {"/v2/pets"}
    assert ps["/v2/pets"] == {"status"}
    assert us == {"http://api.test:8080/v2/pets"}


def test_parse_spec_tolerates_empty_or_bad_paths():
    eps, ps, us, meta = openapi.parse_spec(
        {"openapi": "3.0.0", "paths": {}}, "https://h/openapi.json")
    assert eps == set() and ps == {} and meta["paths"] == 0
    # malformed path items are skipped, not crashed on
    eps, _, _, _ = openapi.parse_spec(
        {"openapi": "3.0.0", "paths": {"/a": None, "/b": {"get": {}}}},
        "https://h/openapi.json")
    assert eps == {"/b"}


# --- _load_spec gating ------------------------------------------------------
def test_load_spec_accepts_json_spec_only():
    spec = {"openapi": "3.0.0", "paths": {}}
    assert openapi._load_spec(json.dumps(spec), "application/json")
    assert openapi._load_spec('{"hello": 1}', "application/json") is None  # not a spec
    assert openapi._load_spec("<html>no</html>", "text/html") is None
    assert openapi._load_spec("", "application/json") is None


def test_load_spec_strips_bom():
    body = "﻿" + json.dumps({"swagger": "2.0", "paths": {}})
    assert openapi._load_spec(body, "application/json")


# --- discover (fake http client) -------------------------------------------
@dataclass
class _Resp:
    status: int
    text: str
    content_type: str = "application/json"
    final_url: str = ""


class _FakeHTTP:
    """Serves one spec at /openapi.json, 404 elsewhere; records requested paths."""
    def __init__(self, spec_body: str):
        self.spec_body = spec_body
        self.requested = []

    async def fetch(self, url, *a, **k):
        self.requested.append(url)
        if url.endswith("/openapi.json"):
            return _Resp(200, self.spec_body, final_url=url)
        return _Resp(404, "")


def _run(coro):
    return asyncio.run(coro)


def test_discover_finds_parses_and_merges():
    spec = json.dumps({
        "openapi": "3.0.0", "info": {"title": "Demo", "version": "1"},
        "paths": {"/api/orders": {"get": {"parameters": [
            {"name": "since", "in": "query"}]}},
            "/api/orders/{oid}": {"delete": {}}}})
    http = _FakeHTTP(spec)
    specs, eps, ps, us = _run(openapi.discover(None, http, ["http://t.local"]))
    assert len(specs) == 1 and specs[0]["title"] == "Demo"
    assert eps == {"/api/orders", "/api/orders/{oid}"}
    assert ps["/api/orders"] == {"since"}
    assert "http://t.local/api/orders" in us
    # it probed multiple well-known paths, not just the one that hit
    assert len(http.requested) == len(openapi.SPEC_PATHS)


def test_discover_dedupes_same_spec_across_bases():
    spec = json.dumps({"openapi": "3.0.0", "info": {"title": "D"},
                       "paths": {"/x": {"get": {}}}})
    http = _FakeHTTP(spec)
    specs, eps, _, _ = _run(
        openapi.discover(None, http, ["http://a.local", "http://b.local"]))
    assert len(specs) == 1          # same (title,paths) fingerprint -> deduped
    assert eps == {"/x"}


def test_discover_returns_empty_when_no_spec():
    class _No:
        async def fetch(self, url, *a, **k):
            return _Resp(404, "")
    specs, eps, ps, us = _run(openapi.discover(None, _No(), ["http://t.local"]))
    assert specs == [] and eps == set() and ps == {} and us == set()
