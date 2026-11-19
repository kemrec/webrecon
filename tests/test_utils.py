from webrecon import utils


def test_is_ip():
    assert utils.is_ip("10.0.0.5") is True
    assert utils.is_ip("::1") is True
    assert utils.is_ip("[::1]") is True
    assert utils.is_ip("example.com") is False
    assert utils.is_ip("") is False


def test_with_port():
    assert utils.with_port("10.0.0.5", 8080) == "10.0.0.5:8080"
    assert utils.with_port("example.com", None) == "example.com"
    assert utils.with_port("::1", 443) == "[::1]:443"
    assert utils.with_port("[::1]", 443) == "[::1]:443"


def test_host_of():
    assert utils.host_of("http://user@ex.com:8080/a") == "ex.com"
    assert utils.host_of("https://10.0.0.5/") == "10.0.0.5"
    assert utils.host_of("http://EX.com/") == "ex.com"


def test_in_scope():
    assert utils.in_scope("http://ex.com/a", {"ex.com"}, False) is True
    assert utils.in_scope("http://a.ex.com/", {"ex.com"}, True) is True
    assert utils.in_scope("http://a.ex.com/", {"ex.com"}, False) is False
    assert utils.in_scope("http://github.com/", {"ex.com"}, True) is False


def test_registrable_hint():
    assert utils.registrable_hint("a.b.example.com") == "example.com"
    assert utils.registrable_hint("example.com") == "example.com"
    assert utils.registrable_hint("localhost") == "localhost"
