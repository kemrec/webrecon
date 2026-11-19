from webrecon import secrets


def test_empty():
    assert secrets.scan("", "src.js") == []


def test_aws_access_key_detected():
    text = 'const k = "AKIAIOSFODNN7EXAMPLE";'
    out = secrets.scan(text, "app.js")
    assert any(f.type == "AWS Access Key ID" for f in out)


def test_placeholder_values_suppressed():
    # a generic key=value whose value is an obvious placeholder is not a secret
    for ph in ("xxxxxxxx", "null", "changeme", "example"):
        text = f'api_key = "{ph}"'
        out = secrets.scan(text, "conf")
        assert all(ph not in f.match_preview for f in out), ph


def test_redaction_does_not_leak_full_secret():
    text = 'aws_key="AKIAIOSFODNN7EXAMPLE"'
    out = secrets.scan(text, "s")
    for f in out:
        assert f.match_preview != "AKIAIOSFODNN7EXAMPLE"
