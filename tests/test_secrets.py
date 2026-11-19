from webrecon import secrets


def _types(out):
    return {f.type for f in out}


def test_empty():
    assert secrets.scan("", "src.js") == []


def test_aws_access_key_detected():
    out = secrets.scan('const k = "AKIAIOSFODNN7EXAMPLE";', "app.js")
    assert "AWS Access Key ID" in _types(out)


def test_values_are_not_redacted():
    # the full secret must appear verbatim in match_preview (operator tool)
    secret = "AKIAIOSFODNN7EXAMPLE"
    out = secrets.scan(f'key="{secret}"', "s")
    aws = [f for f in out if f.type == "AWS Access Key ID"]
    assert aws and aws[0].match_preview == secret


def test_generic_value_not_redacted():
    out = secrets.scan('password = "S3cr3tP@ssw0rd!"', "conf")
    gen = [f for f in out if f.type.startswith("Generic secret")]
    assert gen and gen[0].match_preview == "S3cr3tP@ssw0rd!"


def test_new_provider_patterns():
    samples = {
        "GitHub Token": "ghp_" + "A" * 36,
        "Slack Webhook": "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX",
        "HuggingFace Token": "hf_" + "a" * 34,
        "Stripe Live Secret Key": "sk_live_" + "a" * 24,
        "npm Token": "npm_" + "a" * 36,
        "Private Key Block": "-----BEGIN RSA PRIVATE KEY-----",
        "JWT": "eyJhbGciOiJIUzI1NiIsImtpZCI6.eyJzdWIiOiIxMjM0NTY3.abcdef1234567890",
        "Google API Key": "AIza" + "B" * 35,
    }
    for expected, blob in samples.items():
        out = secrets.scan(blob, "x")
        assert expected in _types(out), f"{expected} not detected in {blob!r}"


def test_placeholder_values_suppressed():
    for ph in ("xxxxxxxx", "null", "changeme", "placeholder", "your-api-key"):
        out = secrets.scan(f'api_key = "{ph}"', "conf")
        assert all(ph not in f.match_preview for f in out), ph
