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


# --- aggressive (opt-in) entropy sweep -------------------------------------
_AGG_TYPE = "High-entropy string (aggressive)"
_SECRET = "x8Kd2PqLm9Zt4Rw7Nv1Bh6Yc3Fa5Gj"   # high-entropy, unknown key name


def test_aggressive_off_by_default():
    # a secret-shaped value under an unrecognised key is NOT flagged by default
    out = secrets.scan(f'const zz = "{_SECRET}";', "app.js")
    assert _AGG_TYPE not in _types(out)


def test_aggressive_flags_high_entropy_literal():
    out = secrets.scan(f'const zz = "{_SECRET}";', "app.js", aggressive=True)
    hits = [f for f in out if f.type == _AGG_TYPE]
    assert hits and hits[0].match_preview == _SECRET   # full value, low sev
    assert hits[0].severity == "low"


def test_aggressive_suppresses_false_positives():
    noise = (
        'h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";'  # sha256
        'm = "d41d8cd98f00b204e9800998ecf8427e";'                                 # md5
        'w = "thequickbrownfoxjumpsover";'                                        # words
        'id = "getUserProfileByIdentifier";'                                      # identifier
    )
    out = secrets.scan(noise, "bundle.js", aggressive=True)
    assert _AGG_TYPE not in _types(out)


def test_aggressive_does_not_double_report_known_provider_key():
    # a value already caught by a provider rule must not re-appear as generic
    out = secrets.scan('const zz = "AKIAIOSFODNN7EXAMPLE";', "app.js",
                       aggressive=True)
    assert "AWS Access Key ID" in _types(out)
    assert _AGG_TYPE not in _types(out)
