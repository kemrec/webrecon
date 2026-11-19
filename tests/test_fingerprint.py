from servicescan import fingerprint as fp


def test_detect_shell_unix_prompt():
    assert fp.detect_shell("root@metasploitable:/# ") is True
    assert fp.detect_shell("user@host:~$") is True


def test_detect_shell_id_output():
    assert fp.detect_shell("uid=0(root) gid=0(root) groups=0(root)") is True


def test_detect_shell_windows():
    assert fp.detect_shell("Microsoft Windows [Version 10.0.19045.3570]") is True
    assert fp.detect_shell("C:\\Users\\admin>") is True


def test_detect_shell_negatives():
    # real service banners must NOT be flagged as a shell (FP guard)
    assert fp.detect_shell("220 ProFTPD 1.3.1 Server ready") is False
    assert fp.detect_shell("SSH-2.0-OpenSSH_7.4") is False
    assert fp.detect_shell("+OK POP3 ready") is False
    assert fp.detect_shell("$") is False          # bare prompt char: deliberately not matched
    assert fp.detect_shell("") is False


def test_parse_banner_empty():
    assert fp.parse_banner("") == ("", "", "")


def test_parse_banner_unrealircd_isupport():
    banner = (":irc.local 005 nick NAMESX WATCHOPTS=A SAFELIST "
              ":are supported by this server")
    product, _ver, conf = fp.parse_banner(banner)
    assert product == "UnrealIRCd"
    assert conf in ("high", "medium")
