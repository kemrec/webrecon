import asyncio

from servicescan import fingerprint as fp


def _probe_against(handler, timeout=0.5):
    """Start a local server with `handler`, run distcc_probe against it, and
    return the result. No network, no docker -- just the loopback interface."""
    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await fp.distcc_probe("127.0.0.1", port, timeout)
        finally:
            server.close()
            await server.wait_closed()
    return asyncio.run(run())


def test_distcc_probe_bad_version_constant_is_read_only():
    # the probe must never carry a compiler command: only a DIST version token
    assert fp._DISTCC_BADVER == b"DISTffffffff"
    assert b"ARGC" not in fp._DISTCC_BADVER
    assert b"DOTI" not in fp._DISTCC_BADVER


def test_distcc_probe_detects_distccd_behaviour():
    # distccd: silent on connect, then closes with no data after the DIST header
    async def distccd(reader, writer):
        try:
            await reader.read(16)       # consume the bad-version DIST header
        except Exception:
            pass
        writer.close()                  # close WITHOUT sending any bytes
    assert _probe_against(distccd) is True


def test_distcc_probe_rejects_greeting_service():
    # a service that greets on connect (SSH/SMTP/FTP...) is not distccd
    async def greeter(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_7.4\r\n")
        await writer.drain()
        await asyncio.sleep(0.3)
        writer.close()
    assert _probe_against(greeter) is False


def test_distcc_probe_rejects_silent_unreactive_service():
    # a silent service that holds the socket open but never reacts to the DIST
    # header must NOT be flagged (the key false-positive guard)
    async def ignorer(reader, writer):
        await asyncio.sleep(1.2)        # outlives the probe's short reads
        writer.close()
    assert _probe_against(ignorer) is False


def test_distcc_probe_rejects_service_that_answers_with_data():
    # distccd never sends data on a bad-version header; one that does is not it
    async def talker(reader, writer):
        try:
            await reader.read(16)
        except Exception:
            pass
        writer.write(b"garbage-reply")
        await writer.drain()
        writer.close()
    assert _probe_against(talker) is False


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
