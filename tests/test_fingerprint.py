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


# --- Tomcat version recovery (FP-free: version from the server itself) -------
def test_valid_tomcat_version_rejects_coyote_protocol():
    # the Coyote connector protocol version (1.1) must never pass as a server
    # version -- that is the whole class of false positives we guard against.
    assert fp._valid_tomcat_version("1.1") == ""
    assert fp._valid_tomcat_version("2.0") == ""
    assert fp._valid_tomcat_version("") == ""
    # plausible server versions (major >= 3) pass through
    assert fp._valid_tomcat_version("9.0.30") == "9.0.30"
    assert fp._valid_tomcat_version("5.5.26") == "5.5.26"


class _TomcatHTTP:
    """Stub: maps a path substring -> (status, body); default is a 404 body."""
    def __init__(self, routes, default=""):
        self.routes = routes
        self.default = default

    async def fetch(self, url, method="GET", read_body=True):
        path = "/" + url.split("://", 1)[1].split("/", 1)[1]
        for frag, body in self.routes.items():
            if frag in path:
                return type("R", (), {"text": body, "status": 404, "ok": False})()
        return type("R", (), {"text": self.default, "status": 404,
                              "ok": False})()


def test_probe_tomcat_version_from_error_page_footer():
    # the default error page (any random 404) carries the exact version in its
    # footer -- the real tomcat:9.0.30 body shape.
    body = ('<!doctype html><html><body><h1>HTTP Status 404</h1>'
            '<h3>Apache Tomcat/9.0.30</h3></body></html>')
    http = _TomcatHTTP({}, default=body)       # every path returns the footer
    ver = asyncio.run(fp._probe_tomcat_version(http, "10.0.0.5", 8080, False))
    assert ver == "9.0.30"


def test_probe_tomcat_version_from_release_notes_fallback():
    body = "Apache Tomcat Version 8.5.61\n...release notes..."
    http = _TomcatHTTP({"/RELEASE-NOTES.txt": body}, default="")
    ver = asyncio.run(fp._probe_tomcat_version(http, "10.0.0.5", 8080, False))
    assert ver == "8.5.61"


def test_probe_tomcat_version_hardened_returns_empty():
    # a hardened server (custom error page, no RELEASE-NOTES) discloses nothing;
    # the probe must return "" so the caller suppresses CVE correlation instead
    # of guessing (no version-less flood).
    http = _TomcatHTTP({}, default="<html><body>Not Found</body></html>")
    ver = asyncio.run(fp._probe_tomcat_version(http, "10.0.0.5", 8080, False))
    assert ver == ""
