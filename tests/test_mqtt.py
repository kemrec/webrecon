"""MQTT anonymous-access exposure (TCP 1883 / 8883 over TLS). Dependency-free,
read-only: a hand-rolled MQTT 3.1.1 CONNECT with no credentials, then at most a
SUBSCRIBE to the single $SYS/broker/version metadata topic. A broker that
answers CONNACK 0x00 accepts anonymous clients = critical. Loopback only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


# --- wire-format unit checks ------------------------------------------------
def test_remaining_length_roundtrip():
    for n in (0, 1, 127, 128, 16383, 16384, 2097151):
        enc = fp._mqtt_rem_len(n)
        val, idx = fp._mqtt_decode_rem_len(enc, 0)
        assert val == n and idx == len(enc)


def test_connect_packet_is_mqtt_311_anonymous():
    pkt = fp._mqtt_connect(b"abc")
    assert pkt[0] == 0x10                       # CONNECT
    rl, j = fp._mqtt_decode_rem_len(pkt, 1)
    body = pkt[j:]
    assert body[:6] == b"\x00\x04MQTT"          # protocol name
    assert body[6] == 0x04                       # level 3.1.1
    assert body[7] == 0x02                       # clean session, no user/pass
    assert body.endswith(b"\x00\x03abc")        # client id, length-prefixed


def test_find_publish_extracts_qos0_payload():
    topic = b"$SYS/broker/version"
    payload = b"mosquitto version 2.0.11"
    body = len(topic).to_bytes(2, "big") + topic + payload
    buf = b"\x90\x03\x00\x01\x00"                # a SUBACK in front
    buf += b"\x30" + fp._mqtt_rem_len(len(body)) + body
    assert fp._mqtt_find_publish(buf, topic) == payload


# --- mock MQTT broker -------------------------------------------------------
def _mqtt_server(mode: str, version: bytes = b"mosquitto version 2.0.11"):
    rc = {"open": 0x00, "open_nover": 0x00, "auth": 0x05, "detected": 0x02}

    async def handler(reader, writer):
        try:
            await asyncio.wait_for(reader.read(512), timeout=2.0)   # CONNECT
            if mode == "notmqtt":
                writer.write(b"\xff\xff\xff\xff")
                await writer.drain()
                writer.close()
                return
            writer.write(bytes([0x20, 0x02, 0x00, rc[mode]]))
            await writer.drain()
            if mode == "open":
                sub = await asyncio.wait_for(reader.read(512), timeout=2.0)
                pid = sub[2:4] if len(sub) >= 4 else b"\x00\x01"
                writer.write(b"\x90\x03" + pid + b"\x00")           # SUBACK
                topic = b"$SYS/broker/version"
                body = len(topic).to_bytes(2, "big") + topic + version
                writer.write(b"\x30" + fp._mqtt_rem_len(len(body)) + body)
                await writer.drain()
            # open_nover: accept, publish nothing -> client recovers no banner
            await asyncio.sleep(0.05)
        except Exception:
            pass
        writer.close()
    return handler


def _probe(mode, timeout=1.0):
    async def run():
        srv = await asyncio.start_server(_mqtt_server(mode), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.mqtt_probe("127.0.0.1", port, timeout, False)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


def test_probe_anonymous_accept_with_version():
    assert _probe("open") == ("open", "mosquitto version 2.0.11")


def test_probe_anonymous_accept_no_version():
    assert _probe("open_nover") == ("open", "")


def test_probe_auth_enforced():
    assert _probe("auth") == ("auth", "")


def test_probe_refused_other_is_detected():
    assert _probe("detected") == ("detected", "")


def test_probe_non_mqtt_is_none():
    assert _probe("notmqtt") is None


# --- check_exposure dispatch ------------------------------------------------
def _check(mode, name="mqtt"):
    svc = Service(port=0, name=name, state="open")

    async def run():
        srv = await asyncio.start_server(_mqtt_server(mode), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_anonymous_broker_is_alert():
    svc = _check("open")
    ids = {s["id"] for s in svc.scripts}
    assert "mqtt-unauth" in ids
    assert "mqtt-unauth" in fp.EXPOSURE_ALERT_IDS
    assert "UNAUTHENTICATED" in svc.extrainfo
    assert svc.product == "MQTT broker"
    assert svc.version == "2.0.11"              # numeric extracted for CVE match


def test_dispatch_auth_broker_is_informational():
    svc = _check("auth")
    ids = {s["id"] for s in svc.scripts}
    assert "mqtt-auth" in ids
    assert "mqtt-auth" not in fp.EXPOSURE_ALERT_IDS
    assert "mqtt-unauth" not in ids


def test_dispatch_detected_only_is_informational():
    svc = _check("detected")
    ids = {s["id"] for s in svc.scripts}
    assert "mqtt-detected" in ids
    assert "mqtt-detected" not in fp.EXPOSURE_ALERT_IDS
    assert "mqtt-unauth" not in ids
