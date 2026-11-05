# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Jump host with a source address: connections are opened by "nc -s <source> <host> <port>" on the
jump host (sites behind policy-based IPsec). Only IP addresses ever reach the remote command."""

import pytest

from lyss import collector


class FakeChannel:
    def __init__(self):
        self.command = None

    def exec_command(self, command):
        self.command = command


class FakeTransport:
    def __init__(self):
        self.opened = []

    def open_session(self, timeout=None):
        chan = FakeChannel()
        self.opened.append(chan)
        return chan

    def open_channel(self, *args, **kwargs):  # pragma: no cover - must not be used with a source
        raise AssertionError("port forwarding used although a source address is set")


def test_nc_command_uses_the_source_address():
    jump = collector.JumpHost({"host": "198.51.100.1", "source": "192.0.2.202"})
    chan = jump._nc_channel(FakeTransport(), "203.0.113.10", 22, 5)
    assert chan.command == "nc -s 192.0.2.202 203.0.113.10 22"


@pytest.mark.parametrize("host", ["sw1.example.test", "203.0.113.10; reboot", "$(id)", "203.0.113.10 22 -e sh"])
def test_nothing_but_addresses_reaches_the_jump_host_shell(host):
    jump = collector.JumpHost({"host": "198.51.100.1", "source": "192.0.2.202"})
    transport = FakeTransport()
    with pytest.raises(ValueError, match="by IP address"):
        jump._nc_channel(transport, host, 22, 5)
    assert not transport.opened


def test_bad_source_is_refused():
    jump = collector.JumpHost({"host": "198.51.100.1", "source": "192.0.2.202 && id"})
    with pytest.raises(ValueError):
        jump._nc_channel(FakeTransport(), "203.0.113.10", 22, 5)


def test_discovery_probes_bound_nc_and_always_close_the_channel(monkeypatch):
    """A probe that times out must still close its channel (it holds a jump-host session), and
    nc must give up by itself (-w) so no process stays behind on the jump host."""
    from lyss import discovery

    class SilentChannel(FakeChannel):
        closed = False

        def settimeout(self, t):
            pass

        def recv(self, n):
            raise TimeoutError

        def close(self):
            self.closed = True

    transport = FakeTransport()
    transport.open_session = lambda timeout=None: transport.opened.append(SilentChannel()) or transport.opened[-1]
    jump = collector.JumpHost({"host": "198.51.100.1", "source": "192.0.2.202"})
    monkeypatch.setattr(jump, "channel", lambda host, port, timeout=15, connect_timeout=None:
                        jump._nc_channel(transport, host, port, timeout, connect_timeout))
    assert discovery._banner("203.0.113.9", jump) is None
    chan = transport.opened[0]
    assert chan.command == "nc -w 4 -s 192.0.2.202 203.0.113.9 22"
    assert chan.closed


def test_without_source_the_jump_uses_port_forwarding():
    assert collector.JumpHost({"host": "198.51.100.1"}).source == ""


def test_settings_validate_the_source(data_dir):
    from fastapi.testclient import TestClient

    from lyss.web import app as webapp
    from test_web import PASSWORD, csrf_of

    webapp._sessions.clear()
    webapp._failures.update(count=0, locked_until=0)
    c = TestClient(webapp.app, base_url="http://127.0.0.1:8765")
    c.post("/setup", data={"password": PASSWORD, "confirm": PASSWORD})
    csrf = csrf_of(c.get("/settings").text)
    key = data_dir / "key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("not a real key")
    base = {"csrf": csrf, "host": "198.51.100.1", "port": "22", "user": "root", "key_file": str(key)}
    assert c.post("/settings/jump", data={**base, "source": "lan; id"}).status_code == 400
    r = c.post("/settings/jump", data={**base, "source": "192.0.2.202"})
    assert r.status_code == 200 and 'value="192.0.2.202"' in r.text
    c.post("/settings/sites", data={"csrf": csrf, "name": "Agency", "ranges": "203.0.113.0/24"})
    assert "(from 192.0.2.202)" in c.get("/discovery").text
