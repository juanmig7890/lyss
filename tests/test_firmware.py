# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Firmware staging / activation against a simulated Catalyst 1000 (no real device)."""

import hashlib
from pathlib import Path

import pytest

from lyss import collector, firmware, inventory

NAME = "c1000-universalk9-tar.152-7.E14.tar"
DATA = b"fake image" * 1000


def test_names_versions_and_paths():
    assert firmware.image_version(NAME) == "15.2(7)E14"
    assert firmware.bin_path(NAME) == "flash:/c1000-universalk9-mz.152-7.E14/c1000-universalk9-mz.152-7.E14.bin"
    assert firmware._free_bytes("122185728 bytes total (79226880 bytes free)") == 79226880
    assert firmware._boot_path("BOOT path-list      : flash:/c1000-universalk9-mz.152-7.E8/c1000-universalk9-mz.152-7.E8.bin\nConfig file : flash:/config.text") \
        == "flash:/c1000-universalk9-mz.152-7.E8/c1000-universalk9-mz.152-7.E8.bin"


def test_upload_requires_cisco_name_and_matching_hash(data_dir):
    with pytest.raises(ValueError):
        firmware.save_image("renamed.tar", DATA, hashlib.md5(DATA).hexdigest())
    with pytest.raises(ValueError):
        firmware.save_image(NAME, DATA, "0" * 32)
    meta = firmware.save_image(NAME, DATA, hashlib.sha512(DATA).hexdigest().upper())
    assert meta["checked_against"] == "sha512" and firmware.get_image(NAME)["version"] == "15.2(7)E14"


class FakeChannel:
    def __init__(self):
        self.sent, self.command = b"", ""

    def settimeout(self, t): pass
    def exec_command(self, c): self.command = c
    def recv(self, n): return b"\x00"
    def sendall(self, b): self.sent += b
    def close(self): pass


def test_scp_sink_protocol(tmp_path):
    f = tmp_path / NAME
    f.write_bytes(DATA)
    chan = FakeChannel()
    transport = type("T", (), {"open_session": lambda self: chan})()
    firmware.scp_put(transport, f, f"flash:/{NAME}")
    assert chan.command == f"scp -t flash:/{NAME}"
    assert chan.sent.startswith(f"C0644 {len(DATA)} {NAME}\n".encode()) and chan.sent.endswith(DATA + b"\x00")


class FakeC1000:
    """Answers like a Catalyst 1000 and records everything LYSS sends."""

    def __init__(self, log, free=200_000_000, aaa=True, md5_ok=True):
        self.log, self.free, self.aaa, self.md5_ok = log, free, aaa, md5_ok
        self.transport = type("T", (), {"open_session": lambda s: FakeChannel()})()
        self.conn = type("C", (), {"send_command_timing": lambda s, c, **k: log.append(("timing", c)) or ""})()

    def run(self, command, timeout):
        self.log.append(("run", command))
        if command == "show version":
            return "Cisco IOS Software, C1000 Software, Version 15.2(7)E8, RELEASE SOFTWARE"
        if command == "show boot":
            return "BOOT path-list      : flash:/c1000-universalk9-mz.152-7.E8/c1000-universalk9-mz.152-7.E8.bin"
        if command == "dir flash:":
            return f"122185728 bytes total ({self.free} bytes free)"
        if command == "show running-config":
            return "aaa new-model\naaa authorization exec default local\n" if self.aaa else "hostname x\n"
        if command.startswith("verify /md5"):
            return f"verify /md5 ... = {hashlib.md5(DATA).hexdigest() if self.md5_ok else 'deadbeef' * 4}"
        if command.startswith("dir flash:/c1000-universalk9-mz.152-7.E14"):
            return "c1000-universalk9-mz.152-7.E14.bin"
        return ""

    def configure(self, commands):
        self.log += [("configure", c) for c in commands]
        return [(c, "") for c in commands]

    def save(self):
        self.log.append(("save", ""))

    def close(self):
        pass


@pytest.fixture
def staged_env(data_dir, monkeypatch):
    image = firmware.save_image(NAME, DATA, hashlib.md5(DATA).hexdigest())
    device = {"id": "c1000-lab", "host": "192.0.2.17", "port": 22, "vendor": "cisco_ios", "via_jump": False}
    return image, device, monkeypatch


def test_stage_runs_documented_steps_in_order_without_reboot(staged_env):
    image, device, monkeypatch = staged_env
    log = []
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeC1000(log))
    out = firmware.stage(device, image, None, lambda m: None)
    sent = [c for kind, c in log if kind in ("run", "configure", "timing")]
    order = ["ip scp server enable", f"verify /md5 flash:/{NAME}",
             f"archive download-sw /safe /no-set-boot flash:/{NAME}", f"delete /force flash:/{NAME}",
             "no ip scp server enable"]
    positions = [sent.index(c) for c in order]
    assert positions == sorted(positions)
    assert not any("reload" in c or c.startswith("boot system") for c in sent)
    assert firmware.device_state("c1000-lab")["status"] == "staged" and "no reboot" in out["outcome"]


@pytest.mark.parametrize("kwargs, message", [
    ({"free": 10_000}, "not enough flash"),
    ({"aaa": False}, "aaa"),
    ({"md5_ok": False}, "MD5"),
])
def test_stage_refusals_and_scp_always_turned_off(staged_env, kwargs, message):
    image, device, monkeypatch = staged_env
    log = []
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeC1000(log, **kwargs))
    with pytest.raises(RuntimeError, match=message):
        firmware.stage(device, image, None, lambda m: None)
    if ("configure", "ip scp server enable") in log:
        assert ("configure", "no ip scp server enable") in log
    assert not any(c.startswith("archive") for _, c in log) or kwargs.get("md5_ok") is not False
    assert firmware.device_state("c1000-lab").get("status") != "staged"


def test_activate_requires_staging(staged_env):
    _, device, _ = staged_env
    with pytest.raises(RuntimeError, match="stage the image first"):
        firmware.activate(device, None, lambda m: None)
