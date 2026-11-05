# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Remediation: fix catalogue, rollback generation, and the apply flow against a simulated
switch session (no real device). The flow must roll back on a rejected command, roll back
fixes that do not verify, and only save after verification."""

import pytest

from lyss import collector, inventory, remediate, scan
from lyss.config import parse
from lyss.engine import audit

from conftest import load_case

PARAMS = {"syslog": "192.0.2.60", "ntp": ["192.0.2.123"], "banner": "Authorized access only."}


def failing(case_name):
    case = load_case(case_name)
    findings = audit(case["config"], case["vendor"], 2, case["state"], case["context"])
    return case, {f.control_id: {"verdict": f.verdict, "evidence": f.evidence} for f in findings if f.verdict == "fail"}


def test_sb_catalogue_and_rollbacks():
    case, fail = failing("sb-weak")
    cfg = parse(case["config"], case["state"])
    fixes = {f.control_id: f for f in remediate.fixes_for("cisco_sb", cfg, fail, PARAMS)}
    assert fixes["LYSS-MGMT-001"].commands == ["no ip telnet server"]
    assert fixes["LYSS-AUTH-001"].commands == ["no snmp-server community public"]
    assert fixes["LYSS-AUTH-001"].rollback == ["snmp-server community public ro view Default"]
    vuln = fixes["LYSS-VULN-001"]
    # sb-weak listens on 80 only: HTTPS is not running, so it is neither stopped nor restarted
    assert vuln.kind == "mitigation" and vuln.commands == ["no ip http server"] and vuln.rollback == ["ip http server"]
    assert fixes["LYSS-LOG-010"].commands == ["logging host 192.0.2.60"]
    assert fixes["LYSS-MGMT-012"].commands == ["banner login #\nAuthorized access only.\n#"]
    # never offered automatically: credentials, AAA, ACLs, VLANs, spanning tree, port shutdowns
    for manual in ("LYSS-AUTH-002", "LYSS-AUTH-003", "LYSS-AUTH-004", "LYSS-AUTH-010", "LYSS-MGMT-010",
                   "LYSS-MGMT-011", "LYSS-ACC-010", "LYSS-ACC-011", "LYSS-MGMT-013"):
        assert manual not in fixes


def test_sb_web_mitigation_uses_the_sb_https_syntax():
    case, fail = failing("sb-weak")
    cfg = parse(case["config"], case["state"].replace(
        "TCP   All:80                 All:0                  HTTP          listen",
        "TCP   All:80                 All:0                  HTTP          listen\n"
        "TCP   All:443                All:0                  HTTPS         listen"))
    vuln = {f.control_id: f for f in remediate.fixes_for("cisco_sb", cfg, fail, PARAMS)}["LYSS-VULN-001"]
    assert vuln.commands == ["no ip http server", "no ip http secure-server"]
    assert vuln.rollback == ["ip http server", "ip http secure-server"]
    assert not any("https server" in c for c in vuln.commands + vuln.rollback)


def test_ios_rollbacks_restore_previous_values():
    case, fail = failing("ios-weak")
    fixes = {f.control_id: f for f in remediate.fixes_for("cisco_ios", parse(case["config"]), fail, PARAMS)}
    mgmt1 = fixes["LYSS-MGMT-001"]
    assert mgmt1.commands == ["line vty 0 4", "transport input ssh", "line vty 5 15", "transport input ssh"]
    assert mgmt1.rollback == ["line vty 0 4", "transport input telnet ssh", "line vty 5 15", "transport input all"]
    assert fixes["LYSS-MGMT-004"].rollback[:2] == ["line con 0", "exec-timeout 0 0"]
    assert fixes["LYSS-MGMT-002"].commands == ["ip ssh version 2"]


def test_hp_catalogue_and_rollbacks():
    case, fail = failing("hp-weak")
    cfg = parse(case["config"], case["state"])
    fixes = {f.control_id: f for f in remediate.fixes_for("hp_procurve", cfg, fail, PARAMS)}
    assert fixes["LYSS-MGMT-001"].commands == ["no telnet-server"]
    assert fixes["LYSS-MGMT-001"].rollback == ["telnet-server"]
    assert fixes["LYSS-MGMT-003"].commands == ["no web-management plaintext"]
    assert "HTTPS is not configured" in fixes["LYSS-MGMT-003"].note   # hp-weak has no "web-management ssl"
    assert fixes["LYSS-MGMT-004"].commands == ["console idle-timeout 600"]
    assert fixes["LYSS-MGMT-004"].rollback == ["console idle-timeout 0"]
    assert fixes["LYSS-AUTH-001"].commands == ['no snmp-server community "public"']
    assert fixes["LYSS-AUTH-001"].rollback == ['snmp-server community "public" unrestricted']
    assert fixes["LYSS-MGMT-012"].commands == ['banner motd "Authorized access only."']
    assert fixes["LYSS-LOG-010"].commands == ["logging 192.0.2.60"]
    for manual in ("LYSS-AUTH-002", "LYSS-AUTH-003", "LYSS-AUTH-004", "LYSS-AUTH-010", "LYSS-MGMT-010",
                   "LYSS-MGMT-011", "LYSS-ACC-010", "LYSS-ACC-011", "LYSS-MGMT-013", "LYSS-LOG-011"):
        assert manual not in fixes


def test_missing_parameters_block_the_fix():
    case, fail = failing("sb-weak")
    fixes = {f.control_id: f for f in remediate.fixes_for("cisco_sb", parse(case["config"]), fail, {"banner": ""})}
    assert fixes["LYSS-LOG-010"].blocked and fixes["LYSS-LOG-011"].blocked and fixes["LYSS-MGMT-012"].blocked
    assert not fixes["LYSS-MGMT-001"].blocked


def test_banner_validation():
    assert remediate.validate_params("192.0.2.1", ["192.0.2.2"], "Accès réservé. Activity is logged.") == []
    assert remediate.validate_params("not-an-ip", [], "ok text")
    assert remediate.validate_params("", [], "bad # delimiter")
    assert remediate.validate_params("", [], "<script>alert(1)</script>")


# ---------------- apply flow with a simulated switch ----------------

class FakeSession:
    def __init__(self, log, reject=None):
        self.log, self.reject = log, reject

    def configure(self, commands):
        done = []
        for c in commands:
            out = "% Invalid input detected" if c == self.reject else ""
            done.append((c, out))
            self.log.append(("configure", c))
            if out:
                break
        return done

    def save(self):
        self.log.append(("save", ""))

    def close(self):
        pass


@pytest.fixture
def lab(data_dir, monkeypatch):
    case = load_case("sb-weak")
    inventory.save_device({"id": "lab", "host": "192.0.2.5", "port": "22", "vendor": "cisco_sb",
                           "username": "ro", "via_jump": False}, "x")
    device = inventory.get_device("lab")
    cfg, state = collector.config_paths(device)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(case["config"], encoding="utf-8")
    state.write_text(case["state"], encoding="utf-8")
    scan.audit_device(device, "manual")
    s = inventory.load_settings()
    s["remediation"] = {"enabled": True, **PARAMS}
    inventory.save_settings(s)
    log = []
    monkeypatch.setattr(collector, "collect_device", lambda d, j: "0s")  # data stays as written
    return device, log


def passing_after(monkeypatch, controls):
    real = scan.audit_device

    def audit_stub(device, trigger="manual", archive=True):
        result = real(device, trigger, archive)
        for f in result["findings"]:
            if f["control_id"] in controls:
                f["verdict"] = "pass"
        return result
    monkeypatch.setattr(scan, "audit_device", audit_stub)


def test_apply_success_saves_and_logs(lab, monkeypatch):
    device, log = lab
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeSession(log))
    passing_after(monkeypatch, {"LYSS-MGMT-001", "LYSS-LOG-010"})
    entry = remediate.apply_device(device, ["LYSS-MGMT-001", "LYSS-LOG-010"], None, lambda *a: None)
    assert entry["applied"] == ["LYSS-MGMT-001", "LYSS-LOG-010"] and entry["saved"]
    assert ("configure", "no ip telnet server") in log and log[-1] == ("save", "")
    assert remediate.load_changes()[0]["outcome"] == "applied and saved"


def test_rejected_command_rolls_everything_back_and_does_not_save(lab, monkeypatch):
    device, log = lab
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeSession(log, reject="logging host 192.0.2.60"))
    entry = remediate.apply_device(device, ["LYSS-MGMT-001", "LYSS-LOG-010"], None, lambda *a: None)
    assert entry["outcome"].startswith("failed, rolled back") and not entry["saved"]
    assert ("configure", "ip telnet server") in log and ("save", "") not in log
    assert set(entry["rolled_back"]) == {"LYSS-MGMT-001", "LYSS-LOG-010"}


def test_unverified_fix_is_rolled_back(lab, monkeypatch):
    device, log = lab
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeSession(log))
    passing_after(monkeypatch, {"LYSS-MGMT-001"})  # LOG-010 still fails after the change
    entry = remediate.apply_device(device, ["LYSS-MGMT-001", "LYSS-LOG-010"], None, lambda *a: None)
    assert entry["applied"] == ["LYSS-MGMT-001"] and entry["rolled_back"] == ["LYSS-LOG-010"]
    assert ("configure", "no logging host 192.0.2.60") in log and entry["saved"]


def test_switch_refusing_a_new_session_is_retried(lab, monkeypatch):
    """Old SG300s drop SSH sessions opened in quick succession (EOFError seen on an SG300)."""
    device, log = lab
    attempts = []

    def flaky(d, j):
        attempts.append(1)
        if len(attempts) == 1:
            raise EOFError()
        return FakeSession(log)
    monkeypatch.setattr(collector, "open_session", flaky)
    monkeypatch.setattr(remediate.time, "sleep", lambda s: None)
    passing_after(monkeypatch, {"LYSS-MGMT-001"})
    entry = remediate.apply_device(device, ["LYSS-MGMT-001"], None, lambda *a: None)
    assert entry["outcome"] == "applied and saved" and len(attempts) >= 2


def test_connection_lost_while_sending_rolls_back_on_a_new_session(lab, monkeypatch):
    device, log = lab

    class Dying(FakeSession):
        def configure(self, commands):
            if commands == ["logging host 192.0.2.60"]:
                raise EOFError()
            return super().configure(commands)
    sessions = []

    def opener(d, j):
        sessions.append(1)
        return Dying(log) if len(sessions) == 1 else FakeSession(log)
    monkeypatch.setattr(collector, "open_session", opener)
    progress = []
    entry = remediate.apply_device(device, ["LYSS-MGMT-001", "LYSS-LOG-010"], None,
                                   lambda m, p=None: progress.append(p))
    assert "connection lost" in entry["outcome"] and "rolled back, not saved" in entry["outcome"]
    assert ("configure", "ip telnet server") in log and ("save", "") not in log and len(sessions) == 2
    values = [p for p in progress if p is not None]
    assert values == sorted(values)


def test_progress_reaches_100(lab, monkeypatch):
    device, log = lab
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeSession(log))
    passing_after(monkeypatch, {"LYSS-MGMT-001"})
    progress = []
    remediate.apply_device(device, ["LYSS-MGMT-001"], None, lambda m, p=None: progress.append(p))
    values = [p for p in progress if p is not None]
    assert values[0] < values[-1] == 100 and values == sorted(values)


def test_mitigation_already_in_place_is_not_offered_again():
    """An SG300 after the change: web interface off, VULN-001 still fails (end of support)."""
    case, fail = failing("sb-weak")
    state = "\n".join(l for l in case["state"].splitlines() if not l.startswith(("TCP   All:80", "TCP   All:23")))
    fixes = {f.control_id: f for f in remediate.fixes_for("cisco_sb", parse(case["config"], state), fail, PARAMS)}
    assert "LYSS-VULN-001" in fail and "LYSS-VULN-001" not in fixes
    assert all(f.commands for f in fixes.values())


def test_sb_banner_is_typed_interactively():
    """Cisco SB 'banner login #' enters a text mode and discards what was typed before its
    "Enter TEXT message" line (timeout seen on an SG300): each line waits for the switch."""

    class SwitchChannel:
        def __init__(self):
            self.sent, self.queue, self.text_mode = [], "", False

        def send(self, data):
            self.sent.append(data)
            if data.startswith("banner login #"):
                self.text_mode = True
                self.queue += "banner login #\nEnter TEXT message. End with the character '#'.\n"
            elif self.text_mode and data == "#\n":
                self.queue += "#\nlab(config)#"
            elif not self.text_mode:
                self.queue += data + "lab(config)#"

        def recv_ready(self):
            return bool(self.queue)

        def recv(self, n):
            out, self.queue = self.queue, ""
            return out.encode()

    s = collector.ShellSession.__new__(collector.ShellSession)
    s.chan = SwitchChannel()
    out = s._multiline("banner login #\nAuthorized access only.\n#")
    assert s.chan.sent == ["banner login #\n", "Authorized access only.\n", "#\n"]
    assert out.rstrip().endswith("lab(config)#") and not collector.CLI_ERROR.search(out)

    # SG300 1.4 (03/11): the text mode starts silently, without any "Enter TEXT message" line
    silent = SwitchChannel()
    original = silent.send

    def quiet(data):
        original(data)
        if data.startswith("banner login #"):
            silent.queue = ""
    silent.send = quiet
    s.chan = silent
    out = s._multiline("banner login #\nAuthorized access only.\n#")
    assert silent.sent == ["banner login #\n", "Authorized access only.\n", "#\n"]
    assert out.rstrip().endswith("lab(config)#") and [t[0] for t in s.transcript] == ["banner login #", "Authorized access only.", "#"]


def test_prompt_repeated_after_an_ansi_erase_code():
    """Exact SG300 output after the banner (03/11): the prompt twice around ESC[K."""
    raw = "\n#\nlab-sw(config)#\x1b[Klab-sw(config)#"
    clean = collector.ShellSession.ANSI.sub("", raw)
    assert "\x1b" not in clean and collector.ShellSession.PROMPT.search(clean)
    # ordinary prompts still match, banner text and a lone delimiter do not
    assert collector.ShellSession.PROMPT.search("show version\nlab-sw#")
    assert not collector.ShellSession.PROMPT.search("banner login \nAuthorized access only.\n")
    assert not collector.ShellSession.PROMPT.search("text\n#")


def test_disabled_remediation_is_refused(lab):
    s = inventory.load_settings()
    s["remediation"]["enabled"] = False
    inventory.save_settings(s)
    assert all(f.blocked for f in remediate.plan(inventory.get_device("lab")))
    with pytest.raises(PermissionError):
        remediate.start({"lab": ["LYSS-MGMT-001"]})
