# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""E-mail alerts against a local SMTP server, CISO Assistant against a mocked API."""

import socket
import time

import httpx
import pytest

from lyss import inventory, notify, vault


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def smtp_server():
    aiosmtpd = pytest.importorskip("aiosmtpd.controller")
    from aiosmtpd.handlers import Message

    received = []

    class Collect(Message):
        def handle_message(self, message):
            received.append(message)

    port = free_port()
    controller = aiosmtpd.Controller(Collect(), hostname="127.0.0.1", port=port)
    controller.start()
    yield port, received
    controller.stop()


def job(items):
    return {"trigger": "schedule", "items": items}


def test_alert_mail_only_when_something_happened(data_dir, smtp_server):
    port, received = smtp_server
    settings = inventory.load_settings()
    settings["smtp"] = {"enabled": True, "host": "127.0.0.1", "port": port, "security": "none",
                        "sender": "lyss@example.com", "recipients": ["soc@example.com"], "mode": "regressions"}
    inventory.save_settings(settings)

    quiet = notify.after_scan(job({"sw1": {"status": "done", "message": ""}}), {"sw1": {"new_fail": [], "fixed": []}}, 0)
    assert quiet == [] and received == []

    notices = notify.after_scan(job({"sw1": {"status": "done", "message": ""},
                                     "sw2": {"status": "error", "message": "TimeoutError"}}),
                                {"sw1": {"new_fail": ["LYSS-MGMT-001"], "fixed": []}}, 1)
    for _ in range(50):
        if received:
            break
        time.sleep(0.05)
    assert notices == ["alert e-mail sent"]
    body = received[0].get_payload()
    assert "LYSS-MGMT-001" in body and "TimeoutError" in body and "1 new switch" in body
    assert received[0]["To"] == "soc@example.com"


def test_ciso_push_sends_report_as_evidence_revision(data_dir, monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["auth"] = request.headers.get("authorization")
        if request.method == "GET":
            return httpx.Response(200, json={"id": "ev-1", "name": "Switch security report"})
        seen["path"] = request.url.path
        seen["body"] = request.content
        return httpx.Response(201, json={"id": "rev-42"})

    monkeypatch.setattr(notify, "_ciso_transport", httpx.MockTransport(handler))
    cfg = {"enabled": True, "url": "https://ciso.example", "evidence_id": "ev-1", "verify_tls": True,
           "secret": vault.protect("tok-123")}
    assert notify.ciso_test(cfg) == "Switch security report"
    assert notify.ciso_push("<html>report</html>", "scheduled scan", cfg) == "rev-42"
    assert seen["auth"] == "Token tok-123" and seen["path"] == "/api/evidence-revisions/"
    assert b"<html>report</html>" in seen["body"] and b'name="evidence"' in seen["body"]


def test_ciso_auto_push_only_after_scheduled_scans(data_dir, monkeypatch):
    calls = []
    monkeypatch.setattr(notify, "ciso_push", lambda html, obs, cfg=None: calls.append(obs) or "rev")
    settings = inventory.load_settings()
    settings["ciso"] = {"enabled": True, "auto_push": True, "url": "https://x", "evidence_id": "e", "secret": ""}
    inventory.save_settings(settings)
    notify.after_scan({"trigger": "manual", "items": {}}, {}, 0)
    assert calls == []
    assert notify.after_scan({"trigger": "schedule", "items": {}}, {}, 0) == ["report sent to CISO Assistant"]
