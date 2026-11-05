# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Web interface: authentication, CSRF/Origin protection, headers, pages, exports, settings,
backups. Runs on a temporary data directory with synthetic switches."""

import re

import pytest
from fastapi.testclient import TestClient

from lyss import collector, history, inventory, scan
from lyss.web import app as webapp

from conftest import load_case

PASSWORD = "correct horse battery"


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


@pytest.fixture
def fleet(data_dir):
    """Two synthetic switches with collected data and an audit result each."""
    for device_id, case_name in (("lab-good", "sb-hardened"), ("lab-bad", "sb-weak")):
        case = load_case(case_name)
        device = {"id": device_id, "host": "192.0.2.1", "port": "22", "vendor": case["vendor"],
                  "username": "ro", "via_jump": False}
        inventory.save_device(device, "Sw1tch-Pass!")
        cfg, state = collector.config_paths(inventory.get_device(device_id))
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(case["config"], encoding="utf-8")
        state.write_text(case["state"], encoding="utf-8")
        scan.audit_device(inventory.get_device(device_id), "schedule")
    return data_dir


@pytest.fixture
def client(fleet):
    webapp._sessions.clear()
    webapp._failures.update(count=0, locked_until=0)
    return TestClient(webapp.app, base_url="http://127.0.0.1:8765")


def login(c) -> str:
    r = c.post("/setup", data={"password": PASSWORD, "confirm": PASSWORD}, follow_redirects=False)
    assert r.status_code == 303
    return csrf_of(c.get("/").text)


def test_requires_login_and_sets_security_headers(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/api/job").status_code == 401
    r = client.get("/login")
    assert "Choose the administrator password" in r.text
    for h in ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"):
        assert h in r.headers
    assert "'unsafe-inline'" not in r.headers["content-security-policy"]
    assert client.get("/docs").status_code == 404


def test_setup_login_cookie_and_lockout(client):
    assert client.post("/setup", data={"password": "short", "confirm": "short"}).status_code == 400
    r = client.post("/setup", data={"password": PASSWORD, "confirm": PASSWORD}, follow_redirects=False)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    client.cookies.clear()
    for _ in range(5):
        assert client.post("/login", data={"password": "wrong"}).status_code in (401, 429)
    assert client.post("/login", data={"password": PASSWORD}).status_code == 429


def test_csrf_and_origin_protection(client):
    token = login(client)
    assert client.post("/scan", data={"csrf": "forged"}, follow_redirects=False).headers["location"] == "/login"
    token = login_again(client)
    assert client.post("/devices/new", data={"csrf": token}, headers={"origin": "http://evil.example"}).status_code == 403
    r = client.post("/devices/new", data={"csrf": token}, headers={"sec-fetch-site": "cross-site", "origin": "null"})
    assert r.status_code == 403
    r = client.post("/devices/new", data={"csrf": token, "id": "x"}, headers={"sec-fetch-site": "same-origin", "origin": "null"})
    assert r.status_code == 400  # accepted, then validated


def login_again(c) -> str:
    c.cookies.clear()
    assert c.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    return csrf_of(c.get("/").text)


def test_pages_render_without_secrets(client):
    login(client)
    secrets = [d["secret"][:16] for d in inventory.load_devices()] + ["Sw1tch-Pass!", "cisco123", "PlainSharedKey"]
    pages = ["/", "/matrix", "/topology", "/discovery", "/settings", "/devices/new", "/remediation", "/firmware",
             "/devices/lab-good", "/devices/lab-bad", "/devices/lab-good/edit", "/api/topology"]
    for url in pages:
        r = client.get(url)
        assert r.status_code == 200, url
        for s in secrets:
            assert s not in r.text, f"{s!r} leaked on {url}"
    assert "Level 2" in client.get("/devices/lab-good").text


def test_exports_are_self_contained_and_clean(client):
    login(client)
    html = client.get("/export/report.html")
    assert html.status_code == 200 and "attachment" in html.headers["content-disposition"]
    assert "<title>Morocco</title>" in html.text
    assert not re.search(r'(src|href)="(https?:)?//', html.text)
    js = client.get("/export/report.json")
    assert '"secret"' not in js.text and "Sw1tch-Pass!" not in js.text
    assert client.get("/export/report.html?device=lab-good").status_code == 200


def test_backups_attestation_and_traversal(client):
    token = login(client)
    v = history.versions("lab-good")
    assert v and client.get(f"/devices/lab-good/backups/{v[0]['file']}").status_code == 200
    r = client.get("/devices/lab-good/backups/..%2F..%2Fsettings.json", follow_redirects=False)
    assert r.status_code in (303, 404)
    r = client.post("/devices/lab-bad/attest", data={"csrf": token, "reference": "Oxidized nightly"}, follow_redirects=False)
    assert r.status_code == 303
    result = inventory.load_result("lab-bad")
    bkp = next(f for f in result["findings"] if f["control_id"] == "LYSS-BKP-001")
    assert bkp["verdict"] == "pass" and "Oxidized nightly" in bkp["evidence"][0]


def test_settings_integrations_never_echo_secrets(client):
    token = login(client)
    r = client.post("/settings/schedule", data={"csrf": token, "enabled": "on", "at": "25:00", "days": ["0"]})
    assert r.status_code == 400
    r = client.post("/settings/schedule", data={"csrf": token, "enabled": "on", "at": "02:30", "days": ["0", "3"]})
    assert r.status_code == 200 and inventory.load_settings()["schedule"]["days"] == [0, 3]
    r = client.post("/settings/smtp", data={"csrf": token, "enabled": "on", "host": "smtp.example.com", "port": "587",
                                             "security": "starttls", "username": "u", "password": "Smtp-S3cret",
                                             "sender": "lyss@example.com", "recipients": "a@example.com, b@example.com",
                                             "mode": "regressions"})
    assert r.status_code == 200 and "Smtp-S3cret" not in r.text
    smtp = inventory.load_settings()["smtp"]
    assert smtp["recipients"] == ["a@example.com", "b@example.com"] and "Smtp-S3cret" not in str(smtp)
    r = client.post("/settings/ciso", data={"csrf": token, "enabled": "on", "url": "https://ciso.example:8443",
                                             "token": "Api-T0ken", "evidence_id": "abc-123", "verify_tls": "on"})
    assert r.status_code == 200 and "Api-T0ken" not in r.text and "Api-T0ken" not in str(inventory.load_settings())
    assert client.post("/settings/ciso", data={"csrf": token, "enabled": "on", "url": "javascript:alert(1)",
                                               "evidence_id": "x"}).status_code == 400


def test_credential_profiles_and_prefilled_form(client):
    token = login(client)
    r = client.post("/settings/profiles", data={"csrf": token, "name": "Test RO", "username": "ro-user",
                                                "password": "Pr0file-Secret!"})
    assert r.status_code == 200 and "Pr0file-Secret!" not in r.text
    assert inventory.device_credentials({"profile": "test-ro"}) == ("ro-user", "Pr0file-Secret!")
    form = client.get("/devices/new?host=192.0.2.9&id=new-sw&vendor=cisco_sb").text
    assert 'value="192.0.2.9"' in form and "Profile: Test RO" in form and "Auto-detect" in form
    assert client.post("/settings/profiles/test-ro/delete", data={"csrf": token}).status_code == 200
