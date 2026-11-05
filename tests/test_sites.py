# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Sites: ranges, automatic assignment (most specific range wins), explicit assignment, dashboard
filter and per-site totals, per-site exports and scans, gentle discovery of a site."""

import pytest
from fastapi.testclient import TestClient

from lyss import discovery, inventory, scan, sites
from lyss.web import app as webapp

from test_web import PASSWORD, csrf_of, fleet  # noqa: F401  (fixture)


def device(device_id: str, host: str, site: str = "") -> None:
    inventory.save_device({"id": device_id, "host": host, "port": "22", "vendor": "cisco_ios",
                           "username": "ro", "via_jump": False, "site": site}, "Sw1tch-Pass!")


def test_parse_accepts_large_site_ranges_and_rejects_garbage():
    nets, errors = sites.parse("198.18.0.0/16 192.0.2.7, 198.51.100.10-20 nonsense 198.18.0.0/4")
    assert nets == ["198.18.0.0/16", "192.0.2.7/32", "198.51.100.10-20"]
    assert len(errors) == 2


def test_most_specific_range_wins_and_explicit_site_is_kept(data_dir):
    assert sites.save("Head office", "198.51.0.0/16")[1] == []
    assert sites.save("Agency", "198.51.100.0/24")[1] == []
    assert sites.site_for_ip("198.51.100.9") == "agency"
    assert sites.site_for_ip("198.51.7.1") == "head-office"
    assert sites.site_for_ip("203.0.113.1") == ""
    assert sites.site_for_ip("sw.example.test") == ""
    device("acc-1", "198.51.100.9")
    device("pinned", "203.0.113.1", site="head-office")
    devices = {d["id"]: d for d in inventory.load_devices()}
    assert sites.of(devices["acc-1"]) == "agency"
    assert sites.of(devices["pinned"]) == "head-office"


def test_same_name_updates_and_delete_unpins(data_dir):
    sid, _ = sites.save("Riverside", "192.0.2.0/25")
    assert sites.save("riverside", "192.0.2.0/24")[0] == sid          # same name: ranges replaced
    assert sites.get(sid)["ranges"] == ["192.0.2.0/24"]
    assert sites.save("Riverside 2", "192.0.2.128/25")[0] != sid
    device("pinned", "203.0.113.5", site=sid)
    assert sites.delete(sid)
    assert inventory.get_device("pinned")["site"] == ""             # back to automatic


def test_unknown_site_is_rejected_on_a_switch(data_dir):
    errors = inventory.validate_device({"id": "x", "host": "192.0.2.1", "port": "22", "vendor": "cisco_ios",
                                        "username": "ro", "site": "nowhere"}, ["cisco_ios"])
    assert "Site: not found." in errors


def test_scan_ranges_skip_networks_larger_than_a_20(data_dir):
    sid, _ = sites.save("HQ", "198.18.0.0/16 192.0.2.0/24")
    ok, skipped = sites.scan_ranges(sites.get(sid))
    assert ok == ["192.0.2.0/24"] and skipped == ["198.18.0.0/16"]


def test_summary_counts_levels_and_unsited(data_dir):
    rows = [{"device": {"id": "a", "host": "192.0.2.1"}, "result": {"summary": {"fail": 3, "achieved_level": 1}}},
            {"device": {"id": "b", "host": "192.0.2.2"}, "result": None},
            {"device": {"id": "c", "host": "203.0.113.1"}, "result": {"summary": {"fail": 0, "achieved_level": 2}}}]
    sites.save("Lab", "192.0.2.0/24")
    by = {s["name"]: s for s in sites.summary(rows)}
    assert by["Lab"] == {"id": "lab", "name": "Lab", "devices": 2, "scanned": 1, "level1": 1, "level2": 0, "fail": 3}
    assert by["No site"]["devices"] == 1 and by["No site"]["level2"] == 1


@pytest.fixture
def client(fleet):  # noqa: F811
    webapp._sessions.clear()
    webapp._failures.update(count=0, locked_until=0)
    c = TestClient(webapp.app, base_url="http://127.0.0.1:8765")
    c.post("/setup", data={"password": PASSWORD, "confirm": PASSWORD})
    return c


def test_web_sites_dashboard_filter_report_and_scan(client, monkeypatch):
    csrf = csrf_of(client.get("/settings").text)
    r = client.post("/settings/sites", data={"csrf": csrf, "name": "Lab site", "ranges": "192.0.2.0/24"})
    assert r.status_code == 200 and "Site Lab site saved." in r.text
    assert client.post("/settings/sites", data={"csrf": csrf, "name": "Bad", "ranges": "999.1.1.1"}).status_code == 400
    # the two synthetic switches (192.0.2.1) fall in the site automatically
    page = client.get("/").text
    assert "Lab site" in page and 'href="/?site=lab-site"' in page
    filtered = client.get("/?site=lab-site").text
    assert "Switches · Lab site" in filtered and "Scan this site" in filtered
    report = client.get("/export/report.html?site=lab-site")
    assert report.status_code == 200 and "<dt>Site</dt><dd>Lab site</dd>" in report.text
    assert "site-lab-site" in report.headers["content-disposition"]
    started = []
    monkeypatch.setattr(scan, "start", lambda ids: started.append(sorted(ids)))
    r = client.post("/scan", data={"csrf": csrf, "site": "lab-site"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/?site=lab-site"
    assert started == [["lab-bad", "lab-good"]]
    # switch form offers the site, and pinning an unknown one fails
    assert "Automatic, from the address (currently: Lab site)" in client.get("/devices/lab-good/edit").text


def test_site_discovery_is_gentle(client, monkeypatch):
    csrf = csrf_of(client.get("/settings").text)
    client.post("/settings/sites", data={"csrf": csrf, "name": "Remote", "ranges": "198.51.100.0/24 198.18.0.0/16"})
    calls = []
    monkeypatch.setattr(discovery, "start_scan", lambda nets, via_jump, gentle=False, label="":
                        calls.append((nets, via_jump, gentle, label)) or True)
    page = client.get("/discovery").text
    assert "Scan a site" in page and "skipped (larger than /20): 198.18.0.0/16" in page
    r = client.post("/discovery/site", data={"csrf": csrf, "site_id": "remote"}, follow_redirects=False)
    assert r.status_code == 303
    assert calls == [(["198.51.100.0/24"], False, True, "Remote")]
