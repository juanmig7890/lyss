# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Every control, on every fully supported platform, has a case where it passes and one where it
fails, and each case's verdicts and conformance level are pinned in tests/cases/*/expected.yaml."""

import re

import pytest

from lyss.engine import audit, conformance, load_adapter, load_spec

from conftest import case_names, load_case

FULL_VENDORS = ["cisco_ios", "cisco_sb", "hp_procurve"]   # Level 1 + 2 checks and device state
SECRETS_IN_CASES = ["cisco123", "PlainSharedKey", "0822455D0A16", "$9$FAKE", "FAKEHASH", "FAKEAESKEY"]


def run(case: dict):
    return audit(case["config"], case["vendor"], 2, case["state"], case["context"])


@pytest.mark.parametrize("name", case_names())
def test_case_verdicts(name):
    case = load_case(name)
    findings = {f.control_id: f for f in run(case)}
    for control_id, expected in case["expected"]["verdicts"].items():
        got = findings[control_id]
        assert got.verdict == expected, f"{name} {control_id}: expected {expected}, got {got.verdict} {got.evidence}"
    if "level" in case["expected"]:
        assert conformance(list(findings.values()))["achieved_level"] == case["expected"]["level"]


@pytest.mark.parametrize("vendor", FULL_VENDORS)
def test_every_control_has_a_passing_and_a_failing_case(vendor):
    seen: dict[str, set] = {}
    for name in case_names():
        case = load_case(name)
        if case["vendor"] == vendor:
            for f in run(case):
                seen.setdefault(f.control_id, set()).add(f.verdict)
    controls = [c["id"] for c in load_spec()["controls"] if c["level"] <= 2]
    missing = [c for c in controls if not {"pass", "fail"} <= seen.get(c, set())]
    assert not missing, f"{vendor}: controls without both a pass and a fail case: {missing}"


@pytest.mark.parametrize("vendor", FULL_VENDORS)
def test_full_adapters_implement_every_level_1_and_2_control(vendor):
    checks = load_adapter(vendor)["checks"]
    controls = [c["id"] for c in load_spec()["controls"] if c["level"] <= 2]
    assert not [c for c in controls if c not in checks]


def test_adapter_checks_reference_existing_controls():
    ids = {c["id"] for c in load_spec()["controls"]}
    for vendor in ("cisco_ios", "cisco_sb", "hp_procurve"):
        unknown = set(load_adapter(vendor)["checks"]) - ids
        assert not unknown, f"{vendor}: checks for unknown controls {unknown}"


def test_adapter_regexes_compile():
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("line", "block", "every_contains", "where", "state", "uplink_config", "require") and isinstance(value, str):
                    re.compile(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    for vendor in ("cisco_ios", "cisco_sb", "hp_procurve"):
        walk(load_adapter(vendor))


@pytest.mark.parametrize("name", case_names())
def test_no_secret_reaches_the_evidence(name):
    case = load_case(name)
    for f in run(case):
        for line in f.evidence:
            for secret in SECRETS_IN_CASES:
                assert secret not in line, f"{name} {f.control_id} leaks {secret!r}: {line}"


def test_failing_controls_carry_a_remediation():
    case = load_case("sb-weak")
    for f in run(case):
        if f.verdict == "fail":
            assert f.remediation or f.control_id in ("LYSS-VULN-001",), f"{f.control_id} has no remediation"
