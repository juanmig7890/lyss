# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Shared fixtures. Every test that touches data runs in a temporary data directory: the real
inventory, credentials and results under private/ are never read or modified by the suite."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

from lyss import inventory

CASES = Path(__file__).parent / "cases"


def pytest_addoption(parser):
    parser.addoption("--update-golden", action="store_true",
                     help="accept the current verdicts of the real switches (tests/test_private.py)")


@pytest.fixture
def data_dir(tmp_path):
    previous = inventory.PRIVATE
    inventory.configure(tmp_path / "data")
    yield tmp_path / "data"
    inventory.configure(previous)


def case_names() -> list[str]:
    return sorted(p.name for p in CASES.iterdir() if (p / "expected.yaml").exists())


def load_case(name: str) -> dict:
    """Configuration, state, expectations and backup context of a test case."""
    folder = CASES / name
    expected = yaml.safe_load((folder / "expected.yaml").read_text(encoding="utf-8"))
    source = CASES / expected.get("config_from", name)
    state = (source / "state.txt") if "config_from" not in expected else None
    return {
        "name": name,
        "vendor": expected["vendor"],
        "config": (source / "config.cfg").read_text(encoding="utf-8"),
        "state": state.read_text(encoding="utf-8") if state and state.exists() else "",
        "expected": expected,
        "context": backup_context(expected.get("backup")),
    }


def backup_context(spec: dict | None) -> dict | None:
    if not spec:
        return None
    now = datetime.now().replace(microsecond=0)
    if "automatic_days_ago" in spec:
        ts = (now - timedelta(days=spec["automatic_days_ago"])).isoformat()
        return {"backup": {"last": ts, "last_automatic": ts, "versions": 2, "attestation": None}}
    ts = (now - timedelta(days=spec.get("manual_days_ago", 0))).isoformat()
    return {"backup": {"last": ts, "last_automatic": None, "versions": 1, "attestation": None}}
