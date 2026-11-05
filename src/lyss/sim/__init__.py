# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""LYSS switch simulator: fictitious Cisco IOS, Cisco Small Business and HPE Aruba (ProCurve)
switches reachable over SSH on 127.0.0.1, for demonstrations and end-to-end tests without
hardware. Every simulated device, address and secret is invented."""

from .lab import Lab, SimSwitch, load_lab
from .server import Simulator

__all__ = ["Lab", "SimSwitch", "Simulator", "load_lab"]
