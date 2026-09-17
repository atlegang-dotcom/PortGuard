# Guard layer: the per-packet decision pipeline.

from typing import Dict, Optional, Set

from port_guard.tracker import PortActivityTracker


def handle_packet(packet, tracker: PortActivityTracker, threshold: int, window_seconds: float, allowlist: Set[str]) -> Optional[Dict]:
    raise NotImplementedError