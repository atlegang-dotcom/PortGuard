# Orchestration layer: wires CLI args, allowlist loading, the tracker, and the live capture together.

from typing import List, Optional

from port_guard.allowlist import load_allowlist
from port_guard.capture import start_capture
from port_guard.cli import parse_args
from port_guard.alerting import format_alert_text, log_alert_json
from port_guard.guard import handle_packet
from port_guard.tracker import PortActivityTracker


def run(argv: Optional[List[str]] = None) -> int:
    raise NotImplementedError


if __name__ == "__main__":
    import sys
    sys.exit(run())
