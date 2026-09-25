# Orchestration layer: wires CLI args, allowlist loading, the tracker, and the live capture together.

import argparse
import time
from typing import List, Optional, Set

from port_guard.allowlist import load_allowlist
from port_guard.capture import start_capture
from port_guard.cli import parse_args
from port_guard.alerting import format_alert_text, log_alert_json
from port_guard.guard import handle_packet
from port_guard.tracker import PortActivityTracker
from port_guard.helper import list_interfaces


def print_welcome() -> None:
    print("-" * 50)
    print("  Port Guard — TCP Port Scan Detector")
    print("-" * 50)
    print("Watches incoming SYN packets and alerts you when a source")
    print("IP touches too many distinct ports in too short a window.")
    print("Run with -h for the full list of options.\n")

def print_status(args: argparse.Namespace, interfaces: List[str], allowlist: Set[str]) -> None:
    print(f"Watching {len(interfaces)} interface(s): {', '.join(interfaces)}")
    print(f"Threshold: {args.threshold} distinct ports | Window: {args.window}s")

    if args.allowlist:
        print(f"Allowlist: {len(allowlist)} IP(s) loaded from {args.allowlist}")

    if args.log:
        print(f"Logging alerts to: {args.log}")

    print("Listening for scans... (Ctrl+C to stop)\n")

def run(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    print_welcome()
    interfaces = list_interfaces()
    allowlist = load_allowlist(args.allowlist) if args.allowlist else set()
    tracker = PortActivityTracker()
    print_status(args, interfaces, allowlist)

    threshold = args.threshold
    window = args.window
    log = args.log
    packet_count = 0

    def on_packet(packet):
        nonlocal packet_count
        packet_count += 1
        alert = handle_packet(packet, tracker, threshold, window, allowlist)

        if alert:
            print(format_alert_text(alert))

            if log:
                log_alert_json(alert, log)

        if packet_count % 100 == 0:
            tracker.prune(time.time(), window)

    start_capture(on_packet)
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(run())
