# Guard layer: the per-packet decision pipeline.

from typing import Dict, Optional, Set

from port_guard.tracker import PortActivityTracker
from port_guard.capture import extract_syn_info
from port_guard.allowlist import is_allowlisted
from port_guard.detector import is_scan, classify_severity
from port_guard.alerting import build_alert

def handle_packet(packet, tracker: PortActivityTracker, threshold: int, window_seconds: float, allowlist: Set[str]) -> Optional[Dict]:
    info = extract_syn_info(packet)
    if info is None:
        return None

    src_ip = info["src_ip"]
    port = info["dst_port"]
    timestamp = info["timestamp"]
    interface = info["interface"]
    if is_allowlisted(src_ip, allowlist):
        return None

    tracker.record_hit(src_ip, port, timestamp)
    ports = tracker.get_ports_in_window(src_ip, window_seconds, timestamp)
    if not is_scan(len(ports), threshold):
        return None

    severity = classify_severity(len(ports), window_seconds)
    return build_alert(src_ip, ports, severity, window_seconds, interface)