# Alerting layer: turn a detected scan into a structured alert, a
# human-readable message, and (optionally) a persisted log entry.

import json
from typing import Dict, Set
from port_guard.helper import check_ip

def build_alert(src_ip: str, ports: Set[int], severity: str, window_seconds: float) -> Dict:
    return {
        "src_ip": src_ip,
        "port_count": len(ports),
        "ports": sorted(ports),
        "severity": severity,
        "window_seconds": window_seconds
    }

def format_alert_text(alert: Dict) -> str:
    return f"[{alert['severity'].upper()}] {alert['src_ip']} hit {alert['port_count']} in {alert['window_seconds']}s."


def log_alert_json(alert: Dict, filepath: str) -> None:
    with open(filepath, "a") as file:
        json.dump(alert, file)
        file.write("\n")