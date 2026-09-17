# Alerting layer: turn a detected scan into a structured alert, a
# human-readable message, and (optionally) a persisted log entry.

from typing import Dict, Set


def build_alert(src_ip: str, ports: Set[int], severity: str, window_seconds: float) -> Dict:
    raise NotImplementedError


def format_alert_text(alert: Dict) -> str:
    raise NotImplementedError


def log_alert_json(alert: Dict, filepath: str) -> None:
    raise NotImplementedError
