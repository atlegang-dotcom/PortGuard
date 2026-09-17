# Tracker layer: remembers which ports each source IP has hit recently.

from typing import Dict, List, Set, Tuple


class PortActivityTracker:

    def __init__(self) -> None:
        self._hits: Dict[str, List[Tuple[int, float]]] = {}

    def record_hit(self, src_ip: str, port: int, timestamp: float) -> None:
        raise NotImplementedError

    def get_ports_in_window(self, src_ip: str, window_seconds: float, now: float) -> Set[int]:
        raise NotImplementedError

    def prune(self, now: float, max_age_seconds: float) -> None:
        raise NotImplementedError
