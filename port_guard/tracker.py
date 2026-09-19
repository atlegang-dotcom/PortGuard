# Tracker layer: remembers which ports each source IP has hit recently.

from typing import Dict, List, Set, Tuple
from port_guard.helper import filter_hits


class PortActivityTracker:

    def __init__(self) -> None:
        self._hits: Dict[str, List[Tuple[int, float]]] = {}

    def record_hit(self, src_ip: str, port: int, timestamp: float) -> None:
        self._hits.setdefault(src_ip, []).append([port, timestamp])

    def get_ports_in_window(self, src_ip: str, window_seconds: float, now: float) -> Set[int]:
        if src_ip not in self._hits:
            return set()

        hits = self._hits.get(src_ip)
        f_hits = filter_hits(hits, window_seconds, now)
        return {port for port, timestamp in f_hits}        

    def prune(self, now: float, max_age_seconds: float) -> None:
        for port in list(self._hits.keys()):
            hits = self._hits[port]
            self._hits[port] = filter_hits(hits, max_age_seconds, now)

            if len(self._hits[port]) <= 0:
                self._hits.pop(port)
