# Allowlist layer: known-good IPs that should never trigger an alert.

from typing import Set


def load_allowlist(filepath: str) -> Set[str]:
    raise NotImplementedError


def is_allowlisted(ip: str, allowlist: Set[str]) -> bool:
    raise NotImplementedError
