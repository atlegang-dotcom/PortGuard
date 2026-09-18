# Allowlist layer: known-good IPs that should never trigger an alert.

from typing import Set
from port_guard.helper import check_ip

def load_allowlist(filepath: str) -> Set[str]:
    result = set()
    with open(filepath, "r") as file:
        data = file.read().split()

    for addr in data:

        if not check_ip(addr):
            continue

        if "#" in addr:
            continue

        result.add(addr.strip())

    return result

def is_allowlisted(ip: str, allowlist: Set[str]) -> bool:
    if ip in allowlist:
        return True

    else:
        return False