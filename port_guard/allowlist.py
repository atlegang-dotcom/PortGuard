# Allowlist layer: known-good IPs that should never trigger an alert.

from typing import Set
import ipaddress as ip

def check_ip(ip_addr) -> bool:
    try:
        ip.ip_address(ip_addr)
        return True
    except ValueError:
        return False

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
    raise NotImplementedError