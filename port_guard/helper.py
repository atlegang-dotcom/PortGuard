import ipaddress as ip

# Checks/validates ip address, returns True if it's a valid ip address, false if not
def check_ip(ip_addr) -> bool:
    try:
        ip.ip_address(ip_addr)
        return True
    except ValueError:
        return False

# checks or validates if a port scanned/hit is within the range now - timestamp <= window_seconds
def filter_hits(hits: list, window: float, now: float) -> bool:
    result = []
    for hit in hits:
        if now - hit[1] <= window:
            result.append([hit[0], hit[1]])

    return result