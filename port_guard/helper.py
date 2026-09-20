import ipaddress as ip
from scapy.all import IP, IPv6, get_if_list

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

# filter between IPv6 and IPv4, by checking each for the ip layer they belong too, returns an IP address of the layer that is found
def ip_filter(packet) -> str:
    if packet.haslayer(IP):
        return packet[IP].src
        
    elif packet.haslayer(IPv6):
        return packet[IPv6].src

    else:
        return None

# return all interfaces on machine
def list_interfaces() -> List[str]:
    return get_if_list()