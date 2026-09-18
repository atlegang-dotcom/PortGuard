import ipaddress as ip

# Checks/validates ip address, returns True if it's a valid ip address, false if not
def check_ip(ip_addr) -> bool:
    try:
        ip.ip_address(ip_addr)
        return True
    except ValueError:
        return False