# Capture layer: recognise SYN packets and pull out the fields we care about. 

from typing import Callable, Dict, List, Optional, Union
from scapy.all import IP, TCP, IPv6, sniff, get_if_list
from port_guard.helper import ip_filter, list_interfaces


def is_syn_packet(packet) -> bool:
    if not packet.haslayer(TCP):
        return False

    return str(packet[TCP].flags) == "S"


def extract_syn_info(packet) -> Optional[Dict]:
    if not is_syn_packet(packet):
        return None

    src_ip = ip_filter(packet)
    if src_ip is None:
        return None

    return {
        "src_ip": src_ip,
        "dst_port": packet[TCP].dport,
        "timestamp": float(packet.time),
        "interface": getattr(packet, "sniffed_on", None)
    }


def start_capture(on_packet: Callable) -> None:
    sniff(
        iface=list_interfaces(),
        filter="tcp",
        prn=on_packet,
        store=False
    )
