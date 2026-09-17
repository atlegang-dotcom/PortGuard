# Capture layer: recognise SYN packets and pull out the fields we care about. 

from typing import Callable, Dict, Optional

from scapy.all import IP, TCP


def is_syn_packet(packet) -> bool:
    raise NotImplementedError


def extract_syn_info(packet) -> Optional[Dict]:
    raise NotImplementedError


def start_capture(interface: str, on_packet: Callable) -> None:
    raise NotImplementedError
