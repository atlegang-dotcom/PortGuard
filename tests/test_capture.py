"""
Unit tests for port_guard.capture

These build real scapy packet objects in memory — IP()/TCP(...) does
NOT touch the network or need root, it just constructs a Python object
representing what such a packet would look like. This is closer to
what you'll see in real capture than mocking would be.
"""

from scapy.all import IP, TCP

from port_guard.capture import is_syn_packet, extract_syn_info


def make_packet(src="10.0.0.5", dst="10.0.0.1", dport=80, flags="S"):
    return IP(src=src, dst=dst) / TCP(dport=dport, flags=flags)


class TestIsSynPacket:
    def test_bare_syn_returns_true(self):
        pkt = make_packet(flags="S")
        assert is_syn_packet(pkt) is True

    def test_syn_ack_returns_false(self):
        pkt = make_packet(flags="SA")
        assert is_syn_packet(pkt) is False

    def test_ack_only_returns_false(self):
        pkt = make_packet(flags="A")
        assert is_syn_packet(pkt) is False

    def test_fin_returns_false(self):
        pkt = make_packet(flags="F")
        assert is_syn_packet(pkt) is False

    def test_non_tcp_packet_returns_false(self):
        pkt = IP(src="10.0.0.5", dst="10.0.0.1")  # no TCP layer at all
        assert is_syn_packet(pkt) is False


class TestExtractSynInfo:
    def test_extracts_src_ip(self):
        pkt = make_packet(src="192.168.1.50")
        info = extract_syn_info(pkt)
        assert info["src_ip"] == "192.168.1.50"

    def test_extracts_dst_port(self):
        pkt = make_packet(dport=443)
        info = extract_syn_info(pkt)
        assert info["dst_port"] == 443

    def test_includes_timestamp_key(self):
        pkt = make_packet()
        info = extract_syn_info(pkt)
        assert "timestamp" in info
        assert isinstance(info["timestamp"], float)

    def test_returns_none_for_non_syn_packet(self):
        pkt = make_packet(flags="SA")
        assert extract_syn_info(pkt) is None

    def test_returns_none_for_non_tcp_packet(self):
        pkt = IP(src="10.0.0.5", dst="10.0.0.1")
        assert extract_syn_info(pkt) is None
