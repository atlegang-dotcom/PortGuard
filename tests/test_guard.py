"""
Tests for port_guard.guard.handle_packet

These are genuine integration tests — real scapy packets, a real
PortActivityTracker, real allowlist sets. No mocking, because every
dependency handle_packet calls is itself pure/deterministic once
implemented. If these tests need a mock to pass, something below this
layer has leaked non-determinism (e.g. reading real time.time()) and
should be fixed at the source, not patched over here.
"""

from scapy.all import IP, TCP

from port_guard.guard import handle_packet
from port_guard.tracker import PortActivityTracker


def make_syn(src="10.0.0.5", dport=80):
    return IP(src=src, dst="10.0.0.1") / TCP(dport=dport, flags="S")


class TestHandlePacket:
    def test_single_packet_below_threshold_returns_none(self):
        tracker = PortActivityTracker()

        result = handle_packet(
            make_syn(dport=80), tracker, threshold=15, window_seconds=10, allowlist=set()
        )

        assert result is None

    def test_reaching_threshold_returns_alert(self):
        tracker = PortActivityTracker()
        src = "10.0.0.5"
        result = None

        # simulate a scan: 15 SYNs to 15 different ports from the same IP
        for port in range(1, 16):
            result = handle_packet(
                make_syn(src=src, dport=port),
                tracker,
                threshold=15,
                window_seconds=10,
                allowlist=set(),
            )

        assert result is not None
        assert result["src_ip"] == src
        assert result["port_count"] == 15

    def test_allowlisted_ip_never_triggers_alert(self):
        tracker = PortActivityTracker()
        src = "10.0.0.5"
        result = None

        for port in range(1, 20):  # well above threshold
            result = handle_packet(
                make_syn(src=src, dport=port),
                tracker,
                threshold=15,
                window_seconds=10,
                allowlist={src},
            )

        assert result is None

    def test_non_syn_packet_returns_none(self):
        tracker = PortActivityTracker()
        pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80, flags="A")

        result = handle_packet(pkt, tracker, threshold=1, window_seconds=10, allowlist=set())

        assert result is None

    def test_different_source_ips_tracked_independently(self):
        tracker = PortActivityTracker()

        # attacker hits threshold
        result_attacker = None
        for port in range(1, 16):
            result_attacker = handle_packet(
                make_syn(src="10.0.0.5", dport=port),
                tracker,
                threshold=15,
                window_seconds=10,
                allowlist=set(),
            )

        # normal single connection from a different IP shouldn't trigger
        result_normal = handle_packet(
            make_syn(src="10.0.0.99", dport=443),
            tracker,
            threshold=15,
            window_seconds=10,
            allowlist=set(),
        )

        assert result_attacker is not None
        assert result_normal is None
