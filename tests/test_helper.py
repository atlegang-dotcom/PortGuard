"""
Unit tests for port_guard.helper

check_ip and filter_hits are pure — no mocking. ip_filter uses real
in-memory scapy packets, same pattern as test_capture.py. list_interfaces
just confirms the wrapper returns what get_if_list() actually returns.
"""

from scapy.all import IP, IPv6, TCP

from port_guard.helper import check_ip, filter_hits, ip_filter, list_interfaces


class TestCheckIp:
    def test_valid_ipv4_returns_true(self):
        assert check_ip("10.0.0.5") is True

    def test_valid_ipv6_returns_true(self):
        assert check_ip("fe80::1") is True

    def test_invalid_string_returns_false(self):
        assert check_ip("not-an-ip") is False

    def test_ipv4_with_port_suffix_returns_false(self):
        assert check_ip("10.0.0.5:80") is False

    def test_empty_string_returns_false(self):
        assert check_ip("") is False

    def test_out_of_range_octet_returns_false(self):
        assert check_ip("999.999.999.999") is False


class TestFilterHits:
    def test_hit_within_window_is_kept(self):
        hits = [(80, 100.0)]
        result = filter_hits(hits, window=10, now=105.0)
        assert result == [[80, 100.0]]

    def test_hit_outside_window_is_dropped(self):
        hits = [(80, 100.0)]
        result = filter_hits(hits, window=10, now=120.0)
        assert result == []

    def test_hit_exactly_at_window_edge_is_kept(self):
        hits = [(80, 100.0)]
        result = filter_hits(hits, window=10, now=110.0)
        assert result == [[80, 100.0]]

    def test_mixed_hits_only_recent_ones_kept(self):
        hits = [(80, 100.0), (443, 108.0), (22, 50.0)]
        result = filter_hits(hits, window=10, now=110.0)
        assert [h[0] for h in result] == [80, 443]

    def test_empty_hits_returns_empty_list(self):
        assert filter_hits([], window=10, now=100.0) == []

    def test_returns_a_list_not_a_bool(self):
        result = filter_hits([(80, 100.0)], window=10, now=100.0)
        assert isinstance(result, list)


class TestIpFilter:
    def test_extracts_ipv4_source(self):
        pkt = IP(src="192.168.1.50", dst="192.168.1.1") / TCP(dport=80, flags="S")
        assert ip_filter(pkt) == "192.168.1.50"

    def test_extracts_ipv6_source(self):
        pkt = IPv6(src="fe80::1", dst="fe80::2") / TCP(dport=80, flags="S")
        assert ip_filter(pkt) == "fe80::1"

    def test_prefers_ipv4_when_somehow_both_present(self):
        pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80, flags="S")
        assert ip_filter(pkt) == "10.0.0.5"

    def test_returns_none_when_neither_layer_present(self):
        from scapy.all import Ether
        pkt = Ether() / TCP(dport=80, flags="S")
        assert ip_filter(pkt) is None


class TestListInterfaces:
    def test_returns_a_list(self):
        assert isinstance(list_interfaces(), list)

    def test_matches_get_if_list_directly(self):
        from scapy.all import get_if_list
        assert list_interfaces() == get_if_list()

    def test_contains_at_least_one_interface(self):
        assert len(list_interfaces()) >= 1