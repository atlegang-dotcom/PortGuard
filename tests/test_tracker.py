"""
Unit tests for port_guard.tracker.PortActivityTracker

`now` and `timestamp` are always passed in explicitly rather than read
from time.time() — that's what lets these tests simulate "10 seconds
later" instantly instead of actually sleeping.
"""

from port_guard.tracker import PortActivityTracker


class TestRecordHit:
    def test_recorded_hit_appears_in_window(self):
        tracker = PortActivityTracker()
        tracker.record_hit("10.0.0.5", 80, timestamp=100.0)

        ports = tracker.get_ports_in_window("10.0.0.5", window_seconds=10, now=100.0)

        assert ports == {80}

    def test_multiple_ports_same_ip_all_tracked(self):
        tracker = PortActivityTracker()
        tracker.record_hit("10.0.0.5", 22, timestamp=100.0)
        tracker.record_hit("10.0.0.5", 80, timestamp=100.5)
        tracker.record_hit("10.0.0.5", 443, timestamp=101.0)

        ports = tracker.get_ports_in_window("10.0.0.5", window_seconds=10, now=101.0)

        assert ports == {22, 80, 443}

    def test_different_ips_tracked_separately(self):
        tracker = PortActivityTracker()
        tracker.record_hit("10.0.0.5", 80, timestamp=100.0)
        tracker.record_hit("10.0.0.6", 22, timestamp=100.0)

        assert tracker.get_ports_in_window("10.0.0.5", 10, now=100.0) == {80}
        assert tracker.get_ports_in_window("10.0.0.6", 10, now=100.0) == {22}


class TestGetPortsInWindow:
    def test_hits_outside_window_are_excluded(self):
        tracker = PortActivityTracker()
        tracker.record_hit("10.0.0.5", 80, timestamp=100.0)

        # 20 seconds later, window is only 10 seconds wide
        ports = tracker.get_ports_in_window("10.0.0.5", window_seconds=10, now=120.0)

        assert ports == set()

    def test_hits_exactly_at_window_edge_are_included(self):
        tracker = PortActivityTracker()
        tracker.record_hit("10.0.0.5", 80, timestamp=100.0)

        ports = tracker.get_ports_in_window("10.0.0.5", window_seconds=10, now=110.0)

        assert ports == {80}

    def test_unknown_ip_returns_empty_set(self):
        tracker = PortActivityTracker()
        assert tracker.get_ports_in_window("1.2.3.4", 10, now=100.0) == set()

    def test_duplicate_port_hits_still_count_once(self):
        tracker = PortActivityTracker()
        tracker.record_hit("10.0.0.5", 80, timestamp=100.0)
        tracker.record_hit("10.0.0.5", 80, timestamp=100.2)  # same port again

        ports = tracker.get_ports_in_window("10.0.0.5", 10, now=100.2)

        assert ports == {80}


class TestPrune:
    def test_prune_removes_old_hits(self):
        tracker = PortActivityTracker()
        tracker.record_hit("10.0.0.5", 80, timestamp=0.0)
        tracker.record_hit("10.0.0.5", 443, timestamp=100.0)

        tracker.prune(now=100.0, max_age_seconds=10)

        ports = tracker.get_ports_in_window("10.0.0.5", window_seconds=1000, now=100.0)
        assert ports == {443}  # port 80's hit at t=0 should be gone

    def test_prune_removes_ip_entirely_when_all_hits_expired(self):
        tracker = PortActivityTracker()
        tracker.record_hit("10.0.0.5", 80, timestamp=0.0)

        tracker.prune(now=100.0, max_age_seconds=10)

        assert tracker.get_ports_in_window("10.0.0.5", window_seconds=1000, now=100.0) == set()

    def test_prune_with_no_data_does_not_raise(self):
        tracker = PortActivityTracker()
        tracker.prune(now=100.0, max_age_seconds=10)  # should just do nothing
