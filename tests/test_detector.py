# Unit tests for port_guard.detector

from port_guard.detector import is_scan, classify_severity


class TestIsScan:
    def test_below_threshold_is_not_a_scan(self):
        assert is_scan(port_count=5, threshold=15) is False

    def test_exactly_at_threshold_is_a_scan(self):
        assert is_scan(port_count=15, threshold=15) is True

    def test_above_threshold_is_a_scan(self):
        assert is_scan(port_count=50, threshold=15) is True

    def test_zero_ports_is_never_a_scan(self):
        assert is_scan(port_count=0, threshold=15) is False


class TestClassifySeverity:
    def test_high_rate_is_aggressive(self):
        # 30 ports in 5 seconds = 6 ports/sec
        assert classify_severity(port_count=30, window_seconds=5.0) == "aggressive - 6.0 ports/sec"

    def test_medium_rate_is_moderate(self):
        # 5 ports in 10 seconds = 0.5 ports/sec
        assert classify_severity(port_count=5, window_seconds=10.0) == "moderate - 0.5 ports/sec"

    def test_low_rate_is_slow(self):
        # 2 ports in 60 seconds
        assert classify_severity(port_count=2, window_seconds=60.0) == "slow - 0.03333333333333333 ports/sec"

    def test_returns_one_of_the_three_known_labels(self):
        result = classify_severity(port_count=15, window_seconds=10.0)
        assert result in ("slow", "moderate - 1.5 ports/sec", "aggressive")
