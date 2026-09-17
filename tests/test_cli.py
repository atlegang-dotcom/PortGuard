"""
Unit tests for port_guard.cli
"""

import pytest

from port_guard.cli import parse_args


class TestParseArgs:
    def test_interface_is_required(self):
        args = parse_args(["-i", "eth0"])
        assert args.interface == "eth0"

    def test_missing_interface_raises_systemexit(self):
        with pytest.raises(SystemExit):
            parse_args([])

    def test_default_threshold_is_15(self):
        args = parse_args(["-i", "eth0"])
        assert args.threshold == 15

    def test_default_window_is_10(self):
        args = parse_args(["-i", "eth0"])
        assert args.window == 10.0

    def test_default_allowlist_is_none(self):
        args = parse_args(["-i", "eth0"])
        assert args.allowlist is None

    def test_default_log_is_none(self):
        args = parse_args(["-i", "eth0"])
        assert args.log is None

    def test_custom_threshold(self):
        args = parse_args(["-i", "eth0", "-n", "25"])
        assert args.threshold == 25
        assert isinstance(args.threshold, int)

    def test_custom_window(self):
        args = parse_args(["-i", "eth0", "-w", "5"])
        assert args.window == 5.0

    def test_allowlist_path(self):
        args = parse_args(["-i", "eth0", "--allowlist", "trusted.txt"])
        assert args.allowlist == "trusted.txt"

    def test_log_path(self):
        args = parse_args(["-i", "eth0", "--log", "alerts.jsonl"])
        assert args.log == "alerts.jsonl"
