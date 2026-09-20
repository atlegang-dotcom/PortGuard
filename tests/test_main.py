"""
Tests for port_guard.main.run()

This is the one place we DO mock — start_capture is a blocking, live,
root-requiring call, so we replace it and just verify run() wires the
right arguments to it. That's a wiring test, not a behaviour test;
the real behaviour is already covered by test_guard.py.
"""

from unittest.mock import patch

from port_guard.main import run, print_welcome, print_status
from port_guard.cli import parse_args


class TestRun:
    @patch("port_guard.main.start_capture")
    def test_returns_zero(self, mock_start_capture):
        exit_code = run([])
        assert exit_code == 0

    @patch("port_guard.main.start_capture")
    def test_passes_an_on_packet_callback(self, mock_start_capture):
        run([])

        args, kwargs = mock_start_capture.call_args
        callback = args[0] if args else kwargs.get("on_packet")
        assert callable(callback)

    @patch("port_guard.main.load_allowlist")
    @patch("port_guard.main.start_capture")
    def test_loads_allowlist_when_path_given(self, mock_start_capture, mock_load):
        mock_load.return_value = {"10.0.0.5"}

        run(["--allowlist", "trusted.txt"])

        mock_load.assert_called_once_with("trusted.txt")

    @patch("port_guard.main.load_allowlist")
    @patch("port_guard.main.start_capture")
    def test_skips_loading_allowlist_when_not_given(self, mock_start_capture, mock_load):
        run([])

        mock_load.assert_not_called()

    def test_print_welcome_mentions_port_guard(self, capsys):
        print_welcome()
        captured = capsys.readouterr()
        assert "Port Guard" in captured.out

    def test_print_status_lists_interfaces(self, capsys):
        args = parse_args(["-n", "20"])
        print_status(args, interfaces=["eth0", "lo"], allowlist=set())
        captured = capsys.readouterr()
        assert "eth0" in captured.out
        assert "lo" in captured.out
        assert "20" in captured.out