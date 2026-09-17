"""
Tests for port_guard.main.run()

This is the one place we DO mock — start_capture is a blocking, live,
root-requiring call, so we replace it and just verify run() wires the
right arguments to it. That's a wiring test, not a behaviour test;
the real behaviour is already covered by test_guard.py.
"""

from unittest.mock import patch

from port_guard.main import run


class TestRun:
    @patch("port_guard.main.start_capture")
    def test_calls_start_capture_with_correct_interface(self, mock_start_capture):
        run(["-i", "eth0"])

        args, kwargs = mock_start_capture.call_args
        assert args[0] == "eth0" or kwargs.get("interface") == "eth0"

    @patch("port_guard.main.start_capture")
    def test_returns_zero(self, mock_start_capture):
        exit_code = run(["-i", "eth0"])
        assert exit_code == 0

    @patch("port_guard.main.start_capture")
    def test_passes_an_on_packet_callback(self, mock_start_capture):
        run(["-i", "eth0"])

        args, kwargs = mock_start_capture.call_args
        callback = args[1] if len(args) > 1 else kwargs.get("on_packet")
        assert callable(callback)

    @patch("port_guard.main.load_allowlist")
    @patch("port_guard.main.start_capture")
    def test_loads_allowlist_when_path_given(self, mock_start_capture, mock_load):
        mock_load.return_value = {"10.0.0.5"}

        run(["-i", "eth0", "--allowlist", "trusted.txt"])

        mock_load.assert_called_once_with("trusted.txt")

    @patch("port_guard.main.load_allowlist")
    @patch("port_guard.main.start_capture")
    def test_skips_loading_allowlist_when_not_given(self, mock_start_capture, mock_load):
        run(["-i", "eth0"])

        mock_load.assert_not_called()
