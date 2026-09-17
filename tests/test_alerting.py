"""
Unit tests for port_guard.alerting
"""

import json

from port_guard.alerting import build_alert, format_alert_text, log_alert_json


class TestBuildAlert:
    def test_builds_correct_shape(self):
        alert = build_alert("10.0.0.5", {80, 22, 443}, "aggressive", 10.0)

        assert alert["src_ip"] == "10.0.0.5"
        assert alert["port_count"] == 3
        assert alert["severity"] == "aggressive"
        assert alert["window_seconds"] == 10.0

    def test_ports_are_sorted_in_output(self):
        alert = build_alert("10.0.0.5", {443, 22, 80}, "moderate", 10.0)
        assert alert["ports"] == [22, 80, 443]


class TestFormatAlertText:
    def test_includes_src_ip(self):
        alert = build_alert("10.0.0.5", {80, 22}, "moderate", 10.0)
        text = format_alert_text(alert)
        assert "10.0.0.5" in text

    def test_includes_port_count(self):
        alert = build_alert("10.0.0.5", {80, 22, 443}, "moderate", 10.0)
        text = format_alert_text(alert)
        assert "3" in text

    def test_includes_severity(self):
        alert = build_alert("10.0.0.5", {80}, "aggressive", 10.0)
        text = format_alert_text(alert)
        assert "aggressive" in text


class TestLogAlertJson:
    def test_appends_valid_json_line(self, tmp_path):
        filepath = tmp_path / "alerts.jsonl"
        alert = build_alert("10.0.0.5", {80, 22}, "moderate", 10.0)

        log_alert_json(alert, str(filepath))

        with open(filepath) as f:
            line = f.readline()
        parsed = json.loads(line)
        assert parsed["src_ip"] == "10.0.0.5"

    def test_second_call_appends_not_overwrites(self, tmp_path):
        filepath = tmp_path / "alerts.jsonl"
        alert1 = build_alert("10.0.0.5", {80}, "slow", 10.0)
        alert2 = build_alert("10.0.0.6", {22}, "slow", 10.0)

        log_alert_json(alert1, str(filepath))
        log_alert_json(alert2, str(filepath))

        with open(filepath) as f:
            lines = f.readlines()
        assert len(lines) == 2
