"""
Unit tests for port_guard.allowlist

Writes real (temporary, pytest-cleaned-up) files — no mocking needed
for simple file reads.
"""

from port_guard.allowlist import load_allowlist, is_allowlisted


class TestLoadAllowlist:
    def test_loads_ips_from_file(self, tmp_path):
        filepath = tmp_path / "allowlist.txt"
        filepath.write_text("10.0.0.5\n10.0.0.6\n")

        result = load_allowlist(str(filepath))

        assert result == {"10.0.0.5", "10.0.0.6"}

    def test_ignores_blank_lines(self, tmp_path):
        filepath = tmp_path / "allowlist.txt"
        filepath.write_text("10.0.0.5\n\n\n10.0.0.6\n")

        result = load_allowlist(str(filepath))

        assert result == {"10.0.0.5", "10.0.0.6"}

    def test_ignores_comment_lines(self, tmp_path):
        filepath = tmp_path / "allowlist.txt"
        filepath.write_text("# trusted monitoring box\n10.0.0.5\n")

        result = load_allowlist(str(filepath))

        assert result == {"10.0.0.5"}

    def test_strips_whitespace(self, tmp_path):
        filepath = tmp_path / "allowlist.txt"
        filepath.write_text("  10.0.0.5  \n")

        result = load_allowlist(str(filepath))

        assert result == {"10.0.0.5"}

    def test_empty_file_returns_empty_set(self, tmp_path):
        filepath = tmp_path / "allowlist.txt"
        filepath.write_text("")

        assert load_allowlist(str(filepath)) == set()


class TestIsAllowlisted:
    def test_present_ip_returns_true(self):
        assert is_allowlisted("10.0.0.5", {"10.0.0.5", "10.0.0.6"}) is True

    def test_absent_ip_returns_false(self):
        assert is_allowlisted("1.2.3.4", {"10.0.0.5"}) is False

    def test_empty_allowlist_always_returns_false(self):
        assert is_allowlisted("10.0.0.5", set()) is False
