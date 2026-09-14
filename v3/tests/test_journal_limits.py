from __future__ import annotations

import unittest

from va_watchdog.journal import _size_bytes


class JournalLimitTests(unittest.TestCase):
    def test_journald_size_values_are_parsed_for_safe_limit_checks(self):
        self.assertEqual(_size_bytes("512M"), 512 * 1024 * 1024)
        self.assertEqual(_size_bytes("1G"), 1024 * 1024 * 1024)

    def test_default_or_invalid_journald_size_is_unbounded(self):
        self.assertIsNone(_size_bytes("system default"))
        self.assertIsNone(_size_bytes("invalid"))


if __name__ == "__main__":
    unittest.main()
