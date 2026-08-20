import unittest
from pathlib import Path

from va_watchdog.web import LEGACY_PAGE_REDIRECTS, VISIBLE_PAGE_GROUPS


class WebNavigationTests(unittest.TestCase):
    def test_visible_navigation_is_limited_to_six_pages(self):
        pages = [page for _, group_pages in VISIBLE_PAGE_GROUPS for page in group_pages]

        self.assertEqual(pages, [
            ("Overview", "/"),
            ("Events", "/events"),
            ("Hardware", "/hardware"),
            ("Network", "/network"),
            ("Services", "/services"),
            ("Settings", "/settings"),
        ])

    def test_removed_pages_redirect_to_their_replacement_sections(self):
        self.assertEqual(LEGACY_PAGE_REDIRECTS, {
            "/storage": "/hardware#storage",
            "/watchdog": "/services#watchdog",
            "/history": "/events?view=history",
            "/diagnostics": "/events?view=evidence",
            "/recovery": "/settings#recovery",
            "/updates": "/settings#software-update",
        })

    def test_watchdog_safety_countdown_reloads_once_at_zero(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("va-watchdog-grace-reload", source)
        self.assertIn("if(s<=0){clearInterval(t)", source)
        self.assertIn("setTimeout(function(){window.location.reload();},500)", source)


if __name__ == "__main__":
    unittest.main()
