import unittest

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


if __name__ == "__main__":
    unittest.main()
