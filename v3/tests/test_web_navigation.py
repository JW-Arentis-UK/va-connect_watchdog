import unittest
from pathlib import Path

from va_watchdog.web import LEGACY_PAGE_REDIRECTS, VISIBLE_PAGE_GROUPS


class WebNavigationTests(unittest.TestCase):
    def test_visible_navigation_separates_operational_and_engineering_responsibilities(self):
        pages = [page for _, group_pages in VISIBLE_PAGE_GROUPS for page in group_pages]

        self.assertEqual(pages, [
            ("Overview", "/"),
            ("Events", "/events"),
            ("Hardware", "/hardware"),
            ("Network", "/network"),
            ("Services", "/services"),
            ("Watchdog", "/watchdog"),
            ("History", "/history"),
            ("Diagnostics", "/diagnostics"),
            ("Settings", "/settings"),
        ])

    def test_removed_pages_redirect_to_their_replacement_sections(self):
        self.assertEqual(LEGACY_PAGE_REDIRECTS, {
            "/storage": "/hardware#storage",
            "/recovery": "/settings#recovery",
            "/updates": "/settings#software-update",
        })

    def test_services_and_watchdog_have_separate_server_renderers(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('if page == "Services":\n            return page_help_html(page) + services_card()', source)
        self.assertIn('if page == "Watchdog":\n            return page_help_html(page) + watchdog_page()', source)
        self.assertNotIn('/services#watchdog', source)

    def test_watchdog_default_view_is_limited_to_neousys_operational_controls(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")
        start = source.index("        def watchdog_page():")
        end = source.index("        def storage_page():", start)
        watchdog_renderer = source[start:end]

        self.assertIn("Neousys WDT_DIO", watchdog_renderer)
        self.assertIn("Protection Details", watchdog_renderer)
        self.assertIn("Last Deliberate Test", watchdog_renderer)
        self.assertIn("Advanced diagnostics", watchdog_renderer)
        self.assertNotIn("Safe Watchdog Test", watchdog_renderer)
        self.assertNotIn("Existing watchdogs and cleanup", watchdog_renderer)

    def test_watchdog_safety_countdown_reloads_once_at_zero(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("va-watchdog-grace-reload", source)
        self.assertIn("if(s<=0){clearInterval(t)", source)
        self.assertIn("setTimeout(function(){window.location.reload();},500)", source)


if __name__ == "__main__":
    unittest.main()
