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

    def test_hardware_and_storage_keep_engineering_detail_collapsed(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")
        start = source.index("        def hardware_page():")
        end = source.index("        def network_page():", start)
        renderer = source[start:end]

        self.assertIn("Gateway Hardware", renderer)
        self.assertIn('disclosure("Engineering hardware details"', renderer)
        self.assertIn("Recording Location", renderer)
        self.assertIn('disclosure("Storage setup and safeguards"', renderer)
        self.assertNotIn("Neousys Watchdog Discovery", renderer)

    def test_network_page_uses_compact_operator_view(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")
        start = source.index("        def network_page():")
        end = source.index("        def speed_test_result_html", start)
        renderer = source[start:end]

        self.assertIn("<th>Target</th><th>Check</th><th>Status</th><th>Detail</th>", renderer)
        self.assertIn('disclosure("Network tools and engineering details"', renderer)
        self.assertNotIn("TeamViewer placeholder", renderer)

    def test_settings_do_not_advertise_unimplemented_update_actions(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertNotIn("Check-only comparison", source)
        self.assertNotIn("Planned: return to a previously validated build", source)
        self.assertIn('disclosure("Software update", updates_card(), opened=True)', source)
        self.assertIn('disclosure("Recovery and repair tools", recovery_page())', source)

    def test_overview_hides_detailed_evidence_and_services_by_default(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('disclosure("Stability evidence", stability_detail)', source)
        self.assertIn('disclosure("Service details", services_card())', source)


if __name__ == "__main__":
    unittest.main()
