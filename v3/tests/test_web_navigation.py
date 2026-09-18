import unittest
from pathlib import Path

from va_watchdog.web import LEGACY_PAGE_REDIRECTS, VISIBLE_PAGE_GROUPS


class WebNavigationTests(unittest.TestCase):
    def test_visible_navigation_is_reduced_to_five_operator_pages(self):
        pages = [page for _, group_pages in VISIBLE_PAGE_GROUPS for page in group_pages]

        self.assertEqual(pages, [
            ("Status", "/"),
            ("Events", "/events"),
            ("Watchdog", "/watchdog"),
            ("Evidence", "/evidence"),
            ("Setup", "/setup"),
        ])

    def test_removed_pages_redirect_to_their_replacement_sections(self):
        self.assertEqual(LEGACY_PAGE_REDIRECTS, {
            "/overview": "/",
            "/hardware": "/evidence#system",
            "/network": "/evidence#network",
            "/services": "/#services",
            "/history": "/evidence#history",
            "/diagnostics": "/evidence",
            "/settings": "/setup",
            "/storage": "/setup#storage",
            "/recovery": "/setup#recovery",
            "/updates": "/setup#software-update",
        })

    def test_status_and_watchdog_have_separate_server_renderers(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('if page == "Status":', source)
        self.assertIn('if page == "Watchdog":\n            return page_help_html(page) + watchdog_page()', source)
        self.assertNotIn('/services#watchdog', source)

    def test_watchdog_default_view_is_limited_to_neousys_operational_controls(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")
        start = source.index("        def watchdog_page():")
        end = source.index("        def storage_page():", start)
        watchdog_renderer = source[start:end]

        self.assertIn("Neousys WDT_DIO", watchdog_renderer)
        self.assertIn("Protection details and setup", watchdog_renderer)
        self.assertIn("Protection proven this boot", watchdog_renderer)
        self.assertIn("Last Test Result", watchdog_renderer)
        self.assertEqual(watchdog_renderer.count("Run deliberate test"), 1)
        self.assertIn("TEST IN PROGRESS", watchdog_renderer)
        self.assertIn("Waiting for reboot", watchdog_renderer)
        self.assertNotIn("Advanced diagnostics", watchdog_renderer)
        self.assertNotIn("Safe Watchdog Test", watchdog_renderer)
        self.assertNotIn("Existing watchdogs and cleanup", watchdog_renderer)

    def test_watchdog_safety_countdown_reloads_once_at_zero(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("va-watchdog-grace-reload", source)
        self.assertIn("if(s<=0){clearInterval(t)", source)
        self.assertIn("setTimeout(function(){window.location.reload();},500)", source)

    def test_watchdog_grace_accepts_a_confirmed_live_hardware_feed(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("feed_live = bool(", source)
        self.assertIn('feed_recent = bool(wdt.get("feed_live"))', source)
        self.assertIn('"feed_live": feed_live', source)

    def test_ending_startup_delay_keeps_live_hardware_feed(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")
        start = source.index("    def arm_hardware_watchdog_now():")
        end = source.index("    def disable_hardware_watchdog_during_grace():", start)
        action = source[start:end]

        self.assertIn('if not feed.get("feeding"):', action)
        self.assertNotIn('if feed.get("opened"):', action)
        self.assertIn("stale-heartbeat enforcement is now active", action)

    def test_event_evidence_expands_as_a_full_width_table_row(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('class=\\\"event-detail-row\\\" hidden', source)
        self.assertIn('onclick=\\\"toggleEventEvidence(this)\\\"', source)
        self.assertIn("detail.hidden=!opening", source)
        self.assertIn("width:calc(190px * var(--scale))", source)
        self.assertNotIn(".event-evidence[open] .event-evidence-body", source)

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

    def test_evidence_offers_a_dedicated_neousys_report(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("Download Neousys report", source)
        self.assertIn('/api/diagnostics/manufacturer-report.zip', source)
        self.assertIn('NEOUSYS-SYSTEM-REPORT.txt', source)

    def test_overview_names_the_problem_instead_of_using_watchdog_safe_wording(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('"recording_storage": "Recording storage"', source)
        self.assertIn('issue_summary = f"{primary_issue_name} needs attention"', source)
        self.assertNotIn("Attention needed, watchdog feed safe", source)

    def test_status_shows_compact_recent_restart_history(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("def recent_restarts_card():", source)
        self.assertIn("Planned tests are labelled separately from automatic recovery.", source)
        self.assertIn('restart.get("restart_type")', source)
        self.assertIn("+ recent_restarts_card()", source)

    def test_status_shows_gateway_hardware_tile(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('gateway_hardware = hardware_identity()', source)
        self.assertIn('tile("Hardware", hardware_model, hardware_detail, hardware_state)', source)
        self.assertIn('gateway_hardware.get("display_model")', source)

    def test_status_offers_direct_rut_webui_route_test(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("Test RUT WebUI", source)
        self.assertIn('href=\\"https://{escape(router_address)}\\"', source)
        self.assertIn('target=\\"_blank\\" rel=\\"noopener noreferrer\\"', source)
        self.assertIn("Videosoft browser route does not expose the router LAN address", source)
        self.assertIn("if router_configured and router_address", source)

    def test_mobile_router_is_compact_optional_evidence(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('disclosure("Mobile router monitoring", router_settings)', source)
        self.assertIn('"Mobile router",\n                        str(router_check.get("message")', source)
        self.assertIn('if router_configured else ""', source)
        self.assertIn("Evidence only. Router availability never controls the Neousys watchdog feed.", source)
        self.assertIn("Allow LAN access only and leave remote or WAN access disabled", source)
        self.assertIn("_format_duration(router_value.get('uptime_seconds'))", source)
        self.assertIn("local_time(router_value.get('started_at'))", source)
        self.assertIn('mobile_router_history_summary(', source)
        self.assertIn("def mobile_router_signal_chart", source)
        self.assertIn("router_period", source)
        self.assertIn("Mobile Signal Overview", source)
        self.assertIn("radio_score(router_value)", source)
        self.assertIn('disclosure("Recent router restarts"', source)
        self.assertIn('disclosure(f"{period_label} radio detail"', source)
        self.assertIn('mobile_router_snmp_community', source)
        self.assertIn('router_settings.pop("snmp_community", "")', source)
        self.assertIn("RUTX50 setup help", source)
        self.assertIn("Services &gt; Modbus &gt; Modbus TCP Server", source)
        self.assertIn("Connection checklist", source)
        self.assertIn('formaction=\\"/mobile-router-test\\"', source)
        self.assertIn('if route_path == "/mobile-router-test":', source)

    def test_watchdog_process_warning_requires_sustained_usage(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "process_monitor.py").read_text(encoding="utf-8")

        self.assertIn('warning_sustained_seconds", 60', source)
        self.assertIn("cpu_high_for >= warning_sustained", source)
        self.assertIn("memory_high_for >= warning_sustained", source)

    def test_header_shows_watchdog_process_overhead(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('id="watchdog-cpu"', source)
        self.assertIn('id="watchdog-memory"', source)
        self.assertIn('id="watchdog-disk"', source)
        self.assertIn("status.watchdog_process || {}", source)

    def test_build_badge_reports_the_code_loaded_by_the_running_process(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("running_version = {", source)
        self.assertIn('"commit": running_version["commit"]', source)

    def test_obsolete_client_renderer_is_not_activated(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertNotIn("LIVE_RENDERED_PAGES", source)
        self.assertNotIn("renderOverview(status, events)", source)


if __name__ == "__main__":
    unittest.main()
