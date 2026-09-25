import unittest
from pathlib import Path

from va_watchdog.web import LEGACY_PAGE_REDIRECTS, VISIBLE_PAGE_GROUPS


class WebNavigationTests(unittest.TestCase):
    def test_visible_navigation_keeps_web_links_beside_status(self):
        pages = [page for _, group_pages in VISIBLE_PAGE_GROUPS for page in group_pages]

        self.assertEqual(pages, [
            ("Status", "/"),
            ("People Counting", "/people-counting"),
            ("Web Links", "/links"),
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

    def test_people_counting_is_a_dedicated_operator_page(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('if page == "People Counting":', source)
        self.assertIn("def people_counting_page():", source)
        self.assertIn("Current Camera Counters", source)
        self.assertIn("Observed Counter Changes", source)
        self.assertIn("Direction is not physically calibrated", source)
        self.assertIn('"/people-counting"', source)
        self.assertIn('route_path == "/api/people-counting"', source)

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

    def test_watchdog_offers_a_guarded_controlled_gateway_restart(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("Gateway Restart", source)
        self.assertIn('href=\\"/gateway-reboot-confirm\\"', source)
        self.assertIn('action=\\"/gateway-reboot-now\\"', source)
        self.assertIn("if not acknowledged:", source)
        self.assertNotIn("reboot-confirm-text", source)
        self.assertIn("Requested reboot", source)

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

    def test_update_launch_failure_renders_an_explanation_instead_of_http_error_page(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")
        start = source.index('            if route_path == "/update-now":')
        end = source.index('            if route_path == "/settings-save":', start)
        handler = source[start:end]

        self.assertIn("Update could not be started", handler)
        self.assertIn("self.send_response(200)", handler)
        self.assertNotIn("self.send_response(200 if result.get(\"ok\") else 500)", handler)

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
        self.assertIn("restart-watchdog", source)
        self.assertIn("restart-test", source)
        self.assertIn("restart-fault", source)
        self.assertIn("restart-unknown", source)
        self.assertIn(".restart-row .pill.restart-test", source)
        self.assertIn(".restart-row .pill.restart-unknown", source)
        self.assertIn("+ recent_restarts_card()", source)

    def test_status_shows_gateway_hardware_tile(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('gateway_hardware = hardware_identity()', source)
        self.assertIn('tile("Hardware", hardware_model, hardware_detail, hardware_state)', source)
        self.assertIn('gateway_hardware.get("display_model")', source)

    def test_web_links_page_groups_launchers_above_editors(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("def web_links_page():", source)
        self.assertLess(source.index("launch_html ="), source.index("management ="))
        self.assertIn("Add Web Link", source)
        self.assertIn("Edit Existing Links", source)
        self.assertIn('/web-link-add', source)
        self.assertIn('/web-link-update', source)
        self.assertIn('/web-link-delete', source)
        self.assertIn('if page == "Web Links":', source)
        self.assertNotIn("Camera WebUI test", source)

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
        self.assertIn('disclosure("RUTX50 setup help", router_setup_help)', source)
        self.assertNotIn('/help/rutx50', source)
        self.assertIn("Services &gt; Modbus &gt; Modbus TCP Server", source)
        self.assertIn("Connection checklist", source)
        self.assertIn("Monitoring verified:", source)
        self.assertIn("router_verified = all", source)
        self.assertIn("Signal advisory:", source)
        self.assertIn('"/evidence?router_period=24#network"', source)
        self.assertNotIn("Save and test router settings", source)
        self.assertNotIn('route_path == "/mobile-router-test"', source)
        self.assertIn("Open RUT WebUI", source)

    def test_hikvision_people_counting_setup_is_production_focused(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")
        start = source.index("            people_counting_settings = (")
        end = source.index("            recovery_settings = (", start)
        renderer = source[start:end]

        self.assertIn('settings_disclosure("Hikvision people counting"', source)
        self.assertIn('people_settings.pop("password", "")', source)
        self.assertIn("Collect people counters", renderer)
        self.assertIn("Camera delivery setup and repair", renderer)
        self.assertIn("Repair camera delivery", renderer)
        self.assertIn('value=\\\"http_push\\\"', renderer)
        self.assertNotIn("Run native API diagnostic", renderer)
        self.assertNotIn("Legacy capability test", renderer)
        self.assertNotIn("Capture camera statistics request", renderer)
        self.assertNotIn("ONVIF diagnostic subscription", renderer)

    def test_recording_storage_setup_is_visible_and_linked_from_status(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn('operational_row(\n                    "Recording storage"', source)
        self.assertIn('"/setup#storage"', source)
        self.assertIn('id=\\"storage\\"', source)
        self.assertIn('disclosure("Recording storage setup"', source)
        self.assertIn("Review recording storage setup", source)
        self.assertIn("choose Monitor only", source)
        self.assertIn('name=\\"cpu_temp_warning_c\\"', source)
        self.assertIn('name=\\"cpu_temp_critical_c\\"', source)

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
        self.assertIn("processValue.data_used_mb", source)
        self.assertIn("processValue.data_limit_mb", source)
        self.assertIn("status.watchdog_process || {}", source)

    def test_build_badge_reports_the_code_loaded_by_the_running_process(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertIn("running_version = {", source)
        self.assertIn('"commit": running_version["commit"]', source)
        self.assertIn("Built __BUILD_DATE__", source)
        self.assertIn('.replace("__BUILD_DATE__", escape(build_date))', source)
        self.assertIn(".top-build-date { color:var(--green);", source)

    def test_obsolete_client_renderer_is_not_activated(self):
        source = (Path(__file__).parents[1] / "va_watchdog" / "web.py").read_text(encoding="utf-8")

        self.assertNotIn("LIVE_RENDERED_PAGES", source)
        self.assertNotIn("renderOverview(status, events)", source)


if __name__ == "__main__":
    unittest.main()
