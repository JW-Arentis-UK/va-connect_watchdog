import unittest
from datetime import datetime, timezone

try:
    from va_watchdog.people_counting_report import build_people_counting_pdf
except ModuleNotFoundError:
    build_people_counting_pdf = None


@unittest.skipIf(build_people_counting_pdf is None, "Install v3/requirements.txt for PDF report tests")
class PeopleCountingReportTests(unittest.TestCase):
    def test_report_is_a_pdf_and_excludes_camera_credentials(self):
        identity = {"display_name": "Barton Lane", "site_name": "Barton Lane", "asset_id": "AHB-1"}
        camera = {
            "address": "192.168.1.72",
            "forward_label": "Car park side",
            "back_label": "Road side",
            "username": "admin",
            "password": "do-not-export",
        }
        summary = {
            "last_reported_counts": {"forward": "118", "back": "99", "bothway": "217"},
            "stale": False,
        }
        rows = [
            {"date": "2026-09-24", "forward": 116, "back": 95, "bothway": 211, "samples": 20,
             "scheduled_resets": 1, "unexpected_resets": 0, "complete": True},
            {"date": "2026-09-25", "forward": 118, "back": 99, "bothway": 217, "samples": 18,
             "scheduled_resets": 1, "unexpected_resets": 0, "complete": False},
        ]

        document = build_people_counting_pdf(
            identity, camera, summary, rows, datetime(2026, 9, 25, 12, tzinfo=timezone.utc)
        )

        self.assertTrue(document.startswith(b"%PDF-"))
        self.assertGreater(len(document), 3000)
        self.assertNotIn(b"do-not-export", document)
        self.assertNotIn(b"admin", document)
