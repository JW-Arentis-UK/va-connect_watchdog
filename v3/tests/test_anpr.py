import tempfile
import unittest
import os
from pathlib import Path

from va_watchdog.anpr import csv_report, load_settings, parse_metadata, query_reads, save_read, save_settings


SAMPLE = b'''<tt:MetadataStream xmlns:tt="http://www.onvif.org/ver10/schema"><tt:VideoAnalytics><tt:Frame UtcTime="2026-10-09T10:26:02Z"><tt:Object><tt:Appearance><tt:LicensePlateInfo><tt:PlateNumber>AB12 CDE</tt:PlateNumber><tt:CountryCode>GB</tt:CountryCode></tt:LicensePlateInfo><tt:VehicleInfo><tt:Brand>Example</tt:Brand><tt:Model>Car</tt:Model><tt:ColorString>Blue</tt:ColorString></tt:VehicleInfo></tt:Appearance></tt:Object></tt:Frame></tt:VideoAnalytics></tt:MetadataStream>'''


class AnprTests(unittest.TestCase):
    def test_camera_settings_are_validated_and_restricted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'anpr.json'
            save_settings('192.168.1.16', 'admin', 'example-password', 45, path)
            self.assertEqual(load_settings(path)['retention_days'], 45)
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                save_settings('not-an-ip', 'admin', 'example-password', 30, path)
            self.assertEqual(load_settings(path)['address'], '192.168.1.16')

    def test_read_deduplication_filter_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'reads.sqlite3'
            read = parse_metadata(SAMPLE, '192.168.1.16')
            self.assertEqual(read['plate'], 'AB12 CDE')
            self.assertTrue(save_read(read, path))
            self.assertFalse(save_read(read, path))
            result = query_reads(path, plate='12 c', start='2026-10-09', end='2026-10-10')
            self.assertEqual(result['total'], 1)
            self.assertIn(b'AB12 CDE', csv_report(result['rows']))
            self.assertEqual(query_reads(path, plate='OTHER')['total'], 0)


if __name__ == '__main__':
    unittest.main()
