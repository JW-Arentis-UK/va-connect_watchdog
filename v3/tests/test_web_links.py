import unittest

from va_watchdog.web_links import configured_web_links, normalize_web_link


class WebLinkTests(unittest.TestCase):
    def test_bare_ip_is_normalized_to_http(self):
        link = normalize_web_link("Front camera", "192.168.1.71", "camera")

        self.assertEqual(link, {
            "name": "Front camera",
            "url": "http://192.168.1.71",
            "group": "camera",
        })

    def test_https_url_and_path_are_preserved(self):
        link = normalize_web_link("RUT", "https://192.168.1.1/status", "rut")

        self.assertEqual(link["url"], "https://192.168.1.1/status")
        self.assertEqual(link["group"], "rut")

    def test_unsafe_scheme_and_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            normalize_web_link("Bad", "javascript:alert(1)", "other")
        with self.assertRaises(ValueError):
            normalize_web_link("Credential", "http://admin:password@192.168.1.71", "camera")

    def test_unknown_group_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_web_link("Camera", "192.168.1.71", "unsupported")

    def test_configured_links_skip_invalid_legacy_entries(self):
        links = configured_web_links({
            "web_links": [
                {"name": "Camera", "url": "192.168.1.71", "group": "camera"},
                {"name": "Unsafe", "url": "file:///etc/passwd", "group": "other"},
                "invalid",
            ]
        })

        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["name"], "Camera")


if __name__ == "__main__":
    unittest.main()
