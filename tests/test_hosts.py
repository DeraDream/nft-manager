import unittest

import web_panel as panel


class HostValidationTests(unittest.TestCase):
    def test_accepts_and_normalizes_ipv4(self):
        self.assertEqual(panel.normalize_host(" 192.168.1.10 "), "192.168.1.10")
        self.assertEqual(panel.normalize_host("http://192.168.1.10"), "192.168.1.10")

    def test_accepts_primary_and_multilevel_domains(self):
        self.assertEqual(panel.normalize_host("Example.COM"), "example.com")
        self.assertEqual(panel.normalize_host("https://node.hk.example.com/"), "node.hk.example.com")

    def test_rejects_urls_with_ports_paths_or_queries(self):
        for value in (
            "https://example.com:443",
            "http://example.com/path",
            "example.com?x=1",
            "user@example.com",
        ):
            with self.subTest(value=value):
                self.assertEqual(panel.normalize_host(value), "")

    def test_rejects_invalid_ipv4_and_domains(self):
        for value in (
            "",
            "localhost",
            "256.1.1.1",
            "01.2.3.4",
            "-bad.example.com",
            "bad-.example.com",
            "bad..example.com",
            "example",
            "example.123",
        ):
            with self.subTest(value=value):
                self.assertEqual(panel.normalize_host(value), "")

    def test_forward_payload_uses_canonical_host(self):
        rules = panel.expand_forward({
            "ip": "HTTP://Node.Example.COM",
            "ports": ["443"],
            "mode": "same",
        })
        self.assertEqual(rules[0]["ip"], "node.example.com")


if __name__ == "__main__":
    unittest.main()
