import sys
import socket
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "backend"))

from app.scan_utils import validate_target_url


class TestTargetValidation(unittest.TestCase):
    def test_blocked_ip_direct(self):
        allowed, blocked_ip, error = validate_target_url("http://172.16.93.136/login")
        self.assertFalse(allowed)
        self.assertEqual(blocked_ip, "172.16.93.136")
        self.assertIsNone(error)

    def test_blocked_ip_direct_with_port(self):
        allowed, blocked_ip, error = validate_target_url("https://172.16.93.211:8006/")
        self.assertFalse(allowed)
        self.assertEqual(blocked_ip, "172.16.93.211")
        self.assertIsNone(error)

    def test_blocked_via_dns(self):
        fake_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.16.93.211", 0)),
        ]
        with patch("app.scan_utils.socket.getaddrinfo", return_value=fake_info):
            allowed, blocked_ip, error = validate_target_url("http://internal.example")
        self.assertFalse(allowed)
        self.assertEqual(blocked_ip, "172.16.93.211")
        self.assertIsNone(error)

    def test_allow_other_internal_ip(self):
        allowed, blocked_ip, error = validate_target_url("http://172.16.93.50")
        self.assertTrue(allowed)
        self.assertIsNone(blocked_ip)
        self.assertIsNone(error)

    def test_ipv6_literal_is_safe(self):
        allowed, blocked_ip, error = validate_target_url("http://[::1]/")
        self.assertTrue(allowed)
        self.assertIsNone(blocked_ip)
        self.assertIsNone(error)

    def test_reject_unsupported_scheme(self):
        allowed, blocked_ip, error = validate_target_url("file:///etc/passwd")
        self.assertFalse(allowed)
        self.assertIsNone(blocked_ip)
        self.assertEqual(error, "unsupported_scheme")


if __name__ == "__main__":
    unittest.main()
