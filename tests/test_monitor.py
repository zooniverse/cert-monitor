#!/usr/bin/env python3
import os
import json
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from freezegun import freeze_time

from monitor import load_config, get_certificates, check_renewal, generate_report, send_email

class TestCertificateMonitor(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        # Fixed reference time (will be used with freezegun)
        self.fixed_now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        # Sample test certificate data (expires 10 days after fixed_now)
        self.sample_cert = {
            "metadata": {
                "name": "test-cert",
                "namespace": "default"
            },
            "spec": {
                "dnsNames": ["example.com", "www.example.com"]
            },
            "status": {
                "notAfter": (self.fixed_now + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        }

        # Test configuration
        self.test_config = {
            "smtp_server": "smtp.test.com",
            "smtp_port": 587,
            "smtp_user": "user@test.com",
            "smtp_password": "password",
            "email_from": "from@test.com",
            "email_to": ["to1@test.com", "to2@test.com"],
            "warning_days": 30
        }

        # Sample expiring certs list
        self.expiring_certs = [{
            "name": "test-cert",
            "namespace": "default",
            "dns_names": ["example.com"],
            "expiry_date": self.fixed_now + timedelta(days=10),
            "days_remaining": 10,
            "needs_renewal": True
        }]

    def test_load_config(self):
        with patch.dict(os.environ, {
            "SMTP_SERVER": "smtp.test.com",
            "SMTP_USER": "user@test.com",
            "SMTP_PASSWORD": "password",
            "EMAIL_FROM": "from@test.com",
            "EMAIL_TO": "to1@test.com,to2@test.com"
        }):
            config = load_config()
            self.assertEqual(config["smtp_server"], "smtp.test.com")
            self.assertEqual(config["smtp_port"], 587)
            self.assertEqual(config["warning_days"], 30)
            self.assertEqual(config["email_to"], ["to1@test.com", "to2@test.com"])

    @patch('subprocess.run')
    def test_get_certificates_success(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"items": [self.sample_cert]})
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        certs = get_certificates()
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["metadata"]["name"], "test-cert")

    @freeze_time("2025-01-01 12:00:00")
    def test_check_renewal(self):
        result = check_renewal(self.sample_cert, 30)
        self.assertTrue(result["needs_renewal"])
        self.assertEqual(result["days_remaining"], 10)
        self.assertEqual(result["name"], "test-cert")

        # Test certificate that doesn't need renewal (40 days left)
        future_cert = self.sample_cert.copy()
        future_date = self.fixed_now + timedelta(days=40)
        future_cert["status"]["notAfter"] = future_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        result = check_renewal(future_cert, 30)
        self.assertFalse(result["needs_renewal"])
        self.assertEqual(result["days_remaining"], 40)

    @freeze_time("2025-01-01 12:00:00")
    def test_generate_report(self):
        # Test with no expiring certificates
        report = generate_report([])
        self.assertIn("No certificates require renewal", report)

        # Test with expiring certificate
        cert_info = check_renewal(self.sample_cert, 30)
        report = generate_report([cert_info])

        self.assertIn("test-cert", report)
        self.assertIn("example.com", report)
        self.assertIn("10 days", report)
        self.assertIn("Certificate Renewal Alert", report)

    @patch('smtplib.SMTP')
    def test_send_email(self, mock_smtp):
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        test_report = "Test report content"
        send_email(self.test_config, self.expiring_certs, test_report)

        mock_smtp.assert_called_once_with("smtp.test.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user@test.com", "password")
        mock_server.send_message.assert_called_once()

if __name__ == '__main__':
    unittest.main()
