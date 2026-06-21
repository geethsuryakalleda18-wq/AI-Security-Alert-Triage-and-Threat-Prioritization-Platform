from __future__ import annotations

import unittest

from triage_platform.integrations import normalize_vendor_event


class IntegrationNormalizationTests(unittest.TestCase):
    def test_azure_ad_signin_becomes_authentication_event(self) -> None:
        event = normalize_vendor_event(
            "azure-ad",
            {
                "createdDateTime": "2026-06-21T10:00:00Z",
                "userPrincipalName": "analyst@example.com",
                "ipAddress": "203.0.113.10",
                "appDisplayName": "Azure Portal",
                "location": {"countryOrRegion": "US"},
                "status": {"errorCode": 0},
            },
        )

        self.assertEqual("azure-ad", event.source)
        self.assertEqual("authentication", event.event_type)
        self.assertEqual("success", event.outcome)
        self.assertEqual("analyst@example.com", event.username)

    def test_zeek_connection_becomes_network_event(self) -> None:
        event = normalize_vendor_event(
            "zeek",
            {
                "ts": "2026-06-21T10:00:00Z",
                "id.orig_h": "10.0.0.10",
                "id.resp_h": "198.51.100.25",
                "id.resp_p": 443,
                "orig_bytes": 65000000,
            },
        )

        self.assertEqual("zeek", event.source)
        self.assertEqual("network", event.event_type)
        self.assertEqual(443, event.destination_port)
        self.assertEqual(65000000, event.bytes_out)

    def test_suricata_alert_becomes_network_alert_event(self) -> None:
        event = normalize_vendor_event(
            "suricata",
            {
                "timestamp": "2026-06-21T10:00:00Z",
                "src_ip": "198.51.100.40",
                "dest_ip": "10.0.0.5",
                "dest_port": 445,
                "alert": {"signature": "ET SCAN SMB"},
            },
        )

        self.assertEqual("suricata", event.source)
        self.assertEqual("network", event.event_type)
        self.assertEqual("ET SCAN SMB", event.action)
        self.assertEqual(445, event.destination_port)


if __name__ == "__main__":
    unittest.main()
