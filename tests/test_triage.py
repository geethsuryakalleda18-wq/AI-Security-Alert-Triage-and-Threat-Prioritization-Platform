from __future__ import annotations

import unittest

from triage_platform.models import SecurityEvent
from triage_platform.triage import triage_events


class TriagePipelineTests(unittest.TestCase):
    def test_brute_force_alert_is_prioritized(self) -> None:
        events = [
            SecurityEvent.from_dict(
                {
                    "timestamp": f"2026-06-20T12:00:0{index}+00:00",
                    "source": "vpn",
                    "event_type": "authentication",
                    "action": "login",
                    "outcome": "failure",
                    "source_ip": "198.51.100.23",
                    "username": "admin",
                    "asset": "vpn-gateway",
                }
            )
            for index in range(6)
        ]

        alerts = triage_events(events)

        self.assertEqual(1, len(alerts))
        self.assertEqual("identity", alerts[0].category)
        self.assertGreaterEqual(alerts[0].risk_score, 90)
        self.assertIn("T1110 - Brute Force", alerts[0].mitre_techniques)

    def test_suspicious_dns_maps_to_network_alert(self) -> None:
        alerts = triage_events(
            [
                SecurityEvent.from_dict(
                    {
                        "timestamp": "2026-06-20T12:09:00+00:00",
                        "source": "dns",
                        "event_type": "dns",
                        "action": "query",
                        "outcome": "success",
                        "source_ip": "10.10.4.22",
                        "domain": "secure-login-update.top",
                        "asset": "laptop-044",
                    }
                )
            ]
        )

        self.assertEqual(1, len(alerts))
        self.assertEqual("network", alerts[0].category)
        self.assertIn("T1566 - Phishing", alerts[0].mitre_techniques)

    def test_port_scan_requires_multiple_ports(self) -> None:
        events = [
            SecurityEvent.from_dict(
                {
                    "timestamp": f"2026-06-20T12:12:{port % 60:02d}+00:00",
                    "source": "firewall",
                    "event_type": "network",
                    "action": "connection",
                    "outcome": "denied",
                    "source_ip": "198.51.100.45",
                    "destination_ip": "10.10.1.10",
                    "destination_port": port,
                    "asset": "payment-api",
                }
            )
            for port in [21, 22, 23, 80, 135, 139, 443, 445, 3389]
        ]

        alerts = triage_events(events)

        self.assertEqual(1, len(alerts))
        self.assertEqual("network", alerts[0].category)
        self.assertIn("T1046 - Network Service Discovery", alerts[0].mitre_techniques)


if __name__ == "__main__":
    unittest.main()
