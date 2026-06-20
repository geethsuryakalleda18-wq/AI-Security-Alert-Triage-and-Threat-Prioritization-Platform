from __future__ import annotations

from datetime import datetime, timezone


def demo_events() -> list[dict]:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    rows: list[dict] = []
    for _ in range(7):
        rows.append(
            {
                "timestamp": now,
                "source": "vpn",
                "event_type": "authentication",
                "action": "login",
                "outcome": "failure",
                "source_ip": "198.51.100.23",
                "username": "admin",
                "asset": "vpn-gateway",
                "geo": "Unknown",
            }
        )
    rows.extend(
        [
            {
                "timestamp": now,
                "source": "azure-ad",
                "event_type": "authentication",
                "action": "login",
                "outcome": "success",
                "source_ip": "203.0.113.77",
                "username": "finance.user",
                "asset": "cloud-admin",
                "geo": "US",
            },
            {
                "timestamp": now,
                "source": "azure-ad",
                "event_type": "authentication",
                "action": "login",
                "outcome": "success",
                "source_ip": "198.51.100.88",
                "username": "finance.user",
                "asset": "cloud-admin",
                "geo": "DE",
            },
            {
                "timestamp": now,
                "source": "dns",
                "event_type": "dns",
                "action": "query",
                "outcome": "success",
                "source_ip": "10.10.4.22",
                "domain": "secure-login-update.top",
                "asset": "laptop-044",
            },
            {
                "timestamp": now,
                "source": "edr",
                "event_type": "endpoint",
                "action": "process_start",
                "outcome": "success",
                "source_ip": "10.10.4.22",
                "username": "jsmith",
                "asset": "laptop-044",
                "process": "powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQAghttps://example.invalid/a",
            },
            {
                "timestamp": now,
                "source": "firewall",
                "event_type": "network",
                "action": "connection",
                "outcome": "allowed",
                "source_ip": "10.10.8.50",
                "destination_ip": "8.8.8.8",
                "destination_port": 443,
                "bytes_out": 85000000,
                "asset": "file-server-02",
            },
        ]
    )
    for port in [21, 22, 23, 80, 135, 139, 443, 445, 3389]:
        rows.append(
            {
                "timestamp": now,
                "source": "firewall",
                "event_type": "network",
                "action": "connection",
                "outcome": "denied",
                "source_ip": "198.51.100.45",
                "destination_ip": "10.10.1.10",
                "destination_port": port,
                "bytes_out": 0,
                "asset": "payment-api",
            }
        )
    return rows
