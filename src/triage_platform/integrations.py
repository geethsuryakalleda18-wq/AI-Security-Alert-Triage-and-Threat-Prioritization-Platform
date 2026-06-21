from __future__ import annotations

from typing import Any

from .models import SecurityEvent, utc_now


def normalize_vendor_event(source: str, row: dict[str, Any]) -> SecurityEvent:
    source = source.lower().strip()
    if source == "wazuh":
        return normalize_wazuh(row)
    if source == "zeek":
        return normalize_zeek(row)
    if source == "suricata":
        return normalize_suricata(row)
    if source == "cloudtrail":
        return normalize_cloudtrail(row)
    if source in {"azure-ad", "azure_ad", "azure"}:
        return normalize_azure_ad(row)
    raise ValueError(f"Unsupported integration source: {source}")


def normalize_wazuh(row: dict[str, Any]) -> SecurityEvent:
    rule = row.get("rule", {})
    agent = row.get("agent", {})
    data = row.get("data", {})
    return SecurityEvent.from_dict(
        {
            "timestamp": row.get("timestamp") or utc_now(),
            "source": "wazuh",
            "event_type": "endpoint",
            "action": str(rule.get("description") or row.get("decoder", {}).get("name") or "alert"),
            "outcome": "alert",
            "source_ip": data.get("srcip") or data.get("src_ip") or "",
            "username": data.get("srcuser") or data.get("user") or "",
            "asset": agent.get("name") or agent.get("id") or "",
            "process": data.get("process") or data.get("win", {}).get("eventdata", {}).get("image") or "",
            "command_line": data.get("command") or data.get("win", {}).get("eventdata", {}).get("commandLine") or "",
            "raw": row,
        }
    )


def normalize_zeek(row: dict[str, Any]) -> SecurityEvent:
    return SecurityEvent.from_dict(
        {
            "timestamp": row.get("ts") or row.get("timestamp") or utc_now(),
            "source": "zeek",
            "event_type": "network",
            "action": "connection",
            "outcome": "allowed",
            "source_ip": row.get("id.orig_h") or row.get("src_ip") or "",
            "destination_ip": row.get("id.resp_h") or row.get("dest_ip") or "",
            "destination_port": row.get("id.resp_p") or row.get("dest_port") or "",
            "bytes_out": row.get("orig_bytes") or 0,
            "raw": row,
        }
    )


def normalize_suricata(row: dict[str, Any]) -> SecurityEvent:
    alert = row.get("alert", {})
    return SecurityEvent.from_dict(
        {
            "timestamp": row.get("timestamp") or utc_now(),
            "source": "suricata",
            "event_type": "network",
            "action": alert.get("signature") or row.get("event_type") or "alert",
            "outcome": "alert",
            "source_ip": row.get("src_ip") or "",
            "destination_ip": row.get("dest_ip") or "",
            "destination_port": row.get("dest_port") or "",
            "raw": row,
        }
    )


def normalize_cloudtrail(row: dict[str, Any]) -> SecurityEvent:
    user = row.get("userIdentity", {})
    source_ip = row.get("sourceIPAddress") or ""
    return SecurityEvent.from_dict(
        {
            "timestamp": row.get("eventTime") or utc_now(),
            "source": "aws-cloudtrail",
            "event_type": "cloud",
            "action": row.get("eventName") or "api_call",
            "outcome": "failure" if row.get("errorCode") else "success",
            "source_ip": source_ip,
            "username": user.get("userName") or user.get("principalId") or "",
            "asset": row.get("recipientAccountId") or "",
            "raw": row,
        }
    )


def normalize_azure_ad(row: dict[str, Any]) -> SecurityEvent:
    status = row.get("status", {})
    user = row.get("userPrincipalName") or row.get("userDisplayName") or ""
    location = row.get("location") or {}
    failure = bool(status.get("errorCode")) if isinstance(status, dict) else False
    return SecurityEvent.from_dict(
        {
            "timestamp": row.get("createdDateTime") or utc_now(),
            "source": "azure-ad",
            "event_type": "authentication",
            "action": "login",
            "outcome": "failure" if failure else "success",
            "source_ip": row.get("ipAddress") or "",
            "username": user,
            "asset": row.get("appDisplayName") or "azure-ad",
            "geo": location.get("countryOrRegion", "") if isinstance(location, dict) else "",
            "raw": row,
        }
    )
