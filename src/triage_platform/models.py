from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    source: str
    event_type: str
    action: str
    outcome: str = "unknown"
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: int | None = None
    username: str = ""
    domain: str = ""
    process: str = ""
    command_line: str = ""
    bytes_out: int = 0
    geo: str = ""
    asset: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "SecurityEvent":
        destination_port = row.get("destination_port")
        if destination_port in ("", None):
            parsed_port = None
        else:
            try:
                parsed_port = int(destination_port)
            except (TypeError, ValueError):
                parsed_port = None

        bytes_out = row.get("bytes_out", 0)
        try:
            parsed_bytes_out = int(bytes_out or 0)
        except (TypeError, ValueError):
            parsed_bytes_out = 0

        return cls(
            timestamp=str(row.get("timestamp") or utc_now()),
            source=str(row.get("source") or "unknown"),
            event_type=str(row.get("event_type") or "unknown"),
            action=str(row.get("action") or "unknown"),
            outcome=str(row.get("outcome") or "unknown"),
            source_ip=str(row.get("source_ip") or ""),
            destination_ip=str(row.get("destination_ip") or ""),
            destination_port=parsed_port,
            username=str(row.get("username") or ""),
            domain=str(row.get("domain") or ""),
            process=str(row.get("process") or ""),
            command_line=str(row.get("command_line") or ""),
            bytes_out=parsed_bytes_out,
            geo=str(row.get("geo") or ""),
            asset=str(row.get("asset") or ""),
            raw=row,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    title: str
    category: str
    severity: str
    risk_score: int
    confidence: str
    summary: str
    business_impact: str
    recommendation: str
    mitre_techniques: list[str]
    entities: dict[str, list[str]]
    evidence: list[str]
    first_seen: str
    last_seen: str
    count: int = 1
    status: str = "open"
    alert_id: str = ""

    def __post_init__(self) -> None:
        if not self.alert_id:
            fingerprint = "|".join(
                [
                    self.category,
                    self.title,
                    ",".join(sorted(self.entities.get("source_ips", []))),
                    ",".join(sorted(self.entities.get("users", []))),
                    ",".join(sorted(self.entities.get("assets", []))),
                ]
            )
            self.alert_id = sha256(fingerprint.encode("utf-8")).hexdigest()[:12]

    def merge(self, other: "Alert") -> None:
        self.count += other.count
        self.last_seen = max(self.last_seen, other.last_seen)
        self.risk_score = max(self.risk_score, other.risk_score)
        self.severity = severity_from_score(self.risk_score)
        self.evidence = sorted(set(self.evidence + other.evidence))
        for key, values in other.entities.items():
            current = set(self.entities.setdefault(key, []))
            current.update(values)
            self.entities[key] = sorted(current)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"
