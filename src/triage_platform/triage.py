from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .detections import (
    detect_brute_force,
    detect_data_exfiltration,
    detect_impossible_travel,
    detect_port_scan,
    detect_suspicious_dns,
    detect_suspicious_process,
)
from .models import Alert, SecurityEvent

DETECTION_PIPELINE = (
    detect_brute_force,
    detect_impossible_travel,
    detect_suspicious_dns,
    detect_port_scan,
    detect_data_exfiltration,
    detect_suspicious_process,
)


class AlertStore:
    def __init__(self) -> None:
        self._alerts: dict[str, Alert] = {}

    def upsert_many(self, alerts: Iterable[Alert]) -> list[Alert]:
        changed: list[Alert] = []
        for alert in alerts:
            existing = self._alerts.get(alert.alert_id)
            if existing:
                existing.merge(alert)
                changed.append(existing)
            else:
                self._alerts[alert.alert_id] = alert
                changed.append(alert)
        return sorted(changed, key=lambda item: (-item.risk_score, item.last_seen))

    def all_alerts(self) -> list[Alert]:
        return sorted(self._alerts.values(), key=lambda item: (-item.risk_score, item.last_seen))

    def clear(self) -> None:
        self._alerts.clear()


def load_jsonl(path: str | Path) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(SecurityEvent.from_dict(json.loads(line)))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
    return events


def dump_jsonl(path: str | Path, rows: Iterable[dict]) -> None:
    with Path(path).open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def triage_events(events: list[SecurityEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for detector in DETECTION_PIPELINE:
        alerts.extend(detector(events))
    store = AlertStore()
    return store.upsert_many(alerts)


def explain_alert(alert: Alert) -> str:
    techniques = ", ".join(alert.mitre_techniques)
    return (
        f"{alert.severity.upper()} | {alert.title}\n"
        f"Risk: {alert.risk_score}/100 | Confidence: {alert.confidence} | MITRE: {techniques}\n"
        f"Summary: {alert.summary}\n"
        f"Business impact: {alert.business_impact}\n"
        f"Recommendation: {alert.recommendation}\n"
        f"Evidence: {'; '.join(alert.evidence)}"
    )
