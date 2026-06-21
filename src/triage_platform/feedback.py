from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .models import Alert, severity_from_score, utc_now

VALID_VERDICTS = {"true_positive", "false_positive", "benign", "escalated"}
RISK_ADJUSTMENTS = {
    "true_positive": 8,
    "escalated": 12,
    "false_positive": -25,
    "benign": -35,
}


@dataclass(frozen=True)
class AnalystFeedback:
    alert_id: str
    verdict: str
    analyst: str = "analyst"
    note: str = ""
    timestamp: str = ""

    @classmethod
    def from_dict(cls, row: dict) -> "AnalystFeedback":
        verdict = str(row.get("verdict") or "").strip().lower()
        if verdict not in VALID_VERDICTS:
            raise ValueError(f"Unsupported feedback verdict: {verdict}")
        return cls(
            alert_id=str(row.get("alert_id") or ""),
            verdict=verdict,
            analyst=str(row.get("analyst") or "analyst"),
            note=str(row.get("note") or ""),
            timestamp=str(row.get("timestamp") or utc_now()),
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class FeedbackStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> list[AnalystFeedback]:
        if not self.path.exists():
            return []
        rows: list[AnalystFeedback] = []
        with self.path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(AnalystFeedback.from_dict(json.loads(line)))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid feedback JSON on line {line_number}: {exc}") from exc
        return rows

    def append(self, feedback: AnalystFeedback) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(feedback.to_dict(), sort_keys=True) + "\n")


def apply_feedback(alerts: Iterable[Alert], feedback_items: Iterable[AnalystFeedback]) -> list[Alert]:
    feedback_by_alert: dict[str, list[AnalystFeedback]] = {}
    for item in feedback_items:
        feedback_by_alert.setdefault(item.alert_id, []).append(item)

    adjusted: list[Alert] = []
    for alert in alerts:
        alert_feedback = feedback_by_alert.get(alert.alert_id, [])
        if alert_feedback:
            adjustment = sum(RISK_ADJUSTMENTS[item.verdict] for item in alert_feedback)
            alert.risk_score = max(0, min(100, alert.risk_score + adjustment))
            alert.severity = severity_from_score(alert.risk_score)
            alert.entities["feedback_verdicts"] = [item.verdict for item in alert_feedback]
        adjusted.append(alert)
    return sorted(adjusted, key=lambda item: (-item.risk_score, item.last_seen))
