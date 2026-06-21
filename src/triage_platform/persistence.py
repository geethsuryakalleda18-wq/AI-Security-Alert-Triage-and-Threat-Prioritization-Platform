from __future__ import annotations

import json
from dataclasses import dataclass
from urllib import error, request

from .models import Alert


@dataclass(frozen=True)
class SearchPersistence:
    base_url: str
    index: str = "security-alerts"

    def index_alerts(self, alerts: list[Alert]) -> int:
        indexed = 0
        for alert in alerts:
            self.index_alert(alert)
            indexed += 1
        return indexed

    def index_alert(self, alert: Alert) -> None:
        url = f"{self.base_url.rstrip('/')}/{self.index}/_doc/{alert.alert_id}"
        payload = json.dumps(alert.to_dict()).encode("utf-8")
        req = request.Request(
            url,
            data=payload,
            method="PUT",
            headers={"Content-Type": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                if response.status >= 400:
                    raise RuntimeError(f"Search backend returned HTTP {response.status}")
        except error.URLError as exc:
            raise RuntimeError(f"Could not persist alert {alert.alert_id}: {exc}") from exc
