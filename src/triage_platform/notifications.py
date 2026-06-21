from __future__ import annotations

import json
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from urllib import error, request

from .models import Alert


@dataclass(frozen=True)
class WebhookNotifier:
    url: str
    kind: str

    def send_alerts(self, alerts: list[Alert]) -> int:
        sent = 0
        for alert in alerts:
            self._send(alert)
            sent += 1
        return sent

    def _send(self, alert: Alert) -> None:
        body = json.dumps(self._payload(alert)).encode("utf-8")
        req = request.Request(
            self.url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                if response.status >= 400:
                    raise RuntimeError(f"{self.kind} webhook returned HTTP {response.status}")
        except error.URLError as exc:
            raise RuntimeError(f"Could not send {self.kind} notification: {exc}") from exc

    def _payload(self, alert: Alert) -> dict:
        text = (
            f"{alert.severity.upper()} | {alert.title}\n"
            f"Risk: {alert.risk_score}/100\n"
            f"Summary: {alert.summary}\n"
            f"Recommendation: {alert.recommendation}"
        )
        if self.kind == "teams":
            return {"text": text}
        return {"text": text}


@dataclass(frozen=True)
class EmailNotifier:
    smtp_host: str
    smtp_port: int
    sender: str
    recipients: list[str]
    username: str = ""
    password: str = ""
    use_tls: bool = True

    def send_alerts(self, alerts: list[Alert]) -> int:
        if not alerts:
            return 0
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)
        message["Subject"] = f"{len(alerts)} prioritized security alerts"
        message.set_content("\n\n".join(_email_alert_body(alert) for alert in alerts))

        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as smtp:
            if self.use_tls:
                smtp.starttls()
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(message)
        return len(alerts)


def _email_alert_body(alert: Alert) -> str:
    return (
        f"{alert.severity.upper()} | {alert.title}\n"
        f"Risk: {alert.risk_score}/100\n"
        f"MITRE: {', '.join(alert.mitre_techniques)}\n"
        f"Summary: {alert.summary}\n"
        f"Business impact: {alert.business_impact}\n"
        f"Recommendation: {alert.recommendation}\n"
        f"Evidence: {'; '.join(alert.evidence)}"
    )
