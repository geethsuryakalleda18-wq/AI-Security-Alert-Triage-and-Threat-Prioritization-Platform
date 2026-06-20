from __future__ import annotations

import json
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .models import SecurityEvent
from .triage import AlertStore, load_jsonl, triage_events

ROOT = Path(__file__).resolve().parents[2]
WEB_ROOT = ROOT / "web"


class TriageState:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []
        self.alert_store = AlertStore()

    def add_events(self, events: list[SecurityEvent]) -> None:
        self.events.extend(events)
        self.alert_store.upsert_many(triage_events(events))

    def load_file(self, path: Path) -> None:
        self.add_events(load_jsonl(path))

    def dashboard(self) -> dict:
        alerts = self.alert_store.all_alerts()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for alert in alerts:
            counts[alert.severity] = counts.get(alert.severity, 0) + 1
        return {
            "event_count": len(self.events),
            "alert_count": len(alerts),
            "severity_counts": counts,
            "alerts": [alert.to_dict() for alert in alerts],
        }


STATE = TriageState()


class TriageRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._send_json({"status": "ok"})
            return
        if parsed.path == "/api/alerts":
            self._send_json(STATE.dashboard())
            return
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/events":
            self.send_error(HTTPStatus.NOT_FOUND, "Unknown API route")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            rows = payload if isinstance(payload, list) else [payload]
            events = [SecurityEvent.from_dict(row) for row in rows]
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        STATE.add_events(events)
        self._send_json(STATE.dashboard(), status=HTTPStatus.CREATED)

    def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_server(host: str = "127.0.0.1", port: int = 8080, seed_path: Path | None = None) -> None:
    if seed_path:
        STATE.load_file(seed_path)
    server = ThreadingHTTPServer((host, port), TriageRequestHandler)
    print(f"Dashboard running at http://{host}:{port}")
    server.serve_forever()
