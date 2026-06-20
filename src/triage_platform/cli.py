from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .demo import demo_events
from .models import SecurityEvent
from .triage import AlertStore, dump_jsonl, explain_alert, load_jsonl, triage_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Real-time security alert triage and prioritization platform")
    parser.add_argument("path", nargs="?", help="JSONL event file to analyze or watch")
    parser.add_argument("--json", action="store_true", help="Print alerts as JSON")
    parser.add_argument("--watch", action="store_true", help="Watch a JSONL file for appended events")
    parser.add_argument("--init-demo", action="store_true", help="Create a sample JSONL dataset")
    parser.add_argument("--append-demo", action="store_true", help="Append a safe simulated burst to a JSONL file")
    parser.add_argument("--serve", action="store_true", help="Start the local dashboard and API server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.serve:
        from .server import run_server

        run_server(args.host, args.port, Path(args.path) if args.path else None)
        return

    if args.init_demo or args.append_demo:
        if not args.path:
            raise SystemExit("Provide a JSONL path for demo events.")
        if args.init_demo:
            Path(args.path).write_text("", encoding="utf-8")
        dump_jsonl(args.path, demo_events())
        print(f"Wrote demo events to {args.path}")
        return

    if not args.path:
        raise SystemExit("Provide a JSONL event file, or use --serve/--init-demo.")

    if args.watch:
        watch_file(Path(args.path), as_json=args.json)
        return

    alerts = triage_events(load_jsonl(args.path))
    print_alerts(alerts, as_json=args.json)


def print_alerts(alerts, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps([alert.to_dict() for alert in alerts], indent=2))
        return
    if not alerts:
        print("No alerts generated.")
        return
    for alert in alerts:
        print(explain_alert(alert))
        print()


def watch_file(path: Path, as_json: bool = False) -> None:
    path.touch(exist_ok=True)
    store = AlertStore()
    seen = 0
    print(f"Watching {path} for new security events. Press Ctrl+C to stop.")
    while True:
        events = load_jsonl(path)
        new_events = events[seen:]
        seen = len(events)
        if new_events:
            alerts = store.upsert_many(triage_events(new_events))
            print_alerts(alerts, as_json=as_json)
        time.sleep(2)


if __name__ == "__main__":
    main()
