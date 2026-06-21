from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .demo import demo_events
from .feedback import AnalystFeedback, FeedbackStore
from .models import SecurityEvent
from .persistence import SearchPersistence
from .streaming import RedisStreamConfig, consume_redis_stream
from .triage import AlertStore, dump_jsonl, explain_alert, load_jsonl, triage_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Real-time security alert triage and prioritization platform")
    parser.add_argument("path", nargs="?", help="JSONL event file to analyze or watch")
    parser.add_argument("--json", action="store_true", help="Print alerts as JSON")
    parser.add_argument("--watch", action="store_true", help="Watch a JSONL file for appended events")
    parser.add_argument("--init-demo", action="store_true", help="Create a sample JSONL dataset")
    parser.add_argument("--append-demo", action="store_true", help="Append a safe simulated burst to a JSONL file")
    parser.add_argument("--serve", action="store_true", help="Start the local dashboard and API server")
    parser.add_argument("--feedback-file", default="data/analyst_feedback.jsonl", help="JSONL file with analyst feedback")
    parser.add_argument("--add-feedback", help="Alert ID to label with analyst feedback")
    parser.add_argument(
        "--verdict",
        choices=["true_positive", "false_positive", "benign", "escalated"],
        help="Feedback verdict for --add-feedback",
    )
    parser.add_argument("--analyst", default="analyst", help="Analyst name to store with feedback")
    parser.add_argument("--note", default="", help="Optional analyst feedback note")
    parser.add_argument("--opensearch-url", help="OpenSearch or Elasticsearch base URL, such as http://localhost:9200")
    parser.add_argument("--opensearch-index", default="security-alerts", help="Search index for persisted alerts")
    parser.add_argument("--redis-url", help="Redis URL for streaming intake, such as redis://localhost:6379/0")
    parser.add_argument("--redis-stream", default="security-events", help="Redis stream name for event intake")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.serve:
        from .server import run_server

        run_server(
            args.host,
            args.port,
            Path(args.path) if args.path else None,
            Path(args.feedback_file),
        )
        return

    if args.add_feedback:
        if not args.verdict:
            raise SystemExit("--verdict is required with --add-feedback.")
        feedback = AnalystFeedback.from_dict(
            {
                "alert_id": args.add_feedback,
                "verdict": args.verdict,
                "analyst": args.analyst,
                "note": args.note,
            }
        )
        FeedbackStore(args.feedback_file).append(feedback)
        print(f"Stored {feedback.verdict} feedback for alert {feedback.alert_id}")
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
        if args.redis_url:
            consume_redis(args)
            return
        raise SystemExit("Provide a JSONL event file, --redis-url, or use --serve/--init-demo.")

    if args.watch:
        watch_file(
            Path(args.path),
            as_json=args.json,
            feedback_store=FeedbackStore(args.feedback_file),
            search=build_search(args),
        )
        return

    feedback_items = FeedbackStore(args.feedback_file).load()
    alerts = triage_events(load_jsonl(args.path), feedback_items=feedback_items)
    persist_alerts(alerts, build_search(args))
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


def watch_file(
    path: Path,
    as_json: bool = False,
    feedback_store: FeedbackStore | None = None,
    search: SearchPersistence | None = None,
) -> None:
    path.touch(exist_ok=True)
    store = AlertStore()
    seen = 0
    print(f"Watching {path} for new security events. Press Ctrl+C to stop.")
    while True:
        events = load_jsonl(path)
        new_events = events[seen:]
        seen = len(events)
        if new_events:
            feedback_items = feedback_store.load() if feedback_store else []
            alerts = store.upsert_many(triage_events(new_events, feedback_items=feedback_items))
            persist_alerts(alerts, search)
            print_alerts(alerts, as_json=as_json)
        time.sleep(2)


def consume_redis(args) -> None:
    store = AlertStore()
    feedback_store = FeedbackStore(args.feedback_file)
    search = build_search(args)
    config = RedisStreamConfig(url=args.redis_url, stream=args.redis_stream)
    print(f"Consuming Redis stream {config.stream} from {config.url}. Press Ctrl+C to stop.")
    for events in consume_redis_stream(config):
        alerts = store.upsert_many(triage_events(events, feedback_items=feedback_store.load()))
        persist_alerts(alerts, search)
        print_alerts(alerts, as_json=args.json)


def build_search(args) -> SearchPersistence | None:
    if not args.opensearch_url:
        return None
    return SearchPersistence(args.opensearch_url, args.opensearch_index)


def persist_alerts(alerts, search: SearchPersistence | None) -> None:
    if not search or not alerts:
        return
    count = search.index_alerts(alerts)
    print(f"Persisted {count} alerts to {search.base_url.rstrip('/')}/{search.index}")


if __name__ == "__main__":
    main()
