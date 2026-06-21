from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .demo import demo_events
from .feedback import AnalystFeedback, FeedbackStore
from .integrations import normalize_vendor_event
from .models import SecurityEvent
from .notifications import EmailNotifier, WebhookNotifier
from .persistence import SearchPersistence
from .streaming import KafkaConfig, RedisStreamConfig, consume_kafka_topic, consume_redis_stream
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
    parser.add_argument("--kafka-bootstrap", help="Kafka bootstrap servers, such as localhost:9092")
    parser.add_argument("--kafka-topic", default="security-events", help="Kafka topic for event intake")
    parser.add_argument("--kafka-group", default="triage-platform", help="Kafka consumer group ID")
    parser.add_argument(
        "--integration-source",
        choices=["wazuh", "zeek", "suricata", "cloudtrail", "azure-ad"],
        help="Normalize vendor JSONL events before triage",
    )
    parser.add_argument("--slack-webhook-url", help="Slack incoming webhook URL for alert notifications")
    parser.add_argument("--teams-webhook-url", help="Microsoft Teams incoming webhook URL for alert notifications")
    parser.add_argument("--smtp-host", help="SMTP host for email alert notifications")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP port for email alert notifications")
    parser.add_argument("--smtp-user", default="", help="SMTP username")
    parser.add_argument("--smtp-password", default="", help="SMTP password or app password")
    parser.add_argument("--email-from", help="Sender email address for alert notifications")
    parser.add_argument("--email-to", help="Comma-separated recipient email addresses")
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
        if args.kafka_bootstrap:
            consume_kafka(args)
            return
        raise SystemExit("Provide a JSONL event file, --redis-url, --kafka-bootstrap, or use --serve/--init-demo.")

    if args.watch:
        watch_file(
            Path(args.path),
            as_json=args.json,
            feedback_store=FeedbackStore(args.feedback_file),
            search=build_search(args),
            notifiers=build_notifiers(args),
            integration_source=args.integration_source,
        )
        return

    feedback_items = FeedbackStore(args.feedback_file).load()
    events = load_events(args.path, args.integration_source)
    alerts = triage_events(events, feedback_items=feedback_items)
    persist_alerts(alerts, build_search(args))
    notify_alerts(alerts, build_notifiers(args))
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
    notifiers=None,
    integration_source: str | None = None,
) -> None:
    path.touch(exist_ok=True)
    store = AlertStore()
    seen = 0
    print(f"Watching {path} for new security events. Press Ctrl+C to stop.")
    while True:
        events = load_events(path, integration_source)
        new_events = events[seen:]
        seen = len(events)
        if new_events:
            feedback_items = feedback_store.load() if feedback_store else []
            alerts = store.upsert_many(triage_events(new_events, feedback_items=feedback_items))
            persist_alerts(alerts, search)
            notify_alerts(alerts, notifiers or [])
            print_alerts(alerts, as_json=as_json)
        time.sleep(2)


def consume_redis(args) -> None:
    store = AlertStore()
    feedback_store = FeedbackStore(args.feedback_file)
    search = build_search(args)
    notifiers = build_notifiers(args)
    config = RedisStreamConfig(url=args.redis_url, stream=args.redis_stream)
    print(f"Consuming Redis stream {config.stream} from {config.url}. Press Ctrl+C to stop.")
    for events in consume_redis_stream(config):
        alerts = store.upsert_many(triage_events(events, feedback_items=feedback_store.load()))
        persist_alerts(alerts, search)
        notify_alerts(alerts, notifiers)
        print_alerts(alerts, as_json=args.json)


def consume_kafka(args) -> None:
    store = AlertStore()
    feedback_store = FeedbackStore(args.feedback_file)
    search = build_search(args)
    notifiers = build_notifiers(args)
    config = KafkaConfig(
        bootstrap_servers=args.kafka_bootstrap,
        topic=args.kafka_topic,
        group_id=args.kafka_group,
    )
    print(f"Consuming Kafka topic {config.topic} from {config.bootstrap_servers}. Press Ctrl+C to stop.")
    for events in consume_kafka_topic(config):
        alerts = store.upsert_many(triage_events(events, feedback_items=feedback_store.load()))
        persist_alerts(alerts, search)
        notify_alerts(alerts, notifiers)
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


def load_events(path: str | Path, integration_source: str | None = None) -> list[SecurityEvent]:
    if not integration_source:
        return load_jsonl(path)
    raw_events = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw_events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
    return [normalize_vendor_event(integration_source, row) for row in raw_events]


def build_notifiers(args):
    notifiers = []
    if args.slack_webhook_url:
        notifiers.append(WebhookNotifier(args.slack_webhook_url, "slack"))
    if args.teams_webhook_url:
        notifiers.append(WebhookNotifier(args.teams_webhook_url, "teams"))
    if args.smtp_host and args.email_from and args.email_to:
        notifiers.append(
            EmailNotifier(
                smtp_host=args.smtp_host,
                smtp_port=args.smtp_port,
                sender=args.email_from,
                recipients=[item.strip() for item in args.email_to.split(",") if item.strip()],
                username=args.smtp_user,
                password=args.smtp_password,
            )
        )
    return notifiers


def notify_alerts(alerts, notifiers) -> None:
    for notifier in notifiers:
        count = notifier.send_alerts(alerts)
        print(f"Sent {count} alerts with {notifier.__class__.__name__}")


if __name__ == "__main__":
    main()
