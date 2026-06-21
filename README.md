# Real-Time AI Security Alert Triage and Threat Prioritization Platform

This project turns raw security events into prioritized SOC-style alerts. It is built for a real company problem: security teams receive too many logs and alerts, and analysts need fast context on which threats matter first, why they matter, and what to do next.

The platform ingests JSONL events, detects suspicious activity, deduplicates related alerts, assigns risk scores, maps activity to MITRE ATT&CK, and presents the result in a lightweight dashboard.

## Features

- Real-time event intake through a local API
- Browser dashboard for alert prioritization
- Brute-force login detection
- Impossible-travel style login detection
- Suspicious DNS and phishing-domain detection
- Port scan and network reconnaissance detection
- Large outbound transfer detection for possible data exfiltration
- Suspicious PowerShell/script execution detection
- MITRE ATT&CK mapping for each alert
- Business impact and recommended response actions
- JSON output for reports or SIEM-style integrations
- Optional Redis Stream intake for higher-volume event flow
- Optional OpenSearch/Elasticsearch persistence for alert search and dashboards
- Analyst feedback loop that can reduce or raise future alert severity
- Safe demo dataset and unit tests

## Why This Solves a Real Company Problem

Modern SOC teams receive high alert volume from VPNs, firewalls, cloud identity systems, DNS logs, EDR tools, and servers. Raw logs alone do not tell an analyst what to handle first. This project demonstrates a practical triage workflow:

1. Normalize security events.
2. Detect suspicious behavior across identity, endpoint, DNS, and network sources.
3. Score alerts by severity, confidence, asset importance, and behavior.
4. Explain the likely business impact.
5. Recommend response steps for a SOC analyst or IT security team.

## Project Structure

```text
real-time-ai-security-alert-triage/
  data/
    sample_events.jsonl
  src/
    triage_platform/
      cli.py
      demo.py
      detections.py
      enrichment.py
      feedback.py
      models.py
      persistence.py
      server.py
      streaming.py
      triage.py
  tests/
    test_triage.py
  web/
    app.js
    index.html
    styles.css
  README.md
  requirements.txt
```

## Quick Start

Run a one-time analysis:

```bash
PYTHONPATH=src python3 -m triage_platform.cli data/sample_events.jsonl
```

Print alerts as JSON:

```bash
PYTHONPATH=src python3 -m triage_platform.cli data/sample_events.jsonl --json
```

Start the local dashboard:

```bash
PYTHONPATH=src python3 -m triage_platform.cli data/sample_events.jsonl --serve --port 8080
```

Open:

```text
http://127.0.0.1:8080
```

## Real-Time Demo

Create a demo event file:

```bash
PYTHONPATH=src python3 -m triage_platform.cli data/demo_watch_events.jsonl --init-demo
```

Watch for new events:

```bash
PYTHONPATH=src python3 -m triage_platform.cli data/demo_watch_events.jsonl --watch
```

Append a safe simulated burst from another terminal:

```bash
PYTHONPATH=src python3 -m triage_platform.cli data/demo_watch_events.jsonl --append-demo
```

## Analyst Feedback

First run the sample alerts and copy an `alert_id` from JSON output:

```bash
PYTHONPATH=src python3 -m triage_platform.cli data/sample_events.jsonl --json
```

Store analyst feedback:

```bash
PYTHONPATH=src python3 -m triage_platform.cli --add-feedback ALERT_ID --verdict false_positive --analyst soc1 --note "Approved test activity"
```

Supported verdicts:

```text
true_positive
false_positive
benign
escalated
```

Future triage runs use `data/analyst_feedback.jsonl` to adjust alert risk scores. The dashboard also includes feedback buttons on each alert card.

## Redis Streaming

For larger event volume, the platform can consume events from a Redis Stream. Install Redis client support first:

```bash
python3 -m pip install redis
```

Then consume events:

```bash
PYTHONPATH=src python3 -m triage_platform.cli --redis-url redis://localhost:6379/0 --redis-stream security-events
```

Each Redis stream message should include an `event` or `payload` field containing one JSON security event.

## OpenSearch or Elasticsearch Persistence

Persist alerts to a search backend:

```bash
PYTHONPATH=src python3 -m triage_platform.cli data/sample_events.jsonl \
  --opensearch-url http://localhost:9200 \
  --opensearch-index security-alerts
```

This uses the OpenSearch/Elasticsearch-compatible document API:

```text
PUT /security-alerts/_doc/{alert_id}
```

## API

Health check:

```bash
curl http://127.0.0.1:8080/api/health
```

Get current alerts:

```bash
curl http://127.0.0.1:8080/api/alerts
```

Send one event:

```bash
curl -X POST http://127.0.0.1:8080/api/events \
  -H "Content-Type: application/json" \
  -d '{"source":"vpn","event_type":"authentication","action":"login","outcome":"failure","source_ip":"198.51.100.23","username":"admin","asset":"vpn-gateway"}'
```

## Example Alert

```text
CRITICAL | Repeated failed logins for admin
Risk: 100/100 | Confidence: high | MITRE: T1110 - Brute Force, T1078 - Valid Accounts
Summary: 6 failed authentication attempts were observed from 198.51.100.23 against admin.
Business impact: Possible credential attack against remote access, cloud, or workstation accounts.
Recommendation: Confirm MFA status, review successful logins after the failures, block or rate-limit the source IP, and reset the account password if compromise is suspected.
```

## Run Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Skills Demonstrated

- Cybersecurity monitoring and SOC alert triage
- Python automation and API development
- Network traffic and authentication log analysis
- Threat detection engineering
- MITRE ATT&CK mapping
- Dashboard-based incident prioritization
- Incident response documentation

## Future Improvements

- Add Kafka consumer support as an alternative to Redis Streams
- Add Slack, Teams, or email notification routing
- Add integrations for Wazuh, Zeek, Suricata, AWS CloudTrail, and Azure AD logs
