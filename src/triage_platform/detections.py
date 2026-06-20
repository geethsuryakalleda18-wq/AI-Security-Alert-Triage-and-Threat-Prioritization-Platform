from __future__ import annotations

from collections import Counter, defaultdict

from .enrichment import HIGH_RISK_PORTS, asset_weight, command_line_risk, domain_risk, is_public_ip
from .models import Alert, SecurityEvent, severity_from_score

FAILED_LOGIN_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 8
EXFIL_BYTES_THRESHOLD = 50_000_000


def detect_brute_force(events: list[SecurityEvent]) -> list[Alert]:
    grouped: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "authentication" and event.action == "login" and event.outcome == "failure":
            grouped[(event.source_ip, event.username)].append(event)

    alerts: list[Alert] = []
    for (source_ip, username), matches in grouped.items():
        if len(matches) < FAILED_LOGIN_THRESHOLD:
            continue
        asset_bonus = max(asset_weight(event.asset) for event in matches)
        risk = min(100, 70 + len(matches) * 3 + asset_bonus + (10 if is_public_ip(source_ip) else 0))
        first_seen = min(event.timestamp for event in matches)
        last_seen = max(event.timestamp for event in matches)
        assets = sorted({event.asset for event in matches if event.asset})
        alerts.append(
            Alert(
                title=f"Repeated failed logins for {username or 'unknown user'}",
                category="identity",
                severity=severity_from_score(risk),
                risk_score=risk,
                confidence="high",
                summary=(
                    f"{len(matches)} failed authentication attempts were observed from {source_ip} "
                    f"against {username or 'an unknown account'}."
                ),
                business_impact="Possible credential attack against remote access, cloud, or workstation accounts.",
                recommendation="Confirm MFA status, review successful logins after the failures, block or rate-limit the source IP, and reset the account password if compromise is suspected.",
                mitre_techniques=["T1110 - Brute Force", "T1078 - Valid Accounts"],
                entities={"source_ips": [source_ip], "users": [username], "assets": assets},
                evidence=[f"{len(matches)} failed logins from {source_ip}"],
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )
    return alerts


def detect_impossible_travel(events: list[SecurityEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    successful_logins: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "authentication" and event.action == "login" and event.outcome == "success":
            successful_logins[event.username].append(event)

    for username, matches in successful_logins.items():
        geos = {event.geo for event in matches if event.geo}
        if len(geos) < 2:
            continue
        source_ips = sorted({event.source_ip for event in matches if event.source_ip})
        risk = 80 + min(15, len(geos) * 5)
        alerts.append(
            Alert(
                title=f"Impossible-travel style login pattern for {username}",
                category="identity",
                severity=severity_from_score(risk),
                risk_score=risk,
                confidence="medium",
                summary=f"Successful logins for {username} appeared from multiple geographies: {', '.join(sorted(geos))}.",
                business_impact="Could indicate stolen credentials or session hijacking.",
                recommendation="Validate with the user, review device fingerprints, revoke suspicious sessions, and require step-up authentication.",
                mitre_techniques=["T1078 - Valid Accounts"],
                entities={"source_ips": source_ips, "users": [username], "geos": sorted(geos)},
                evidence=[f"Successful login geographies: {', '.join(sorted(geos))}"],
                first_seen=min(event.timestamp for event in matches),
                last_seen=max(event.timestamp for event in matches),
            )
        )
    return alerts


def detect_suspicious_dns(events: list[SecurityEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.event_type != "dns" or not event.domain:
            continue
        risk_bonus = domain_risk(event.domain)
        if risk_bonus < 25:
            continue
        risk = min(100, 45 + risk_bonus + asset_weight(event.asset))
        alerts.append(
            Alert(
                title=f"Suspicious DNS lookup for {event.domain}",
                category="network",
                severity=severity_from_score(risk),
                risk_score=risk,
                confidence="medium",
                summary=f"{event.asset or event.source_ip} queried a domain with phishing or malware-like characteristics.",
                business_impact="The endpoint may have reached phishing infrastructure or malware command-and-control.",
                recommendation="Check endpoint process history, block the domain if unapproved, and search DNS logs for additional affected hosts.",
                mitre_techniques=["T1071 - Application Layer Protocol", "T1566 - Phishing"],
                entities={"source_ips": [event.source_ip], "domains": [event.domain], "assets": [event.asset] if event.asset else []},
                evidence=[f"DNS query: {event.domain} from {event.source_ip}"],
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
        )
    return alerts


def detect_port_scan(events: list[SecurityEvent]) -> list[Alert]:
    ports_by_source: dict[str, set[int]] = defaultdict(set)
    timestamps: dict[str, list[str]] = defaultdict(list)
    destinations: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event.event_type != "network" or event.destination_port is None:
            continue
        ports_by_source[event.source_ip].add(event.destination_port)
        timestamps[event.source_ip].append(event.timestamp)
        if event.destination_ip:
            destinations[event.source_ip].add(event.destination_ip)

    alerts: list[Alert] = []
    for source_ip, ports in ports_by_source.items():
        if len(ports) < PORT_SCAN_THRESHOLD:
            continue
        high_risk_hits = len(ports.intersection(HIGH_RISK_PORTS))
        risk = min(100, 60 + len(ports) + high_risk_hits * 7 + (10 if is_public_ip(source_ip) else 0))
        alerts.append(
            Alert(
                title=f"Possible port scan from {source_ip}",
                category="network",
                severity=severity_from_score(risk),
                risk_score=risk,
                confidence="medium",
                summary=f"{source_ip} touched {len(ports)} unique destination ports.",
                business_impact="May indicate reconnaissance before exploitation or misconfigured scanning activity.",
                recommendation="Confirm whether this is an approved scanner, review firewall blocks, and isolate the source if unauthorized.",
                mitre_techniques=["T1046 - Network Service Discovery"],
                entities={"source_ips": [source_ip], "destination_ips": sorted(destinations[source_ip])},
                evidence=[f"Unique destination ports: {', '.join(str(port) for port in sorted(ports))}"],
                first_seen=min(timestamps[source_ip]),
                last_seen=max(timestamps[source_ip]),
            )
        )
    return alerts


def detect_data_exfiltration(events: list[SecurityEvent]) -> list[Alert]:
    totals: Counter[tuple[str, str]] = Counter()
    timestamps: dict[tuple[str, str], list[str]] = defaultdict(list)
    assets: dict[tuple[str, str], set[str]] = defaultdict(set)
    for event in events:
        if event.event_type != "network" or event.bytes_out <= 0:
            continue
        key = (event.source_ip, event.destination_ip)
        totals[key] += event.bytes_out
        timestamps[key].append(event.timestamp)
        if event.asset:
            assets[key].add(event.asset)

    alerts: list[Alert] = []
    for (source_ip, destination_ip), total_bytes in totals.items():
        if total_bytes < EXFIL_BYTES_THRESHOLD or not is_public_ip(destination_ip):
            continue
        risk = min(100, 75 + total_bytes // 50_000_000)
        alerts.append(
            Alert(
                title=f"Large outbound transfer from {source_ip}",
                category="data-loss",
                severity=severity_from_score(risk),
                risk_score=int(risk),
                confidence="medium",
                summary=f"{source_ip} sent {round(total_bytes / 1_000_000, 2)} MB to external host {destination_ip}.",
                business_impact="Possible data exfiltration, unauthorized backup, or compromised endpoint activity.",
                recommendation="Validate the destination, inspect proxy and endpoint telemetry, and temporarily block traffic if no business owner confirms it.",
                mitre_techniques=["T1041 - Exfiltration Over C2 Channel", "T1567 - Exfiltration Over Web Service"],
                entities={"source_ips": [source_ip], "destination_ips": [destination_ip], "assets": sorted(assets[(source_ip, destination_ip)])},
                evidence=[f"Outbound bytes: {total_bytes}"],
                first_seen=min(timestamps[(source_ip, destination_ip)]),
                last_seen=max(timestamps[(source_ip, destination_ip)]),
            )
        )
    return alerts


def detect_suspicious_process(events: list[SecurityEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.event_type != "endpoint":
            continue
        risk_bonus = command_line_risk(event.command_line, event.process)
        if risk_bonus < 25:
            continue
        risk = min(100, 50 + risk_bonus + asset_weight(event.asset))
        alerts.append(
            Alert(
                title=f"Suspicious command execution on {event.asset or event.source_ip}",
                category="endpoint",
                severity=severity_from_score(risk),
                risk_score=risk,
                confidence="medium",
                summary=f"{event.process or 'A process'} executed command-line behavior often seen in malware or hands-on-keyboard activity.",
                business_impact="Could indicate script-based malware, credential theft, or lateral movement preparation.",
                recommendation="Collect process tree, isolate the endpoint if needed, review parent process, and search for the same command across the environment.",
                mitre_techniques=["T1059 - Command and Scripting Interpreter", "T1105 - Ingress Tool Transfer"],
                entities={"source_ips": [event.source_ip], "assets": [event.asset] if event.asset else [], "users": [event.username] if event.username else []},
                evidence=[f"{event.process}: {event.command_line}".strip()],
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
        )
    return alerts
