from __future__ import annotations

from ipaddress import ip_address

HIGH_RISK_TLDS = (".ru", ".top", ".xyz", ".click", ".zip", ".mov")
EXECUTION_KEYWORDS = ("powershell", "encodedcommand", "wscript", "cscript", "rundll32", "regsvr32")
HIGH_RISK_PORTS = {22, 23, 445, 3389, 5900, 5985, 5986}
CRITICAL_ASSETS = {"domain-controller", "payment-api", "ehr-db", "vpn-gateway", "cloud-admin"}


def is_public_ip(value: str) -> bool:
    if not value:
        return False
    try:
        parsed = ip_address(value)
    except ValueError:
        return False
    return not (parsed.is_private or parsed.is_loopback or parsed.is_multicast)


def domain_risk(domain: str) -> int:
    domain = domain.lower()
    score = 0
    if any(domain.endswith(tld) for tld in HIGH_RISK_TLDS):
        score += 25
    if domain.count("-") >= 2:
        score += 10
    if any(token in domain for token in ("login", "verify", "secure", "update", "mfa")):
        score += 10
    return score


def asset_weight(asset: str) -> int:
    return 15 if asset.lower() in CRITICAL_ASSETS else 0


def command_line_risk(command_line: str, process: str = "") -> int:
    text = f"{process} {command_line}".lower()
    score = 0
    if any(keyword in text for keyword in EXECUTION_KEYWORDS):
        score += 25
    if "-enc" in text or "frombase64string" in text:
        score += 25
    if "http://" in text or "https://" in text:
        score += 10
    return score
