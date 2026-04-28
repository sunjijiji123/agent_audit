"""Rule matching — filter audit events by file path, network IP, DNS domain.

Matching logic:
  FILE: event file path starts with any rule prefix
  NET:  event IP:port matches rule (IP or IP:port)
  DNS:  event domain matches rule (exact or suffix with leading dot)

If a target has empty rules for a type, all events of that type pass through.
"""

from typing import List, Dict


def _match_file(path: str, rules: List[str]) -> bool:
    if not rules:
        return True
    return any(path.startswith(r) for r in rules)


def _match_net(dst: str, rules: List[str]) -> bool:
    if not rules:
        return True
    try:
        ip_port = dst.rsplit(":", 1)
        event_ip = ip_port[0].strip("[]")
        event_port = int(ip_port[1]) if len(ip_port) > 1 else 0
    except (ValueError, IndexError):
        return False

    for rule in rules:
        if ":" in rule and not rule.startswith("["):
            rule_ip, rule_port = rule.rsplit(":", 1)
            if event_ip == rule_ip and event_port == int(rule_port):
                return True
        else:
            if event_ip == rule:
                return True
    return False


def _match_dns(query: str, rules: List[str]) -> bool:
    if not rules:
        return True
    for rule in rules:
        if rule.startswith("."):
            if query.endswith(rule) or query == rule[1:]:
                return True
        else:
            if query == rule:
                return True
    return False


def match_event(event: Dict, targets: List[Dict]) -> bool:
    """Check if an event matches any enabled target's rules.

    Returns True if the event should be logged.
    """
    if not targets:
        return True

    event_type = event.get("type", "")
    pid = event.get("process", {}).get("pid", 0)

    for t in targets:
        if not t.get("enabled", True):
            continue
        if t.get("pid") and t["pid"] != pid:
            continue

        rules_key = {"FILE": "file", "NET": "network", "DNS": "dns"}.get(event_type)
        if not rules_key:
            continue

        rules = t.get(rules_key, [])
        if not rules:
            return True

        if event_type == "FILE":
            path = event.get("file", {}).get("path", "")
            if _match_file(path, rules):
                return True
        elif event_type == "NET":
            dst = event.get("network", {}).get("dst", "")
            if _match_net(dst, rules):
                return True
        elif event_type == "DNS":
            query = event.get("dns", {}).get("query", "")
            if _match_dns(query, rules):
                return True

    return False
