"""Rule matching — filter BPF events by process comm and target rules.

Matching logic:
  1. event.comm must exactly match a target's process name
  2. The event type (FILE/NET/DNS) must have matching rules in the target
     FILE: event.data must start with one of target["file"] prefixes
     NET:  event.data IP must match target["network"] (IP or IP:port)
     DNS:  event.data domain must match target["dns"] (exact or suffix)
"""

from typing import List, Dict, Any


_TYPE_TO_FIELD = {"FILE": "file", "NET": "network", "DNS": "dns"}


def _match_file(event_data: str, rules: List[str]) -> bool:
    """Check if file path matches any prefix rule."""
    if not rules:
        return False
    for rule in rules:
        if event_data.startswith(rule):
            return True
    return False


def _match_net(event_data: str, rules: List[str]) -> bool:
    """Check if IP:port matches any network rule.

    rules: ["127.0.0.1", "192.168.1.1:80", "10.0.0.0/8"]
    event_data: "192.168.1.1:9999"
    """
    if not rules or not event_data:
        return False

    # Parse event IP:port
    try:
        ip_port = event_data.split(":")
        event_ip = ip_port[0]
        event_port = int(ip_port[1]) if len(ip_port) > 1 else 0
    except (ValueError, IndexError):
        return False

    for rule in rules:
        if ":" in rule:
            # IP:port rule
            rule_ip, rule_port = rule.split(":")
            if event_ip == rule_ip and event_port == int(rule_port):
                return True
        else:
            # IP only rule
            if event_ip == rule:
                return True
            # TODO: support CIDR like "10.0.0.0/8"

    return False


def _match_dns(event_data: str, rules: List[str]) -> bool:
    """Check if DNS query matches any domain rule.

    rules: ["example.com", ".google.com"]
    event_data: "www.example.com"

    Exact match: "example.com" → only "example.com"
    Suffix match: ".example.com" → "www.example.com", "api.example.com"
    """
    if not rules or not event_data:
        return False

    for rule in rules:
        if rule.startswith("."):
            # Suffix match
            if event_data.endswith(rule) or event_data == rule[1:]:
                return True
        else:
            # Exact match
            if event_data == rule:
                return True

    return False


def filter_events(events: List[Dict], targets: List[Dict]) -> List[Dict]:
    """Filter events by process name AND rule matching.

    Returns filtered list of events.
    """
    if not events or not targets:
        return []

    enabled_targets = [t for t in targets if t.get("enabled", True)]
    if not enabled_targets:
        return []

    filtered = []
    for event in events:
        comm = event.get("comm", "")
        event_type = event.get("type", "")
        event_data = event.get("data", "")
        if not comm or not event_type:
            continue

        rule_field = _TYPE_TO_FIELD.get(event_type)
        if not rule_field:
            continue

        # Find matching target
        matched = False
        for target in enabled_targets:
            if comm != target.get("process", ""):
                continue

            target_rules = target.get(rule_field, [])
            if not target_rules:
                continue

            # Apply type-specific matching
            if event_type == "FILE":
                if _match_file(event_data, target_rules):
                    matched = True
                    break
            elif event_type == "NET":
                if _match_net(event_data, target_rules):
                    matched = True
                    break
            elif event_type == "DNS":
                if _match_dns(event_data, target_rules):
                    matched = True
                    break

        if matched:
            filtered.append(event)

    return filtered
