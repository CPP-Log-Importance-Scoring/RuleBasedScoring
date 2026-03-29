"""
parsing/template_extraction.py
-------------------------------
Assigns a template_id to each LogRecord by normalising the message text —
replacing volatile tokens (IPs, MACs, port numbers, VLAN IDs, Router IDs,
usernames, server addresses) with fixed placeholders, then building a
deterministic string key from (service, event_action, normalised_message).

WHY this approach instead of a full Drain/LenMa parser:
  • Your log corpus has a small, well-known set of services and message
    structures (identified from logs.txt).  Simple regex normalisation
    produces stable, human-readable template IDs without the overhead of
    an online clustering algorithm.
  • template_id feeds directly into frequency.py's sliding-window counter,
    so it MUST be deterministic: two structurally identical lines from
    different hosts must produce the same template_id.

Template ID format:  "<SERVICE>_<EVENT_ACTION>"
  e.g.  OSPF_NEIGHBOR_DOWN
        SECURITY_PORT_SCAN
        SNMP_AUTH_FAILURE
        PORT_PORT_DOWN
        CONFIG_CONFIG_CHANGE
        DHCP_SNOOP_PACKET_DROPPED
        IDM_ACL_ERROR
        VLAN_VLAN_ADDED
        VLAN_VLAN_REMOVED
        SYSLOG_LOGGING_STARTED

For services/actions that are genuinely distinct in message structure
(e.g. VLAN_ADDED vs VLAN_REMOVED) the event_action already captures
the distinction, so the template_id is simply f"{service}_{event_action}".

The normalised_message is stored separately for debugging; it is NOT part
of the template_id key (keeping IDs short and readable).
"""

import re
from parsing.schema import LogRecord


# ── Volatile-token patterns (order matters — most specific first) ─────────────

_NORMALISATION_RULES: list[tuple[re.Pattern, str]] = [
    # Router ID  e.g. "Router ID 192.168.46.47"
    (re.compile(r"Router ID\s+\d{1,3}(?:\.\d{1,3}){3}"), "Router ID <ROUTER_ID>"),

    # MAC address  e.g. "09:A0:B2:56:6C:18"  or  "09-A0-B2-56-6C-18"
    (re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"), "<MAC>"),

    # IPv4 address  e.g. "192.168.14.92"
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),

    # Interface / port  e.g. "1/0/28"  "1/0/3"
    (re.compile(r"\b\d+/\d+/\d+\b"), "<PORT>"),

    # VLAN number  e.g. "VLAN 44"  "VLAN 1"
    (re.compile(r"\bVLAN\s+\d+\b"), "VLAN <VLAN_ID>"),

    # Generic integer (catch remaining numbers that vary per event)
    # Intentionally conservative — only bare numbers ≥2 digits
    (re.compile(r"\b\d{2,}\b"), "<NUM>"),
]


def _normalise_message(message: str) -> str:
    """
    Replace volatile tokens in a log message with fixed placeholders,
    producing a stable structural representation.
    """
    result = message
    for pattern, replacement in _NORMALISATION_RULES:
        result = pattern.sub(replacement, result)
    return result


def assign_template_id(record: LogRecord) -> LogRecord:
    """
    Compute and write template_id (and normalised_message) into a LogRecord.
    Returns the same record (mutated in place) for easy chaining.

    template_id is intentionally coarse: it groups all log lines that have
    the same structural meaning, regardless of the specific IPs/ports involved.
    This is exactly what the 60-second frequency window needs.
    """
    # Primary key: service + event_action  (already extracted by parse_logs.py)
    # This covers ~95% of your log corpus cleanly.
    template_id = f"{record.service}_{record.event_action}".upper()

    # Store the normalised message for debugging / template_extraction.py tests
    record.message = _normalise_message(record.message)   # replace in-place
    record.template_id = template_id
    return record


def assign_template_ids_batch(records: list[LogRecord]) -> list[LogRecord]:
    """
    Convenience wrapper: assign template_ids to a list of records.
    Returns the same list (mutated in place).
    """
    for record in records:
        assign_template_id(record)
    return records


# ── Template registry: human-readable descriptions ───────────────────────────
# Used by tests and reporting to describe what each template means.

TEMPLATE_DESCRIPTIONS: dict[str, str] = {
    "OSPF_NEIGHBOR_DOWN":        "OSPF neighbour transitioned from FULL to DOWN",
    "OSPF_STATE_CHANGE":         "OSPF neighbour state changed (non-DOWN)",
    "SECURITY_PORT_SCAN":        "Possible port scan detected from an IP",
    "SECURITY_MAC_BLOCKED":      "MAC address blocked by security policy",
    "SECURITY_GENERIC":          "Generic security event",
    "SNMP_AUTH_FAILURE":         "SNMP authentication failure",
    "SNMP_GENERIC":              "Generic SNMP event",
    "PORT_PORT_DOWN":            "Physical port transitioned to DOWN",
    "PORT_PORT_UP":              "Physical port transitioned to UP",
    "PORT_STATE_CHANGE":         "Port state changed (unclassified direction)",
    "DHCP_SNOOP_PACKET_DROPPED": "DHCP packet dropped by snooping on untrusted port",
    "VLAN_VLAN_ADDED":           "VLAN added to a port",
    "VLAN_VLAN_REMOVED":         "VLAN removed from a port",
    "VLAN_CHANGE":               "Generic VLAN configuration change",
    "IDM_ACL_ERROR":             "IDM ACL error — invalid VLAN for client",
    "IDM_GENERIC":               "Generic IDM event",
    "CONFIG_CONFIG_CHANGE":      "Configuration saved to flash by admin",
    "CONFIG_GENERIC":            "Generic configuration manager event",
    "SYSLOG_LOGGING_STARTED":    "Syslog forwarding started to a remote server",
    "MANAGER_UNKNOWN":           "Unclassified Manager event",
}


def describe_template(template_id: str) -> str:
    """Return a human-readable description for a template_id."""
    return TEMPLATE_DESCRIPTIONS.get(template_id, f"Unknown template: {template_id}")


# ── Smoke-test (run directly: python -m parsing.template_extraction) ──────────
if __name__ == "__main__":
    import sys
    from parsing.parse_logs import parse_file
    from collections import Counter

    log_file = sys.argv[1] if len(sys.argv) > 1 else "data/logs.txt"
    print(f"Template extraction on: {log_file}\n{'─'*60}")

    template_counts: Counter = Counter()

    for record in parse_file(log_file):
        assign_template_id(record)
        template_counts[record.template_id] += 1

    print(f"{'Template ID':<35} {'Count':>7}  Description")
    print("─" * 80)
    for tid, count in template_counts.most_common():
        desc = describe_template(tid)
        print(f"{tid:<35} {count:>7}  {desc}")

    print(f"\nTotal unique templates : {len(template_counts)}")
    print(f"Total records parsed   : {sum(template_counts.values())}")