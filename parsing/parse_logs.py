

import re
from pathlib import Path
from typing import Iterator

from parsing.schema import LogRecord, priority_to_log_level

#  Regex for the syslog line
# Group 1: priority integer  e.g. 190
# Group 2: timestamp         e.g. "Mar 12 10:00:00"
# Group 3: host              e.g. "sw-access-02"
# Group 4: service           e.g. "SNMP"
# Group 5: message body      e.g. "Authentication failure from 192.168.14.92"
_SYSLOG_RE = re.compile(
    r"^<(\d+)>"                          # <PRI>
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"  # timestamp
    r"\s+(\S+)"                          # host
    r"\s+([A-Z_]+):\s*"                  # SERVICE:
    r"(.+)$"                             # message
)

#  Per-service action extraction rules
# Returns (event_type, event_action) given service name + message text.
# Keeps parse_logs.py self-contained; no external lookup needed here.

def _extract_event(service: str, message: str) -> tuple[str, str]:
 
    msg = message.lower()

    if service == "OSPF":
        if "full to down" in msg:
            return "OSPF", "NEIGHBOR_DOWN"
        return "OSPF", "STATE_CHANGE"

    if service == "SECURITY":
        if "port scan" in msg:
            return "SECURITY", "PORT_SCAN"
        if "mac" in msg and "blocked" in msg:
            return "SECURITY", "MAC_BLOCKED"
        return "SECURITY", "GENERIC"

    if service == "SNMP":
        if "authentication failure" in msg:
            return "SNMP", "AUTH_FAILURE"
        return "SNMP", "GENERIC"

    if service == "PORT":
        if "state to down" in msg:
            return "PORT", "PORT_DOWN"
        if "state to up" in msg:
            return "PORT", "PORT_UP"
        return "PORT", "STATE_CHANGE"

    if service == "DHCP_SNOOP":
        return "DHCP_SNOOP", "PACKET_DROPPED"

    if service == "VLAN":
        if "added" in msg:
            return "VLAN", "VLAN_ADDED"
        if "removed" in msg:
            return "VLAN", "VLAN_REMOVED"
        return "VLAN", "CHANGE"

    if service == "IDM":
        if "acl error" in msg:
            return "IDM", "ACL_ERROR"
        return "IDM", "GENERIC"

    if service == "Manager":
        if "configuration saved" in msg:
            return "CONFIG", "CONFIG_CHANGE"
        return "CONFIG", "GENERIC"

    if service == "syslog":
        return "SYSLOG", "LOGGING_STARTED"

    # Fallback — preserve raw service name
    return service, "UNKNOWN"


# Main parsing function 

def parse_line(raw_line: str) -> LogRecord | None:
    """
    Parse a single syslog line into a LogRecord.
    Returns None if the line doesn't match the expected format
    (e.g. blank lines, comments).
    """
    line = raw_line.strip()
    if not line:
        return None

    match = _SYSLOG_RE.match(line)
    if not match:
        return None

    priority_str, timestamp, host, service, message = match.groups()
    priority = int(priority_str)
    log_level = priority_to_log_level(priority)
    event_type, event_action = _extract_event(service, message)

    return LogRecord(
        raw_line     = raw_line.rstrip(),
        timestamp    = timestamp.strip(),
        log_level    = log_level,
        host         = host,
        service      = service,
        event_type   = event_type,
        event_action = event_action,
        message      = message.strip(),
    )


def parse_file(log_path: str | Path) -> Iterator[LogRecord]:
    """
    Lazily yield LogRecord objects from a log file, one per valid line.
    Skips malformed lines silently (prints a warning if debug=True).
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            record = parse_line(raw_line)
            if record is not None:
                yield record
      


if __name__ == "__main__":
    import sys

    log_file = sys.argv[1] if len(sys.argv) > 1 else "data/logs.txt"
    print(f"Parsing: {log_file}\n{'─'*60}")

    for i, record in enumerate(parse_file(log_file)):
        print(
            f"[{record.timestamp}] {record.host} | {record.log_level:8s} | "
            f"{record.service:12s} | {record.event_type}/{record.event_action}"
        )
        if i >= 14:          # show first 15 records then stop
            print("... (truncated, remove limit to see all)")
            break