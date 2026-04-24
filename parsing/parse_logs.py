import re
from pathlib import Path
from typing import Iterator

from parsing.schema import LogRecord, priority_to_log_level

# ── Syslog line regex ────────────────────────────────────────────────────
# Group 1: priority integer  e.g. 190
# Group 2: timestamp         e.g. "Mar 12 10:00:00"
# Group 3: host              e.g. "sw-core-01"
# Group 4: service           e.g. "APP"
# Group 5: message body      e.g. "Database timeout"

_SYSLOG_RE = re.compile(
    r"^<(\d+)>"                              # <PRI>
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"   # timestamp
    r"\s+(\S+)"                              # host
    r"\s+([A-Z_]+):\s*"                      # SERVICE:
    r"(.+)$"                                 # message
)


# ── Per-service action extraction ────────────────────────────────────────

def _extract_event(service: str, message: str) -> tuple[str, str]:
    """
    Returns (event_type, event_action) for a given service + message.
    Covers every service present in logs5_fixed.txt.
    """
    msg = message.lower()

    # ── APP ──────────────────────────────────────────────────────────────
    if service == "APP":
        if "authentication failed" in msg:
            return "APP", "authentication failed"
        if "database timeout" in msg:
            return "APP", "Database timeout"
        if "service restarted" in msg:
            return "APP", "Service restarted"
        if "user login success" in msg:
            return "APP", "User login success"
        return "APP", "GENERIC"

    # ── FW ───────────────────────────────────────────────────────────────
    if service == "FW":
        if "connection denied" in msg:
            return "FW", "connection denied"
        if "connection allowed" in msg:
            return "FW", "connection allowed"
        return "FW", "GENERIC"

    # ── WEB ──────────────────────────────────────────────────────────────
    if service == "WEB":
        if "/.env" in msg:
            return "WEB", "GET /.env"
        if "/wp-admin" in msg:
            return "WEB", "GET /wp-admin"
        if "/admin" in msg:
            return "WEB", "GET /admin"
        if "/api/data" in msg and "500" in msg:
            return "WEB", "GET /api/data 500"
        if "/api/data" in msg:
            return "WEB", "GET /api/data 200"
        if "/login" in msg and "500" in msg:
            return "WEB", "GET /login 500"
        if "/login" in msg and "404" in msg:
            return "WEB", "GET /login 404"
        if "/login" in msg and "200" in msg:
            return "WEB", "GET /login 200"
        return "WEB", "GENERIC"

    #  SYS 
    if service == "SYS":
        if "health check failed" in msg or "failed" in msg:
            return "SYS", "health check FAILED"
        if "periodic health check" in msg:
            return "SYS", "periodic health check"
        return "SYS", "GENERIC"

    # ── ROUTING 
    if service == "ROUTING":
        if "flap" in msg:
            return "ROUTING", "route flap detected"
        if "added" in msg:
            return "ROUTING", "route added"
        if "removed" in msg:
            return "ROUTING", "route removed"
        return "ROUTING", "GENERIC"

    # ── IDM ──────────────────────────────────────────────────────────────
    if service == "IDM":
        if "privilege escalation" in msg:
            return "IDM", "privilege escalation attempt"
        if "acl error" in msg:
            return "IDM", "ACL error"
        return "IDM", "GENERIC"

    # ── PORT ─────────────────────────────────────────────────────────────
    if service == "PORT":
        if "state to down" in msg:
            return "PORT", "port changed state to down"
        if "state to up" in msg:
            return "PORT", "port changed state to up"
        return "PORT", "STATE_CHANGE"

    # ── Legacy / less common services ────────────────────────────────────
    if service == "OSPF":
        if "full to down" in msg:
            return "OSPF", "NEIGHBOR_DOWN"
        return "OSPF", "STATE_CHANGE"

    if service == "SECURITY" or service == "SECURITY_PORT_SCAN":
        if "port scan" in msg:
            return "SECURITY", "PORT_SCAN"
        if "mac" in msg and "blocked" in msg:
            return "SECURITY", "MAC_BLOCKED"
        return "SECURITY", "GENERIC"

    if service == "SNMP":
        if "authentication failure" in msg:
            return "SNMP", "AUTH_FAILURE"
        return "SNMP", "GENERIC"

    if service == "DHCP_SNOOP":
        return "DHCP_SNOOP", "PACKET_DROPPED"

    if service == "VLAN":
        if "added" in msg:
            return "VLAN", "VLAN_ADDED"
        if "removed" in msg:
            return "VLAN", "VLAN_REMOVED"
        return "VLAN", "CHANGE"

    if service == "Manager":
        if "configuration saved" in msg:
            return "CONFIG", "CONFIG_CHANGE"
        return "CONFIG", "GENERIC"

    if service == "syslog":
        return "SYSLOG", "LOGGING_STARTED"

    # Final fallback
    return service, "UNKNOWN"


# ── Line parser ──────────────────────────────────────────────────────────

def parse_line(raw_line: str) -> LogRecord | None:
    """
    Parse a single syslog line into a LogRecord.
    Returns None if the line doesn't match expected format.
    """
    line = raw_line.strip()
    if not line:
        return None

    match = _SYSLOG_RE.match(line)
    if not match:
        return None

    priority_str, timestamp, host, service, message = match.groups()
    priority  = int(priority_str)
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


# ── File parser ──────────────────────────────────────────────────────────

def parse_file(log_path: str | Path) -> Iterator[LogRecord]:
    """
    Lazily yield LogRecord objects from a log file, one per valid line.
    Skips malformed lines silently.
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            record = parse_line(raw_line)
            if record is not None:
                yield record


# ── CLI quick-check ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    log_file = sys.argv[1] if len(sys.argv) > 1 else "data/logs.txt"
    print(f"Parsing: {log_file}\n{'─' * 60}")

    for i, record in enumerate(parse_file(log_file)):
        print(
            f"[{record.timestamp}] {record.host} | {record.log_level:8s} | "
            f"{record.service:12s} | {record.event_type}/{record.event_action}"
        )
        if i >= 14:
            print("... (truncated)")
            break