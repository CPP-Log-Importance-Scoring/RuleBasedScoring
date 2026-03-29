"""
parsing/schema.py
-----------------
Defines the unified LogRecord dataclass that all pipeline stages read/write.
Every field that is empty at parse time gets filled in by downstream modules.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LogRecord:
    # ── Stage 1: Populated by parse_logs.py ──────────────────────────────────
    timestamp:        str            = ""   # "Mar 12 10:00:00"
    log_level:        str            = ""   # "INFO" | "WARN" | "ERROR" | "CRITICAL"
    host:             str            = ""   # "sw-core-01", "sw-access-02", …
    service:          str            = ""   # "OSPF", "SECURITY", "SNMP", …
    event_type:       str            = ""   # coarse category  e.g. "OSPF"
    event_action:     str            = ""   # fine action      e.g. "NEIGHBOR_DOWN"
    message:          str            = ""   # full raw message text
    raw_line:         str            = ""   # original unparsed syslog line

    # ── Stage 1b: Populated by template_extraction.py ────────────────────────
    template_id:      str            = ""   # e.g. "OSPF_NEIGHBOR_DOWN"

    # ── Stage 2: Populated by features/ modules ──────────────────────────────
    severity_score:   float          = 0.0  # 1–4  from log_level
    event_type_score: float          = 0.0  # 1–4  from event_type + event_action lookup
    anomaly_score:    float          = 0.0  # 0 or 1  from anomaly_proximity.py
    frequency:        int            = 0    # count of same template_id in last 60 s

    # ── Stage 3: Populated by scoring/event_weight.py ────────────────────────
    event_weight:     float          = 0.0  # w1·sev + w2·evt + w3·anom

    # ── Stage 4: Populated by correlation/correlation_engine.py ──────────────
    correlation_id:   Optional[str]  = None  # UUID shared by a correlated cluster
    correlation_score: float         = 0.0   # proportional to cluster size

    # ── Stage 5: Populated by scoring/importance_score.py ────────────────────
    importance_score: float          = 0.0   # α·ew + β·log(freq+1) + γ·corr
    label:            str            = ""    # "Ignore"|"Low"|"Medium"|"Critical"


# ── Syslog priority → log_level mapping ──────────────────────────────────────
# RFC 3164 priority values found in your logs: <189>=DEBUG/INFO, <190>=NOTICE,
# <191>=INFO.  We map numerically to the four scoring tiers.
PRIORITY_TO_LEVEL: dict[int, str] = {
    # facility=23 (local7), severity 0-7
    # <184> sev=0 EMERGENCY
    # <185> sev=1 ALERT
    # <186> sev=2 CRITICAL
    # <187> sev=3 ERROR
    # <188> sev=4 WARNING
    # <189> sev=5 NOTICE   → mapped to WARN  (elevated)
    # <190> sev=6 INFO     → mapped to INFO
    # <191> sev=7 DEBUG    → mapped to INFO
}

def priority_to_log_level(priority: int) -> str:
    """Convert raw syslog <PRI> integer to a scoring log_level string."""
    severity = priority & 0x07          # lowest 3 bits = syslog severity
    if severity <= 2:
        return "CRITICAL"
    elif severity == 3:
        return "ERROR"
    elif severity == 4:
        return "WARN"
    else:                               # 5, 6, 7
        return "INFO"