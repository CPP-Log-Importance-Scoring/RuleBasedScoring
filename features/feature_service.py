import re
import logging
from dataclasses import dataclass
from collections import Counter

from parsing.schema import LogRecord

logger = logging.getLogger(__name__)


# ── Severity map ─────────────────────────────────────────────────────────────

SEVERITY_MAP: dict[str, float] = {
    "INFO":     1.0,
    "WARN":     2.0,
    "ERROR":    3.0,
    "CRITICAL": 4.0,
}


# ── Event type score table ───────────────────────────────────────────────────

EVENT_TYPE_SCORE_TABLE: dict[tuple[str, str], float] = {
    ("OSPF", "NEIGHBOR_DOWN"):        4.0,
    ("OSPF", "STATE_CHANGE"):         2.5,
    ("OSPF", "*"):                    2.5,

    ("SECURITY", "PORT_SCAN"):        4.0,
    ("SECURITY", "MAC_BLOCKED"):      4.0,
    ("SECURITY", "GENERIC"):          3.0,
    ("SECURITY", "*"):                3.0,

    ("SNMP", "AUTH_FAILURE"):         3.0,
    ("SNMP", "GENERIC"):              1.0,
    ("SNMP", "*"):                    1.0,

    ("PORT", "PORT_DOWN"):            3.0,
    ("PORT", "PORT_UP"):              1.0,
    ("PORT", "STATE_CHANGE"):         1.5,
    ("PORT", "*"):                    1.5,

    ("DHCP_SNOOP", "PACKET_DROPPED"): 2.0,
    ("DHCP_SNOOP", "*"):              2.0,

    ("VLAN", "VLAN_ADDED"):           1.0,
    ("VLAN", "VLAN_REMOVED"):         1.5,
    ("VLAN", "CHANGE"):               1.0,
    ("VLAN", "*"):                    1.0,

    ("IDM", "ACL_ERROR"):             2.5,
    ("IDM", "GENERIC"):               1.0,
    ("IDM", "*"):                     1.0,

    ("CONFIG", "CONFIG_CHANGE"):      1.0,
    ("CONFIG", "GENERIC"):            1.0,
    ("CONFIG", "*"):                  1.0,

    ("SYSLOG", "LOGGING_STARTED"):    0.5,
    ("SYSLOG", "*"):                  0.5,
}


# ── Scored result ────────────────────────────────────────────────────────────

@dataclass
class ScoredResult:
    score: float
    confidence: float
    tier: str


# ── Pattern rules ────────────────────────────────────────────────────────────

@dataclass
class PatternRule:
    pattern: re.Pattern
    score: float
    label: str
    confidence: float


PATTERN_SCORE_TABLE: list[PatternRule] = [
    PatternRule(re.compile(r"timeout|unreachable", re.I), 3.8, "TIMEOUT", 0.65),
    PatternRule(re.compile(r"(link|interface|port).*(down|fail)", re.I), 3.5, "LINK_DOWN", 0.75),
    PatternRule(re.compile(r"(auth|authentication).*(fail|error)", re.I), 3.4, "AUTH_FAIL", 0.80),
    PatternRule(re.compile(r"(acl|access.list).*(deny|block|drop)", re.I), 3.0, "ACL_DENY", 0.70),
    PatternRule(re.compile(r"(cpu|memory).*(high|exceed|full)", re.I), 2.8, "RESOURCE", 0.70),
    PatternRule(re.compile(r"(queue|buffer).*(drop)", re.I), 2.5, "QUEUE_DROP", 0.72),
]


# ── Keyword tiers ────────────────────────────────────────────────────────────

_KW_CRITICAL = ["fail", "down", "timeout", "error", "drop"]
_KW_WARNING  = ["warn", "slow", "retry", "high"]
_KW_INFO     = ["start", "success", "up", "ok"]


# ── Gap tracking ─────────────────────────────────────────────────────────────

fallback_counter: Counter = Counter()


def _record_gap(et: str, ea: str):
    fallback_counter[(et, ea)] += 1


def gap_report(top_n: int = 20):
    return [
    {"event_type": et, "event_action": ea, "miss_count": c}
    for (et, ea), c in fallback_counter.most_common(top_n)
]


# ── Core scoring ─────────────────────────────────────────────────────────────

def get_severity_score(log_level: str) -> float:
    return SEVERITY_MAP.get(log_level.upper(), 1.0)


def get_event_type_score(event_type, event_action, raw_message="") -> ScoredResult:
    et = (event_type or "*").upper()
    ea = (event_action or "*").upper()

    # Tier 1
    score = EVENT_TYPE_SCORE_TABLE.get((et, ea))
    if score is not None:
        return ScoredResult(score, 1.0, "exact")

    # Tier 2
    score = EVENT_TYPE_SCORE_TABLE.get((et, "*"))
    if score is not None:
        return ScoredResult(score, 0.85, "wildcard")

    # Tier 3 (pattern)
    if raw_message:
        for rule in PATTERN_SCORE_TABLE:
            if rule.pattern.search(raw_message):
                return ScoredResult(rule.score, rule.confidence, "pattern")

        msg = raw_message.lower()

        # Tier 4 (keyword)
        if any(k in msg for k in _KW_CRITICAL):
            return ScoredResult(3.5, 0.4, "keyword")
        if any(k in msg for k in _KW_WARNING):
            return ScoredResult(2.0, 0.4, "keyword")
        if any(k in msg for k in _KW_INFO):
            return ScoredResult(0.8, 0.4, "keyword")

    # Tier 5 fallback
    _record_gap(et, ea)
    return ScoredResult(1.2, 0.2, "fallback")


# ── Compute features ─────────────────────────────────────────────────────────

def compute_features(record: LogRecord) -> LogRecord:
    record.severity_score = get_severity_score(record.log_level)

    result = get_event_type_score(
        record.event_type,
        record.event_action,
        record.message,
    )

    record.event_type_score = result.score
    record.event_type_confidence = result.confidence
    record.event_type_tier = result.tier

    # 🔥 NEW FIX: promote pattern → event_type
    if record.event_type == "UNKNOWN" and result.tier in ("pattern", "keyword"):
        record.event_type = result.tier.upper()

    return record


def compute_features_batch(records: list[LogRecord]) -> list[LogRecord]:
    for r in records:
        compute_features(r)
    return records