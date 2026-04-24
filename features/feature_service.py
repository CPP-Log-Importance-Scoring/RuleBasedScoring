"""
feature_service.py
──────────────────
Computes all features on a LogRecord before scoring:
  - severity_score       (from syslog priority)
  - event_type_score     (from event_type + event_action semantics)
  - anomaly_score        (binary: 1.0 if anomalous pattern, else 0.0)
  - frequency            (count of same template in sliding window)
  - novelty_score        (1.0 = first time seen, 0.0 = seen constantly)
  - correlation_score    (set externally by correlation engine)

Event type scores are calibrated against the actual log distribution
in logs5_fixed.txt. Rare + security-relevant events score highest.
"""

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)


# ── Event Type Score Table ──────────────────────────────────────────────
#
# Scale: 0.0 (pure noise) → 5.0 (critical security event)
#
# Calibration notes (from logs5_fixed.txt distribution):
#   - SYS: periodic health check     → 5080 occurrences → noise floor
#   - ROUTING: route added/removed   → 5233 occurrences → background churn
#   - FW: connection allowed         → 2326 occurrences → normal traffic
#   - APP: User login success        → 1576 occurrences → normal
#   - APP: Service restarted         → 655  occurrences → worth noting
#   - WEB: GET /login 500/404        → 952  occurrences → elevated but common
#   - APP: Database timeout          → 385  occurrences → operational concern
#   - IDM: privilege escalation      → 34   occurrences → HIGH security
#   - APP: authentication failed     → 6    occurrences → CRITICAL (brute force)
#   - SYS: health check FAILED       → 2    occurrences → CRITICAL (outage)
#   - ROUTING: route flap detected   → 2    occurrences → HIGH (instability)
#   - WEB: GET /admin 403            → 4    occurrences → HIGH (recon)
#   - WEB: GET /.env 404             → 2    occurrences → HIGH (secret probe)
#   - FW: connection denied port=22  → 2    occurrences → HIGH (SSH attack)
#   - IDM: ACL error                 → 24   occurrences → MEDIUM

_EVENT_TYPE_SCORES: dict[str, float] = {
    # ── CRITICAL (4.5 – 5.0) ─────────────────────────────────────────
    "authentication failed":        5.0,   # brute force / credential attack
    "health check FAILED":          4.8,   # system outage signal
    "connection denied":            4.5,   # blocked attack attempt

    # ── HIGH (3.0 – 4.4) ─────────────────────────────────────────────
    "privilege escalation attempt": 4.2,   # security violation
    "route flap detected":          3.8,   # routing instability (network impact)
    "GET /admin":                   3.5,   # admin recon attempt
    "GET /.env":                    3.5,   # secret/config file probe
    "GET /wp-admin":                3.2,   # CMS exploit scan
    "ACL error":                    3.0,   # network policy violation

    # ── MEDIUM (1.5 – 2.9) ───────────────────────────────────────────
    "Database timeout":             2.5,   # operational issue
    "Service restarted":            2.0,   # instability indicator
    "GET /login 500":               1.8,   # server error on auth endpoint
    "GET /login 404":               1.5,   # missing resource on auth endpoint
    "GET /api/data 500":            1.8,   # backend API failure

    # ── LOW (0.5 – 1.4) ──────────────────────────────────────────────
    "User login success":           0.8,   # normal — but high volume is suspect
    "GET /login 200":               0.5,   # successful login — normal
    "GET /api/data 200":            0.3,   # normal API traffic
    "route added":                  0.4,   # routine routing update
    "route removed":                0.4,   # routine routing update
    "port changed state to down":   0.9,   # worth tracking, common
    "port changed state to up":     0.5,   # recovery event
    "connection allowed":           0.2,   # normal firewall pass

    # ── IGNORE (0.0 – 0.4) ───────────────────────────────────────────
    "periodic health check":        0.0,   # pure noise — suppress entirely
}

# Fallback score for unknown event actions
_DEFAULT_EVENT_TYPE_SCORE = 1.0


# ── Syslog Priority → Severity Score ───────────────────────────────────
#
# Syslog facility*8 + severity. Lower number = more severe.
# <11> = facility 1 (user), severity 3 (error) → maps to high
# <185> = facility 23 (local7), severity 1 (alert) → maps to high
# <186> = facility 23 (local7), severity 2 (critical) → maps to medium
# <188> = facility 23 (local7), severity 4 (warning) → maps to low
# <191> = facility 23 (local7), severity 7 (debug) → maps to ignore

def _log_level_to_severity(log_level: str) -> float:
    """
    Convert LogRecord.log_level string to a severity score.
    log_level is set by parse_logs via priority_to_log_level() in schema.py:
      CRITICAL -> syslog sev 0-2  (emergency / alert / critical)
      ERROR    -> syslog sev 3
      WARN     -> syslog sev 4-5
      INFO     -> syslog sev 6-7
    """
    return {
        "CRITICAL": 4.0,
        "ERROR":    3.5,
        "WARN":     2.0,
        "INFO":     0.5,
    }.get((log_level or "INFO").upper(), 1.0)


#  Anomaly Patterns 
#
# Binary flag: 1.0 if event matches a known anomalous pattern.
# These are heuristics based on the actual log data.

_ANOMALY_PATTERNS = [
    "privilege escalation attempt",
    "authentication failed",
    "health check FAILED",
    "route flap detected",
    "connection denied",
    "GET /admin",
    "GET /.env",
    "GET /wp-admin",
    "ACL error",
    "GET /login 500",
    "Database timeout",
]


def _compute_anomaly_score(record: LogRecord) -> float:
    """
    Returns 1.0 if the event_action matches any known anomaly pattern.
    Returns 0.0 otherwise.
    """
    action = record.event_action or ""
    for pattern in _ANOMALY_PATTERNS:
        if pattern in action:
            return 1.0
    return 0.0


#  Sliding Window Frequency Counter 

class _SlidingWindowCounter:
    """
    Tracks per-template_id event frequency in a sliding time window.
    Used to compute frequency score and novelty.
    """

    def __init__(self, window_seconds: int = 300):
        self.window = timedelta(seconds=window_seconds)
        # template_id → deque of timestamps
        self._buckets: dict[str, deque] = defaultdict(deque)
        # template_id → total lifetime count (for novelty)
        self._lifetime: dict[str, int] = defaultdict(int)

    def record_and_count(self, template_id: str, timestamp: datetime) -> tuple[int, float]:
        """
        Records this event and returns:
          - frequency: count of same template in the sliding window
          - novelty_score: 1.0 if first ever seen, decays toward 0.0 as count grows
        """
        dq = self._buckets[template_id]

        # Evict events outside the window
        cutoff = timestamp - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

        # Record current event
        dq.append(timestamp)
        self._lifetime[template_id] += 1

        frequency = len(dq)
        lifetime_count = self._lifetime[template_id]

        # Novelty: decays as lifetime count grows
        # novelty = 1.0 on first occurrence, ~0.5 at 10th, ~0.1 at 100th
        novelty_score = 1.0 / (1.0 + (lifetime_count - 1) * 0.1)
        novelty_score = max(0.0, min(1.0, novelty_score))

        return frequency, novelty_score


# Module-level singleton counter (shared across batch)
_window_counter = _SlidingWindowCounter(window_seconds=300)


# ── Public API ──────────────────────────────────────────────────────────

def compute_all_features(record: LogRecord) -> LogRecord:
    """
    Computes and sets all feature fields on a LogRecord:
      - severity_score
      - event_type_score
      - anomaly_score
      - frequency
      - novelty_score

    Must be called after parse_logs (so event_action is set)
    and after assign_template_id (so template_id is set).
    correlation_score is set separately by the correlation engine.
    """

    # 1. Severity score from log_level string (CRITICAL/ERROR/WARN/INFO)
    record.severity_score = _log_level_to_severity(record.log_level)

    # 2. Event type score — look up by event_action substring match
    record.event_type_score = _lookup_event_type_score_tracked(record.event_action or "")

    # 3. Anomaly score
    record.anomaly_score = _compute_anomaly_score(record)

    # 4. Frequency + novelty from sliding window
    # timestamp is a str e.g. "Mar 12 10:00:00" — parse it for the window
    try:
        ts = datetime.strptime(record.timestamp, "%b %d %H:%M:%S").replace(year=datetime.now().year)
    except (ValueError, TypeError):
        ts = datetime.now()
    tid = record.template_id or record.event_action or "UNKNOWN"
    record.frequency, record.novelty_score = _window_counter.record_and_count(tid, ts)

    logger.debug(
        "features: sev=%.1f etype=%.1f anom=%.1f freq=%d novelty=%.3f  [%s/%s]",
        record.severity_score,
        record.event_type_score,
        record.anomaly_score,
        record.frequency,
        record.novelty_score,
        record.event_type,
        record.event_action,
    )

    return record


def compute_all_features_batch(records: list[LogRecord]) -> list[LogRecord]:
    """
    Apply feature computation to all records in order.
    Order matters for the sliding window frequency counter.
    """
    for record in records:
        compute_all_features(record)
    return records


def reset_window_counter(window_seconds: int = 300) -> None:
    """
    Reset the sliding window counter. Call between test runs
    or when processing a new log file from scratch.
    """
    global _window_counter
    _window_counter = _SlidingWindowCounter(window_seconds=window_seconds)


#  Aliases expected by main.py 

# main.py imports compute_features_batch — alias to compute_all_features_batch
compute_features_batch = compute_all_features_batch


# ── Gap Report ───────────────────────────────────────────────────────────

# Tracks event_action strings that fell through to the default score
# so you can see which templates have no explicit mapping yet.
_gap_misses: dict[str, int] = defaultdict(int)


def _lookup_event_type_score_tracked(event_action: str) -> float:
    """
    Same as _lookup_event_type_score but records misses for gap_report.
    Replaces the internal lookup used by compute_all_features.
    """
    for pattern, score in _EVENT_TYPE_SCORES.items():
        if pattern in event_action:
            return score

    _gap_misses[event_action] += 1
    logger.debug("No event_type_score match for action: %r", event_action)
    return _DEFAULT_EVENT_TYPE_SCORE


def gap_report(top_n: int = 10) -> list[dict]:
    """
    Returns the top_n event_action strings that had no explicit score mapping.
    Called by main.py after the pipeline completes to surface unmapped templates.

    Returns list of dicts: [{"event_type": str, "event_action": str, "miss_count": int}]
    """
    sorted_gaps = sorted(_gap_misses.items(), key=lambda x: x[1], reverse=True)
    results = []
    for action, count in sorted_gaps[:top_n]:
        # Try to split event_type from action if formatted as "TYPE: action"
        if ": " in action:
            etype, eaction = action.split(": ", 1)
        else:
            etype, eaction = "UNKNOWN", action
        results.append({
            "event_type":   etype,
            "event_action": eaction,
            "miss_count":   count,
        })
    return results


# ── Internal Helpers ────────────────────────────────────────────────────

def _lookup_event_type_score(event_action: str) -> float:
    """
    Finds the best matching score for an event_action string.
    Uses substring matching so partial actions still resolve.
    Falls back to _DEFAULT_EVENT_TYPE_SCORE if no match.
    """
    for pattern, score in _EVENT_TYPE_SCORES.items():
        if pattern in event_action:
            return score

    logger.debug("No event_type_score match for action: %r", event_action)
    return _DEFAULT_EVENT_TYPE_SCORE