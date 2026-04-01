"""
features/frequency.py
---------------------
Computes the frequency field on each LogRecord.

frequency = number of records with the same template_id seen within
            the last N seconds (default 60s, from config/weights.yaml).

This is Stage 2.  importance_score.py reads it in Stage 5.

Design doc §5.2 — Frequency (burst detection):
    "For each incoming log, we count how many other records share the
    same template_id within the last T seconds.  A high frequency count
    signals a burst — either a real incident manifesting repeatedly,
    or a chatty process generating noise."

WHY a sliding window (not a total count):
    Total count would grow forever.  A sliding window gives you the
    *current* burst rate — useful for real-time noise suppression.

Call order:
    parse_logs.py + template_extraction.py   [Stage 1]
    feature_service.py                       [Stage 2]
    >>> frequency.py                         [Stage 2]  ← this file
    anomaly_proximity.py                     [Stage 2]
    event_weight.py                          [Stage 3]
"""

import time
import logging
from collections import defaultdict, deque
from datetime import datetime
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------
# Syslog timestamp format: "Mar 12 10:00:00"
# We don't have a year in the logs — assume current year for time delta math.
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3,  "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7,  "Aug": 8,
    "Sep": 9, "Oct": 10,"Nov": 11, "Dec": 12,
}

def _parse_timestamp(ts_str: str) -> float:
    """
    Convert a syslog timestamp string to a Unix epoch float.

    Args:
        ts_str: e.g. "Mar 12 10:00:00"

    Returns:
        Unix timestamp float.  Falls back to time.time() on parse error.
    """
    try:
        parts = ts_str.strip().split()
        # parts = ["Mar", "12", "10:00:00"]
        month = _MONTHS.get(parts[0], 1)
        day   = int(parts[1])
        h, m, s = parts[2].split(":")
        now = datetime.now()
        dt = datetime(now.year, month, day, int(h), int(m), int(s))
        return dt.timestamp()
    except Exception:
        logger.debug("Could not parse timestamp '%s', using time.time()", ts_str)
        return time.time()



# FrequencyCounter — the sliding window state

class FrequencyCounter:

    def __init__(self, window_seconds: int = 60):
        """
        Args:
            window_seconds: Size of the sliding time window.
                            Logs older than this are evicted.
        """
        self.window_seconds = window_seconds
        # template_id -> deque of Unix timestamps within the window
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    def update(self, record: LogRecord) -> int:
        tid = record.template_id
        if not tid:
            logger.warning(
                "template_id is empty on record host=%s service=%s — "
                "frequency will be 0.  Did template_extraction.py run?",
                record.host, record.service,
            )
            record.frequency = 0
            return 0

        ts = _parse_timestamp(record.timestamp)
        window = self._windows[tid]

        # Evict timestamps older than the window
        cutoff = ts - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

  
        count = len(window)
        window.append(ts)

        record.frequency = count
        logger.debug(
            "frequency: template_id=%s  count=%d  window_size=%d  host=%s",
            tid, count, len(window), record.host,
        )
        return count

    def reset(self) -> None:
        """Clear all window state (useful between test runs)."""
        self._windows.clear()

    def window_sizes(self) -> dict[str, int]:
        """Return current window sizes per template_id (for debugging)."""
        return {tid: len(dq) for tid, dq in self._windows.items()}

_default_counter: FrequencyCounter | None = None


def get_default_counter(window_seconds: int = 60) -> FrequencyCounter:
    """
    Return the module-level shared FrequencyCounter, creating it if needed.

    Args:
        window_seconds: Only used on first call (when counter is created).
    """
    global _default_counter
    if _default_counter is None:
        _default_counter = FrequencyCounter(window_seconds=window_seconds)
    return _default_counter


def compute_frequency(
    record: LogRecord,
    counter: FrequencyCounter | None = None,
    window_seconds: int = 60,
) -> int:
 
    if counter is None:
        counter = get_default_counter(window_seconds)
    return counter.update(record)



if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    counter = FrequencyCounter(window_seconds=60)
    print("=== Burst detection: 5 identical events ===")
    for i in range(5):
        r = LogRecord(
            timestamp="Mar 12 10:00:00",
            template_id="SNMP_AUTH_FAILURE",
            host="sw-core-01", service="SNMP",
            log_level="ERROR", event_type="SNMP", event_action="AUTH_FAILURE",
            message="", raw_line="",
        )
        freq = counter.update(r)
        print(f"  event {i+1}: frequency = {freq}  (expected {i})")
        assert freq == i, f"Expected {i}, got {freq}"
    print("PASS\n")

    # Different template_id must have independent window
    print("=== Different template_id has independent counter ===")
    r2 = LogRecord(
        timestamp="Mar 12 10:00:00",
        template_id="PORT_PORT_DOWN",
        host="sw-access-02", service="PORT",
        log_level="WARN", event_type="PORT", event_action="PORT_DOWN",
        message="", raw_line="",
    )
    counter.update(r2)
    assert r2.frequency == 0, f"Expected 0 for new template_id, got {r2.frequency}"
    print(f"  PORT_PORT_DOWN frequency = {r2.frequency}  (expected 0)")
    print("PASS\n")

    # Verify window sizes
    sizes = counter.window_sizes()
    print(f"=== Window state ===")
    for tid, size in sizes.items():
        print(f"  {tid}: {size} record(s) in window")
    assert sizes["SNMP_AUTH_FAILURE"] == 5
    assert sizes["PORT_PORT_DOWN"]    == 1
    print("PASS")