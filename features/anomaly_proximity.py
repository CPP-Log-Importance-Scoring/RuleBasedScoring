import os
import csv
import logging
from pathlib import Path
from parsing.schema import LogRecord
from features.frequency import _parse_timestamp   # reuse the same parser

logger = logging.getLogger(__name__)

# Default proximity window in seconds (from config, defaulting here)
DEFAULT_DELTA_SECONDS: int = 30



class AnomalyIndex:
    """
    Preloads counter anomaly timestamps from a CSV file and answers
    proximity queries efficiently.

    One instance should be created at pipeline startup and reused.

    Usage:
        index = AnomalyIndex.from_csv("data/counters.csv")
        for record in records:
            anomaly_proximity.compute(record, index)
    """

    def __init__(self, anomaly_timestamps: list[float], delta_seconds: int = DEFAULT_DELTA_SECONDS):
        """
        Args:
            anomaly_timestamps: Sorted list of Unix timestamps where
                                counter anomalies were detected.
            delta_seconds:      Proximity window (±delta).
        """
        self.timestamps  = sorted(anomaly_timestamps)
        self.delta       = delta_seconds

    @classmethod
    def from_csv(
        cls,
        csv_path: str | Path,
        delta_seconds: int = DEFAULT_DELTA_SECONDS,
    ) -> "AnomalyIndex":
   
        path = Path(csv_path)
        if not path.exists():
            logger.warning(
                "Counter CSV not found at %s — anomaly_score will always be 0.0. "
                "Create data/counters.csv to enable cross-signal correlation.",
                csv_path,
            )
            return cls([], delta_seconds)

        timestamps: list[float] = []
        try:
            with path.open("r", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    if row.get("is_anomaly", "0").strip() == "1":
                        ts = _parse_timestamp(row.get("timestamp", ""))
                        timestamps.append(ts)
        except Exception as exc:
            logger.error("Failed to read %s: %s — anomaly_score will be 0.0", csv_path, exc)
            return cls([], delta_seconds)

        logger.info(
            "AnomalyIndex loaded %d anomaly timestamps from %s (±%ds window)",
            len(timestamps), csv_path, delta_seconds,
        )
        return cls(timestamps, delta_seconds)

    @classmethod
    def empty(cls, delta_seconds: int = DEFAULT_DELTA_SECONDS) -> "AnomalyIndex":
        """Return an empty index (anomaly_score always 0.0). Useful in tests."""
        return cls([], delta_seconds)

    def is_near_anomaly(self, ts: float) -> bool:
    
        if not self.timestamps:
            return False

        # Binary search for the insertion point of ts
        lo, hi = 0, len(self.timestamps) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.timestamps[mid] < ts:
                lo = mid + 1
            else:
                hi = mid - 1

        # Check neighbours around the insertion point
        for idx in (lo - 1, lo):
            if 0 <= idx < len(self.timestamps):
                if abs(self.timestamps[idx] - ts) <= self.delta:
                    return True
        return False



def compute_anomaly_score(
    record: LogRecord,
    index: AnomalyIndex,
) -> float:

    ts = _parse_timestamp(record.timestamp)

    proximity_score = 1.0 if index.is_near_anomaly(ts) else 0.0

    record.anomaly_score = max(record.anomaly_score, proximity_score)

    logger.debug(
        "anomaly_score=%.1f  timestamp=%s  host=%s  service=%s",
        record.anomaly_score, record.timestamp, record.host, record.service,
    )

    return record.anomaly_score


def compute_anomaly_scores_batch(
    records: list[LogRecord],
    index: AnomalyIndex,
) -> list[LogRecord]:
    """Apply compute_anomaly_score to a list of records. Returns the same list."""
    for record in records:
        compute_anomaly_score(record, index)
    return records



# Self-test  —  python -m features.anomaly_proximity

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    # Build index with a known anomaly at "Mar 12 10:00:05"
    anomaly_ts = _parse_timestamp("Mar 12 10:00:05")
    index = AnomalyIndex([anomaly_ts], delta_seconds=30)

    print("=== Proximity detection (±30s window) ===")
    test_cases = [
        # (timestamp_str,      expected_score, note)
        ("Mar 12 10:00:05",   1.0, "exact hit"),
        ("Mar 12 10:00:00",   1.0, "5s before — within window"),
        ("Mar 12 10:00:34",   1.0, "29s after — within window"),
        ("Mar 12 10:00:36",   0.0, "31s after — outside window"),
        ("Mar 12 09:59:34",   0.0, "31s before — outside window"),
    ]
    all_pass = True
    for ts_str, expected, note in test_cases:
        r = LogRecord(
            timestamp=ts_str, raw_line="", host="sw-core-01",
            log_level="WARN", service="PORT", event_type="PORT",
            event_action="PORT_DOWN", message="",
        )
        got = compute_anomaly_score(r, index)
        status = "PASS" if got == expected else f"FAIL (got {got})"
        print(f"  {ts_str}  score={got:.1f}  [{status}]  {note}")
        if got != expected:
            all_pass = False

    print()
    print("=== Empty index always returns 0.0 ===")
    empty_index = AnomalyIndex.empty()
    r2 = LogRecord(timestamp="Mar 12 10:00:05", raw_line="", host="",
                   log_level="CRITICAL", service="OSPF",
                   event_type="OSPF", event_action="NEIGHBOR_DOWN", message="")
    compute_anomaly_score(r2, empty_index)
    assert r2.anomaly_score == 0.0
    print(f"  anomaly_score = {r2.anomaly_score}  PASS")

    print()
    print("All tests PASS" if all_pass else "SOME TESTS FAILED")