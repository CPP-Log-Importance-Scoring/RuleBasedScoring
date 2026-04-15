# correlation/correlation_engine.py

import logging
from datetime import datetime
from collections import defaultdict

from parsing.schema import LogRecord
from correlation.clustering_utils import (
    bucket_timestamp,
    make_cluster_key,
    make_correlation_id,
    compute_correlation_score,
    WINDOW_SECONDS,
)

logger = logging.getLogger(__name__)


class CorrelationEngine:

    def __init__(self, window_seconds: int = WINDOW_SECONDS):
        self.window_seconds = window_seconds

        # cluster_key → list of LogRecord (all members of this cluster)
        self._clusters: dict[str, list[LogRecord]] = defaultdict(list)

        # cluster_key → sequential counter (for correlation_id generation)
        self._seq_counters: dict[str, int] = defaultdict(int)

    def process_record(self, record: LogRecord) -> LogRecord:
        """
        Assign correlation_id and correlation_score to a single record.

        In streaming mode, scores reflect the cluster size AT THE TIME this
        record arrived — earlier records in the same cluster will have lower
        scores.  Use correlate_batch() when you have all records upfront.

        Mutates record in-place and returns it.
        """
        cluster_key = self._get_cluster_key(record)

        # Register this record in its cluster
        self._clusters[cluster_key].append(record)
        self._seq_counters[cluster_key] += 1
        seq = self._seq_counters[cluster_key]

        cluster_size = len(self._clusters[cluster_key])
        score = compute_correlation_score(cluster_size)
        corr_id = make_correlation_id(cluster_key, seq)

        record.correlation_id = corr_id
        record.correlation_score = score

        logger.debug(
            "corr_id=%s  score=%.4f  cluster_size=%d  key=%s",
            corr_id, score, cluster_size, cluster_key,
        )
        return record

    def correlate_batch(self, records: list[LogRecord]) -> list[LogRecord]:
        """
        Two-pass batch correlation — more accurate than streaming for offline data.

        Pass 1: Assign cluster memberships (build _clusters dict).
        Pass 2: Re-score all records with the final cluster size.

        This ensures every record in a 7-event cluster gets score=log2(8)≈3.0,
        rather than the first record getting log2(2)=1.0 because it arrived
        before the others.

        Mutates all records in-place and returns the list.
        """
        # Reset state for a clean batch run
        self.reset()

        # Pass 1 — build clusters
        for record in records:
            cluster_key = self._get_cluster_key(record)
            self._clusters[cluster_key].append(record)

        # Pass 2 — assign final scores now that cluster sizes are known
        seq_counters: dict[str, int] = defaultdict(int)
        for record in records:
            cluster_key = self._get_cluster_key(record)
            cluster_size = len(self._clusters[cluster_key])
            seq_counters[cluster_key] += 1
            seq = seq_counters[cluster_key]

            score = compute_correlation_score(cluster_size)
            corr_id = make_correlation_id(cluster_key, seq)

            record.correlation_id = corr_id
            record.correlation_score = score

            logger.debug(
                "batch  corr_id=%s  score=%.4f  cluster_size=%d  host=%s  %s/%s",
                corr_id, score, cluster_size,
                record.host, record.event_type, record.event_action,
            )

        logger.info(
            "correlate_batch: %d records → %d clusters",
            len(records), len(self._clusters),
        )
        return records

    def reset(self) -> None:
        """Clear all cluster state. Call between independent batch runs."""
        self._clusters.clear()
        self._seq_counters.clear()

    def get_cluster_summary(self) -> list[dict]:
        """
        Return a human-readable summary of all current clusters.
        Useful for logging and storage.py.

        Returns list of dicts: {cluster_key, size, score, members: [host, ...]}
        """
        summary = []
        for key, members in self._clusters.items():
            summary.append({
                "cluster_key": key,
                "size": len(members),
                "score": compute_correlation_score(len(members)),
                "members": [
                    {
                        "host": r.host,
                        "service": r.service,
                        "event_action": r.event_action,
                        "timestamp": r.timestamp,
                        "correlation_id": r.correlation_id,
                    }
                    for r in members
                ],
            })
        return summary

    def _get_cluster_key(self, record: LogRecord) -> str:
        """
        Derive the cluster key for a record.

        Handles both string timestamps (from syslog parser) and datetime objects.
        Falls back to bucket=0 if timestamp is unparseable — record still gets
        correlated by host+event, just without time bucketing.
        """
        bucket = self._parse_bucket(record.timestamp)
        return make_cluster_key(
            host=record.host,
            event_type=record.event_type,
            event_action=record.event_action,
            bucket=bucket,
        )

    def _parse_bucket(self, timestamp: str | datetime) -> int:
        """Parse timestamp → epoch bucket, with graceful fallback."""
        if isinstance(timestamp, datetime):
            return bucket_timestamp(timestamp, self.window_seconds)
        try:
            # Syslog format: "Mar 12 10:00:00" — no year, so inject current year
            from datetime import date
            ts = datetime.strptime(
                f"{date.today().year} {timestamp}",
                "%Y %b %d %H:%M:%S",
            )
            return bucket_timestamp(ts, self.window_seconds)
        except (ValueError, TypeError) as exc:
            logger.warning("Could not parse timestamp %r: %s — bucket=0", timestamp, exc)
            return 0


# ---------------------------------------------------------------------------
# Module-level engine for streaming use (process_record convenience wrapper)
# ---------------------------------------------------------------------------

_default_engine = CorrelationEngine()


# ---------------------------------------------------------------------------
# FIX: correlate_batch now returns (records, cluster_summary) as a tuple
#
# BEFORE (broken):
#   engine = CorrelationEngine(...)
#   return engine.correlate_batch(records)       ← engine discarded here
#                                                  get_cluster_summary() forever lost
#
# AFTER (fixed):
#   engine = CorrelationEngine(...)
#   engine.correlate_batch(records)
#   return records, engine.get_cluster_summary() ← summary captured before engine dies
#
# Callers that don't need the summary can ignore it:
#   records, _ = correlate_batch(records)
# main.py uses CorrelationEngine directly instead, which is the cleaner pattern.
# ---------------------------------------------------------------------------

def correlate_batch(
    records: list[LogRecord],
    window_seconds: int = WINDOW_SECONDS,
) -> tuple[list[LogRecord], list[dict]]:
    """
    Convenience wrapper — creates a fresh engine and runs a two-pass batch.
    Safe to call multiple times; each call uses a clean engine.

    Returns:
        (records, cluster_summary) — records mutated in-place with correlation
        fields set; cluster_summary is a list of dicts from get_cluster_summary().
    """
    engine = CorrelationEngine(window_seconds=window_seconds)
    engine.correlate_batch(records)
    return records, engine.get_cluster_summary()


def process_record(record: LogRecord) -> LogRecord:
    """
    Convenience wrapper using the module-level default engine.
    Use for live streaming where state must persist across calls.
    """
    return _default_engine.process_record(record)



# Self-test  —  python -m correlation.correlation_engine
# 
if __name__ == "__main__":
    import sys
    import math
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    print("=== Batch correlation: 5 AUTH_FAILURE from same host ===")
    records = [
        LogRecord(
            timestamp=f"Mar 12 10:0{i}:00", raw_line="",
            log_level="ERROR", host="sw-core-01",
            service="SNMP", event_type="SNMP", event_action="AUTH_FAILURE",
            message="Authentication failure",
            template_id="SNMP_AUTH_FAILURE",
            severity_score=3.0, event_type_score=3.0,
            anomaly_score=1.0, event_weight=2.6,
            frequency=i + 1,
        )
        for i in range(5)
    ]

    engine = CorrelationEngine()
    engine.correlate_batch(records)

    for r in records:
        print(f"  {r.timestamp}  corr_id={r.correlation_id}  score={r.correlation_score}")

    expected_score = round(min(math.log2(6), 3.0), 4)
    assert all(r.correlation_score == expected_score for r in records), \
        "All records in same cluster should have same score after batch"
    print(f"All scores = {expected_score}  PASS\n")

    print("=== Isolation: different hosts → different clusters ===")
    r_a = LogRecord(
        timestamp="Mar 12 10:00:00", raw_line="", log_level="ERROR",
        host="sw-core-01", service="SNMP", event_type="SNMP",
        event_action="AUTH_FAILURE", message="", template_id="",
        severity_score=3.0, event_type_score=3.0, anomaly_score=0.0,
        event_weight=2.6, frequency=1,
    )
    r_b = LogRecord(
        timestamp="Mar 12 10:00:30", raw_line="", log_level="ERROR",
        host="sw-access-02", service="SNMP", event_type="SNMP",
        event_action="AUTH_FAILURE", message="", template_id="",
        severity_score=3.0, event_type_score=3.0, anomaly_score=0.0,
        event_weight=2.6, frequency=1,
    )
    engine2 = CorrelationEngine()
    engine2.correlate_batch([r_a, r_b])
    assert r_a.correlation_id != r_b.correlation_id, "Different hosts → different clusters"
    assert r_a.correlation_score == round(math.log2(2), 4)
    assert r_b.correlation_score == round(math.log2(2), 4)
    print(f"  sw-core-01   → {r_a.correlation_id}  score={r_a.correlation_score}")
    print(f"  sw-access-02 → {r_b.correlation_id}  score={r_b.correlation_score}")
    print("PASS\n")

    print("=== Score saturation at cluster_size=7 ===")
    from correlation.clustering_utils import compute_correlation_score
    assert compute_correlation_score(7) == 3.0
    assert compute_correlation_score(50) == 3.0
    print("Score saturates at 3.0  PASS\n")

    # FIX TEST: verify the convenience wrapper now returns a tuple
    print("=== correlate_batch() returns (records, summary) tuple ===")
    result = correlate_batch(records)
    assert isinstance(result, tuple) and len(result) == 2, \
        "correlate_batch must return (records, cluster_summary)"
    returned_records, summary = result
    assert len(summary) >= 1, "Summary should have at least one cluster"
    assert "cluster_key" in summary[0]
    assert "members" in summary[0]
    print(f"  Returned {len(summary)} cluster(s) in summary")
    print("PASS")