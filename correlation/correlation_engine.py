import logging
from datetime import datetime
from collections import defaultdict

from parsing.schema import LogRecord
from correlation.clustering_utils import (
    bucket_timestamp,
    make_correlation_id,
    compute_correlation_score,
    WINDOW_SECONDS,
)

logger = logging.getLogger(__name__)



#  Event Families (expandable)


EVENT_FAMILIES = {
    "NETWORK_DOWN": {
        ("PORT", "PORT_DOWN"),
        ("OSPF", "NEIGHBOR_DOWN"),
    },
    "NETWORK_UP": {
        ("PORT", "PORT_UP"),
    },
    "SECURITY": {
        ("SECURITY", "PORT_SCAN"),
        ("SECURITY", "MAC_BLOCKED"),
    },
    "AUTH": {
        ("SNMP", "AUTH_FAILURE"),
    },
    "CONFIG": {
        ("CONFIG", "CONFIG_CHANGE"),
    },
}



#  Correlation Engine


class CorrelationEngine:

    def __init__(self, window_seconds: int = WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self._clusters: dict[str, list[LogRecord]] = defaultdict(list)

    # ─────────────────────────────────────────────────────────
    # Batch correlation
    # ─────────────────────────────────────────────────────────
    def correlate_batch(self, records: list[LogRecord]) -> list[LogRecord]:
        self._clusters.clear()

        # First pass: group into clusters
        for record in records:
            key = self._get_cluster_key(record)
            self._clusters[key].append(record)

        # Second pass: assign correlation_id + score
        for record in records:
            key = self._get_cluster_key(record)

            cluster_size = len(self._clusters[key])

            record.correlation_id = make_correlation_id(key)
            record.correlation_score = compute_correlation_score(cluster_size)

        logger.info(
            "correlate_batch: %d records → %d clusters",
            len(records),
            len(self._clusters),
        )

        return records

    # ─────────────────────────────────────────────────────────
    # Cluster Key Logic (CRITICAL FIX)
    # ─────────────────────────────────────────────────────────
    def _get_cluster_key(self, record: LogRecord) -> str:
        bucket = self._parse_bucket(record.timestamp)
        family = self._get_event_family(record)

        #  FIX: add granularity to avoid mega-clusters
        return (
            f"{family}|"
            f"{record.host}|"
            f"{record.event_type}|"
            f"{record.event_action}|"
            f"{bucket}"
        )

    # ─────────────────────────────────────────────────────────
    # Event Family Mapping
    # ─────────────────────────────────────────────────────────
    def _get_event_family(self, record: LogRecord) -> str:
        key = (record.event_type, record.event_action)

        for family, members in EVENT_FAMILIES.items():
            if key in members:
                return family

        # fallback: still useful
        return record.event_type or "UNKNOWN"

    # ─────────────────────────────────────────────────────────
    # Time Bucketing
    # ─────────────────────────────────────────────────────────
    def _parse_bucket(self, timestamp: str | datetime) -> int:
        if isinstance(timestamp, datetime):
            return bucket_timestamp(timestamp, self.window_seconds)

        try:
            from datetime import date

            ts = datetime.strptime(
                f"{date.today().year} {timestamp}",
                "%Y %b %d %H:%M:%S",
            )
            return bucket_timestamp(ts, self.window_seconds)

        except Exception:
            return 0

    # ─────────────────────────────────────────────────────────
    # Cluster Summary (FIXED)
    # ─────────────────────────────────────────────────────────
    def get_cluster_summary(self) -> list[dict]:
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

    # ─────────────────────────────────────────────────────────
    # Reset (optional utility)
    # ─────────────────────────────────────────────────────────
    def reset(self):
        self._clusters.clear()
