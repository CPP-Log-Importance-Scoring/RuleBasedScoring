"""
scoring/scoring_utils.py
Utility functions for working with scored LogRecords.


This module answers questions *about* a set of already-scored records:
    - What is the label distribution?
    - What is the noise suppression ratio?
    - Which records are critical?
    - Pretty-print a single record's scoring breakdown.
"""

import logging
from collections import Counter
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

# ── Label constants ───────────────────────────────────────
LABEL_IGNORE   = "ignore"
LABEL_LOW      = "low"
LABEL_MEDIUM   = "medium"
LABEL_HIGH     = "high"      
LABEL_CRITICAL = "critical"

ALL_LABELS = [
    LABEL_IGNORE,
    LABEL_LOW,
    LABEL_MEDIUM,
    LABEL_HIGH,     # ✅ INCLUDED
    LABEL_CRITICAL
]


# Label distribution

def label_distribution(records: list[LogRecord]) -> dict[str, int]:
    counts: Counter = Counter(r.label for r in records)
    return {label: counts.get(label, 0) for label in ALL_LABELS}


def noise_suppression_ratio(records: list[LogRecord]) -> float:
    if not records:
        return 0.0

    suppressed = sum(
        1 for r in records
        if r.label in (LABEL_IGNORE, LABEL_LOW)
    )
    return suppressed / len(records)


def critical_records(records: list[LogRecord]) -> list[LogRecord]:
    return [r for r in records if r.label == LABEL_CRITICAL]


def actionable_records(records: list[LogRecord]) -> list[LogRecord]:
    """
    Medium + High + Critical require attention
    """
    return [
        r for r in records
        if r.label in (LABEL_MEDIUM, LABEL_HIGH, LABEL_CRITICAL)
    ]



# Pretty printing

def format_record(record: LogRecord, verbose: bool = False) -> str:
    label_upper = record.label.upper() if record.label else "UNSCORED"
    corr = record.correlation_id or "none"

    if not verbose:
        return (
            f"[{label_upper:8s}] score={record.importance_score:.3f}  "
            f"{record.timestamp}  {record.host}  {record.service}  "
            f"{record.event_type}/{record.event_action}  corr={corr}"
        )

    lines = [
        f"{'─'*60}",
        f"  timestamp    : {record.timestamp}",
        f"  host         : {record.host}",
        f"  service      : {record.service}",
        f"  log_level    : {record.log_level}",
        f"  event        : {record.event_type}/{record.event_action}",
        f"  template_id  : {record.template_id}",
        f"  message      : {record.message[:80]}{'…' if len(record.message) > 80 else ''}",
        f"  ── features ─────────────────────────────────────────",
        f"  severity_score   : {record.severity_score:.1f}",
        f"  event_type_score : {record.event_type_score:.1f}",
        f"  anomaly_score    : {record.anomaly_score:.1f}",
        f"  frequency        : {record.frequency}",
        f"  ── scoring ──────────────────────────────────────────",
        f"  event_weight     : {record.event_weight:.4f}",
        f"  correlation_id   : {record.correlation_id or 'none'}",
        f"  correlation_score: {record.correlation_score:.4f}",
        f"  importance_score : {record.importance_score:.4f}",
        f"  label            : {label_upper}",
        f"{'─'*60}",
    ]
    return "\n".join(lines)



# Summary printing

def print_summary(records: list[LogRecord]) -> None:
    dist  = label_distribution(records)
    total = len(records)
    nsr   = noise_suppression_ratio(records)

    print(f"\n{'═'*50}")
    print(f"  Scoring summary  ({total} records)")
    print(f"{'═'*50}")

    for label in ALL_LABELS:
        count = dist[label]
        pct   = (count / total * 100) if total else 0
        bar   = "█" * int(pct / 5)
        print(f"  {label:8s}  {count:6d}  ({pct:5.1f}%)  {bar}")

    print(f"{'─'*50}")
    print(f"  Noise suppression ratio : {nsr:.1%}")
    print(f"  Actionable (med+high+crit): {len(actionable_records(records))}")
    print(f"  Critical                : {len(critical_records(records))}")
    print(f"{'═'*50}\n")


# Self-test

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    def _make(label: str, importance_score: float = 1.0) -> LogRecord:
        r = LogRecord(
            timestamp="Mar 12 10:00:00", raw_line="",
            log_level="INFO", host="sw-core-01", service="SNMP",
            event_type="SNMP", event_action="AUTH_FAILURE", message="",
        )
        r.label = label
        r.importance_score = importance_score
        r.event_weight = 1.0
        r.severity_score = 1.0
        r.event_type_score = 1.0
        return r

    records = (
        [_make(LABEL_IGNORE,   0.2)] * 50 +
        [_make(LABEL_LOW,      0.7)] * 30 +
        [_make(LABEL_MEDIUM,   1.2)] * 20 +
        [_make(LABEL_HIGH,     1.8)] * 10 +
        [_make(LABEL_CRITICAL, 2.8)] * 5
    )

    print_summary(records)

    print("Sample record:")
    r = records[-1]
    r.template_id = "SNMP_AUTH_FAILURE"
    r.correlation_id = "corr-001"
    r.correlation_score = 2.0
    r.frequency = 5
    r.anomaly_score = 1.0
    r.event_weight = 2.6
    r.importance_score = 2.8
    r.label = LABEL_CRITICAL

    print(format_record(r))