from datetime import date, datetime
from dataclasses import dataclass

from parsing.schema import LogRecord


@dataclass
class IncidentGroup:
    representative: LogRecord
    members: list[LogRecord]
    first_seen: str
    last_seen: str
    grouping_reason: str
    correlation_ids: list[str]


def _parse_timestamp(timestamp: str) -> datetime:
    return datetime.strptime(
        f"{date.today().year} {timestamp}",
        "%Y %b %d %H:%M:%S",
    )


def _incident_key(record: LogRecord) -> str:
    return "|".join((record.host, record.event_type, record.event_action))


def collapse_incidents(
    records: list[LogRecord],
    window_seconds: int,
) -> list[LogRecord]:
    """
    Collapse repeated records from the same host/event into one incident.

    Records are grouped when consecutive events with the same host, event_type,
    and event_action occur within the configured correlation window. The highest
    scoring record is kept as the representative incident.
    """
    return [
        incident.representative
        for incident in build_incident_groups(records, window_seconds)
    ]


def build_incident_groups(
    records: list[LogRecord],
    window_seconds: int,
) -> list[IncidentGroup]:
    groups: dict[str, list[LogRecord]] = {}
    for record in records:
        groups.setdefault(_incident_key(record), []).append(record)

    incidents: list[IncidentGroup] = []

    for group_records in groups.values():
        group_records.sort(key=lambda record: _parse_timestamp(record.timestamp))

        current_group: list[LogRecord] = []
        previous_ts: datetime | None = None

        for record in group_records:
            current_ts = _parse_timestamp(record.timestamp)

            if (
                current_group
                and previous_ts is not None
                and (current_ts - previous_ts).total_seconds() > window_seconds
            ):
                incidents.append(_make_incident(current_group, window_seconds))
                current_group = []

            current_group.append(record)
            previous_ts = current_ts

        if current_group:
            incidents.append(_make_incident(current_group, window_seconds))

    return sorted(
        incidents,
        key=lambda incident: incident.representative.importance_score,
        reverse=True,
    )


def _best_record(records: list[LogRecord]) -> LogRecord:
    return max(records, key=lambda record: record.importance_score)


def _make_incident(records: list[LogRecord], window_seconds: int) -> IncidentGroup:
    representative = _best_record(records)
    first_seen = records[0].timestamp
    last_seen = records[-1].timestamp
    correlation_ids = sorted({
        record.correlation_id
        for record in records
        if record.correlation_id
    })
    reason = (
        "same host, event_type, and event_action; consecutive matching logs "
        f"are within {window_seconds} seconds"
    )

    return IncidentGroup(
        representative=representative,
        members=list(records),
        first_seen=first_seen,
        last_seen=last_seen,
        grouping_reason=reason,
        correlation_ids=correlation_ids,
    )
