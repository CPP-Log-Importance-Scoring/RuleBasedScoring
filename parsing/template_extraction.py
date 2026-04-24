from parsing.schema import LogRecord
from parsing.drain_parser import drain_parser


def assign_template_id(record: LogRecord) -> LogRecord:
    """
    Use Drain to extract log templates dynamically.

    Assigns template_id for grouping/clustering purposes only.
    Does NOT overwrite event_action — that must stay as the parsed
    semantic action (e.g. 'privilege escalation attempt') so that
    event_type_score lookups in feature_service work correctly.
    """

    cluster_id, template = drain_parser.parse(record.message)

    # Template ID used for correlation clustering and grouping
    record.template_id = f"TEMPLATE_{cluster_id}"

    # Normalized template stored for debugging/display
    record.message = template


    return record


def assign_template_ids_batch(records: list[LogRecord]) -> list[LogRecord]:
    """
    Apply Drain-based template extraction to all records.
    """
    for record in records:
        assign_template_id(record)
    return records