from parsing.schema import LogRecord
from parsing.drain_parser import drain_parser


def assign_template_id(record: LogRecord) -> LogRecord:
    """
    Use Drain to extract log templates dynamically.

    This replaces rule-based template extraction.
    """

    # Parse log message using Drain
    cluster_id, template = drain_parser.parse(record.message)

    # Assign template ID (used across pipeline)
    record.template_id = f"TEMPLATE_{cluster_id}"

    # Store normalized template (helps debugging & grouping)
    record.message = template

  
    record.event_action = f"TEMPLATE_{cluster_id}"

    return record


def assign_template_ids_batch(records: list[LogRecord]) -> list[LogRecord]:
    """
    Apply Drain-based template extraction to all records.
    """
    for record in records:
        assign_template_id(record)
    return records