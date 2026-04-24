import logging
import yaml
import os
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

# Default weights (used if config file missing or invalid)
_DEFAULT_WEIGHTS = {
    "w1": 0.5,
    "w2": 0.3,
    "w3": 0.2,
}

# Cache to avoid reloading config repeatedly
_weights_cache: dict[str, dict[str, float]] = {}


def _load_weights(config_path: str) -> dict[str, float]:
    """
    Load weights from YAML config file.
    Falls back to defaults if file missing or invalid.
    """
    if not os.path.exists(config_path):
        logger.warning("Weights config not found. Using defaults.")
        return _DEFAULT_WEIGHTS.copy()

    try:
        with open(config_path, "r") as fh:
            cfg = yaml.safe_load(fh)

        return {
            "w1": float(cfg.get("w1", _DEFAULT_WEIGHTS["w1"])),
            "w2": float(cfg.get("w2", _DEFAULT_WEIGHTS["w2"])),
            "w3": float(cfg.get("w3", _DEFAULT_WEIGHTS["w3"])),
        }

    except Exception as e:
        logger.warning("Error loading config: %s. Using defaults.", e)
        return _DEFAULT_WEIGHTS.copy()


def compute_event_weight(
    record: LogRecord,
    config_path: str = "config/weights.yaml"
) -> float:
    """
    Compute event_weight = w1*severity + w2*event_type + w3*anomaly
    """

    # ── Guard: check feature_service actually ran ────────────────────────
    # We check log_level (always set by parse_logs) instead of checking
    # severity_score/event_type_score == 0.0, because 0.0 is a VALID score
    # for noise events like "periodic health check". The old guard was
    # incorrectly treating valid low-scored events as pipeline errors.
    if not record.log_level:
        raise ValueError(
            f"Feature computation missing before event_weight — "
            f"log_level is empty for host={record.host} msg={record.message!r}"
        )

    # ── Guard: anomaly_score must be binary ──────────────────────────────
    # Snap float precision issues (e.g. 0.9999999) before checking.
    record.anomaly_score = round(record.anomaly_score)
    if record.anomaly_score not in (0.0, 1.0):
        raise ValueError(
            f"Invalid anomaly_score={record.anomaly_score} "
            f"for host={record.host} service={record.service}"
        )

    #  Load weights 
    if config_path not in _weights_cache:
        _weights_cache[config_path] = _load_weights(config_path)

    w = _weights_cache[config_path]

    #  Compute 
    event_weight = (
        w["w1"] * record.severity_score +
        w["w2"] * record.event_type_score +
        w["w3"] * record.anomaly_score
    )

    record.event_weight = round(event_weight, 4)

    logger.info(
        "event_weight=%.4f (sev=%.1f etype=%.1f anom=%.1f)",
        record.event_weight,
        record.severity_score,
        record.event_type_score,
        record.anomaly_score,
    )

    return record.event_weight


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    r = LogRecord(
        log_level="ERROR",
        event_type="OSPF",
        event_action="NEIGHBOR_DOWN",
        severity_score=3.0,
        event_type_score=4.0,
        anomaly_score=1.0,
    )

    result = compute_event_weight(r)
    print(f"Computed event_weight: {result}")