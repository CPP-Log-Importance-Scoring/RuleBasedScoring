import math
import yaml
import os
import logging
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

LABEL_IGNORE   = "ignore"
LABEL_LOW      = "low"
LABEL_MEDIUM   = "medium"
LABEL_CRITICAL = "critical"
LABEL_HIGH = "high" 

_DEFAULT_CONFIG: dict[str, float] = {
    "alpha": 0.60,
    "beta":  0.25,
    "gamma": 0.15,

    "threshold_low":      0.5,   # was 0.8
    "threshold_medium":   1.0,
        "threshold_high": 1.6,# was 1.6
    "threshold_critical": 2.0   # was 2.5
}

_config_cache: dict[str, dict[str, float]] = {}


def _load_config(config_path: str) -> dict[str, float]:
    if not os.path.exists(config_path):
        logger.warning(
            "weights.yaml not found at '%s' — using defaults. "
            "Active thresholds: low=%.1f medium=%.1f critical=%.1f",
            config_path,
            _DEFAULT_CONFIG["threshold_low"],
            _DEFAULT_CONFIG["threshold_medium"],
            _DEFAULT_CONFIG["threshold_high"],
            _DEFAULT_CONFIG["threshold_critical"],
        )
        return _DEFAULT_CONFIG.copy()

    try:
        with open(config_path, "r") as fh:
            cfg = yaml.safe_load(fh)

        loaded = {key: float(cfg.get(key, default))
                  for key, default in _DEFAULT_CONFIG.items()}

        logger.info(
            "importance_score config loaded: low=%.2f medium=%.2f critical=%.2f",
            loaded["threshold_low"],
            loaded["threshold_medium"],
            loaded["threshold_critical"],
        )
        return loaded

    except Exception as exc:
        logger.error("Failed to load config — using defaults: %s", exc)
        return _DEFAULT_CONFIG.copy()


def get_label(score, cfg):
    if score >= cfg["threshold_critical"]:
        return LABEL_CRITICAL
    if score >= cfg["threshold_high"]:    
        return LABEL_HIGH
    if score >= cfg["threshold_medium"]:
        return LABEL_MEDIUM
    if score >= cfg["threshold_low"]:
        return LABEL_LOW
    return LABEL_IGNORE


def compute_importance_score(
    record: LogRecord,
    config_path: str = "config/weights.yaml",
) -> tuple[float, str]:

    if config_path not in _config_cache:
        _config_cache[config_path] = _load_config(config_path)

    cfg = _config_cache[config_path]

    freq_term = min(math.log(record.frequency + 1), 3.0)

    importance_score = (
        (cfg["alpha"] * record.event_weight)
        + (cfg["beta"]  * freq_term)
        + (cfg["gamma"] * record.correlation_score)
    )

    label = get_label(importance_score, cfg)

    record.importance_score = round(importance_score, 4)
    record.label = label

    logger.info(
        "importance_score=%.4f  label=%s  "
        "[ew=%.2f] [freq=%.2f] [corr=%.2f] "
        "host=%s  %s/%s",
        importance_score, label,
        record.event_weight,
        freq_term,
        record.correlation_score,
        record.host,
        record.event_type,
        record.event_action,
    )

    return importance_score, label


def score_batch(
    records: list[LogRecord],
    config_path: str = "config/weights.yaml",
) -> list[LogRecord]:
    for record in records:
        compute_importance_score(record, config_path=config_path)
    return records