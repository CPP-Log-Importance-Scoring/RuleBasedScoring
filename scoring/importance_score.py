import yaml
import os
import logging
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

# ── Labels ──────────────────────────────────────────────────────────────

LABEL_IGNORE   = "ignore"
LABEL_LOW      = "low"
LABEL_MEDIUM   = "medium"
LABEL_HIGH     = "high"
LABEL_CRITICAL = "critical"


# ── Default Config ──────────────────────────────────────────────────────

_DEFAULT_CONFIG: dict[str, float] = {
    "alpha": 0.6,   # event weight
    "beta":  0.1,   # novelty bonus
    "gamma": 0.35,  # correlation boost (increased)

    "threshold_low":      0.5,
    "threshold_medium":   1.0,
    "threshold_high":     1.6,
    "threshold_critical": 2.0,
}

_config_cache: dict[str, dict[str, float]] = {}


# ── Config Loader ───────────────────────────────────────────────────────

def _load_config(config_path: str) -> dict[str, float]:
    if not os.path.exists(config_path):
        logger.warning("weights.yaml not found — using defaults")
        return _DEFAULT_CONFIG.copy()

    try:
        with open(config_path, "r") as fh:
            cfg = yaml.safe_load(fh)

        return {
            key: float(cfg.get(key, default))
            for key, default in _DEFAULT_CONFIG.items()
        }

    except Exception as exc:
        logger.error("Failed to load config — using defaults: %s", exc)
        return _DEFAULT_CONFIG.copy()


# ── Label Assignment ────────────────────────────────────────────────────

def get_label(score: float, cfg: dict[str, float]) -> str:
    if score >= cfg["threshold_critical"]:
        return LABEL_CRITICAL
    if score >= cfg["threshold_high"]:
        return LABEL_HIGH
    if score >= cfg["threshold_medium"]:
        return LABEL_MEDIUM
    if score >= cfg["threshold_low"]:
        return LABEL_LOW
    return LABEL_IGNORE


# ── Core Scoring Function ───────────────────────────────────────────────

def compute_importance_score(
    record: LogRecord,
    config_path: str = "config/weights.yaml",
) -> tuple[float, str]:

    if config_path not in _config_cache:
        _config_cache[config_path] = _load_config(config_path)

    cfg = _config_cache[config_path]

    # ─────────────────────────────────────────
    # 🔥 FIX 1: soften novelty penalty
    # ─────────────────────────────────────────
    novelty_factor = 0.5 + 0.5 * record.novelty_score

    weighted_event = (
        cfg["alpha"]
        * record.event_weight
        * record.event_type_confidence
        * novelty_factor
    )

    # ─────────────────────────────────────────
    # 🔥 FIX 2: small additive novelty bonus
    # ─────────────────────────────────────────
    novelty_bonus = cfg["beta"] * record.novelty_score

    # ─────────────────────────────────────────
    # 🔥 FIX 3: stronger correlation impact
    # ─────────────────────────────────────────
    correlation_term = cfg["gamma"] * record.correlation_score

    # ─────────────────────────────────────────
    # 🔥 FIX 4: rarity boost (NEW)
    # ─────────────────────────────────────────
    rarity_boost = 1.0 / (1.0 + record.frequency)
    rarity_term = 0.3 * rarity_boost

    # ─────────────────────────────────────────
    # Final score
    # ─────────────────────────────────────────
    importance_score = (
        weighted_event
        + novelty_bonus
        + correlation_term
        + rarity_term
    )

    label = get_label(importance_score, cfg)

    # Save results
    record.importance_score = round(importance_score, 4)
    record.label = label

    # Debug logging
    logger.info(
        "importance_score=%.4f label=%s "
        "[ew=%.2f × conf=%.2f × nov_factor=%.3f] "
        "[nov_bonus=%.3f] [corr=%.2f] [rarity=%.3f] "
        "host=%s %s/%s",
        importance_score,
        label,
        record.event_weight,
        record.event_type_confidence,
        novelty_factor,
        novelty_bonus,
        record.correlation_score,
        rarity_term,
        record.host,
        record.event_type,
        record.event_action,
    )

    return importance_score, label


# ── Batch Scoring ───────────────────────────────────────────────────────

def score_batch(
    records: list[LogRecord],
    config_path: str = "config/weights.yaml",
) -> list[LogRecord]:
    for record in records:
        compute_importance_score(record, config_path=config_path)
    return records