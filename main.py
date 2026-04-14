import logging
import yaml

from parsing.parse_logs import parse_file
from parsing.template_extraction import assign_template_ids_batch

from features.feature_service import compute_features_batch
from features.frequency import compute_frequency
from features.anomaly_proximity import (
    compute_anomaly_scores_batch,
    AnomalyIndex,
)

from scoring.event_weight import compute_event_weight
from scoring.importance_score import score_batch
from scoring.scoring_utils import print_summary, format_record

from correlation.correlation_engine import CorrelationEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_config(config_path: str = "config/weights.yaml") -> dict:
    """Load weights.yaml. Exits with a clear error if file is missing."""
    try:
        with open(config_path, "r") as fh:
            cfg = yaml.safe_load(fh)
        logger.info(
            "Config loaded: thresholds low=%.1f medium=%.1f critical=%.1f | "
            "corr_window=%ds",
            cfg.get("threshold_low", 0.5),
            cfg.get("threshold_medium", 1.0),
            cfg.get("threshold_critical", 2.0),
            cfg.get("correlation_window_seconds", 300),
        )
        return cfg
    except FileNotFoundError:
        logger.critical(
            "weights.yaml not found at '%s'. Cannot start pipeline — "
            "label thresholds and window sizes would be wrong.", config_path
        )
        raise


def main(log_file: str = "data/logs.txt", config_path: str = "config/weights.yaml"):
    cfg = load_config(config_path)
    corr_window = cfg.get("correlation_window_seconds", 300)

    logger.info("Starting pipeline  (correlation window = %ds)...", corr_window)

    # ── Step 1: Parse ─────────────────────────────────────
    records = list(parse_file(log_file))
    logger.info("Parsed %d records", len(records))

    # ── Step 2: Template Extraction ───────────────────────
    assign_template_ids_batch(records)

    # ── Step 3: Feature Engineering ───────────────────────
    compute_features_batch(records)

    # ── Step 4: Frequency ─────────────────────────────────
    for r in records:
        compute_frequency(r)

    # ── Step 5: Anomaly ───────────────────────────────────
    index = AnomalyIndex.empty()
    compute_anomaly_scores_batch(records, index)

    # ── Step 6: Event Weight ──────────────────────────────
    for r in records:
        compute_event_weight(r)

    # ── Step 7: Correlation ───────────────────────────────
    # FIX 1: Use window from yaml, not the hardcoded 300s default.
    # FIX 2: Keep engine instance so we can call get_cluster_summary() below.
    engine = CorrelationEngine(window_seconds=corr_window)
    engine.correlate_batch(records)

    # ── Step 8: Importance Score ──────────────────────────
    score_batch(records, config_path=config_path)

    # ── Sort by importance score (highest first) ──────────
    records_sorted = sorted(records, key=lambda r: r.importance_score, reverse=True)

    # ── Print Top Logs ────────────────────────────────────
    print("\nTop Important Logs:\n" + "-" * 80)
    for r in records_sorted[:10]:
        print(format_record(r))

    # ── Save scored output ────────────────────────────────
    with open("output.txt", "w") as f:
        for r in records_sorted:
            f.write(format_record(r) + "\n")
    logger.info("Scored output written to output.txt")

    # ── FIX 3: Write correlation cluster summary ──────────
    # get_cluster_summary() was inaccessible before because the old convenience
    # wrapper discarded the engine. Now we hold the engine instance.
    cluster_summary = engine.get_cluster_summary()
    # Sort clusters by score descending (most significant first)
    cluster_summary.sort(key=lambda c: c["score"], reverse=True)

    with open("correlation_clusters.txt", "w") as f:
        f.write(f"Cross-Signal Correlation Report\n{'=' * 60}\n")
        f.write(f"Total clusters: {len(cluster_summary)}\n")
        f.write(f"Correlation window: {corr_window}s\n\n")

        for i, cluster in enumerate(cluster_summary, start=1):
            f.write(
                f"[Cluster {i:04d}]  size={cluster['size']}  "
                f"score={cluster['score']:.4f}\n"
            )
            f.write(f"  key : {cluster['cluster_key']}\n")
            for m in cluster["members"]:
                f.write(
                    f"    {m['timestamp']}  {m['host']}  "
                    f"{m['service']}  corr_id={m['correlation_id']}\n"
                )
            f.write("\n")

    logger.info(
        "Correlation clusters written to correlation_clusters.txt  "
        "(%d clusters)", len(cluster_summary)
    )

    print_summary(records_sorted)


if __name__ == "__main__":
    main()