import logging
import yaml

from parsing.parse_logs import parse_file
from parsing.template_extraction import assign_template_ids_batch

from features.feature_service import compute_features_batch, gap_report
from features.frequency import compute_frequency
from features.novelty import compute_novelty_batch, NoveltyTracker

from scoring.event_weight import compute_event_weight
from scoring.importance_score import score_batch
from scoring.scoring_utils import print_summary, format_record

from correlation.correlation_engine import CorrelationEngine

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def load_config(config_path: str = "config/weights.yaml") -> dict:
    with open(config_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def format_full_line(record) -> str:
    rarity  = round(1.0 / (1.0 + record.frequency), 3)
    nov_bonus = round(0.25 * record.novelty_score, 3)
    nov_factor = round(0.5 + 0.5 * record.novelty_score, 3)

    return (
        f"importance_score={record.importance_score:.4f} label={record.label} "
        f"[ew={record.event_weight:.2f} × conf={record.event_type_confidence:.2f} × nov_factor={nov_factor:.3f}] "
        f"[nov_bonus={nov_bonus:.3f}] "
        f"[corr={record.correlation_score:.2f}] "
        f"[rarity={rarity:.3f}] "
        f"host={record.host} "
        f"{record.service}/{record.message}"
    )


def main(log_file: str = "data/logs.txt", config_path: str = "config/weights.yaml"):
    cfg         = load_config(config_path)
    corr_window = cfg.get("correlation_window_seconds", 1800)

    logger.info("Starting pipeline...")

    # Stage 1: Parse
    records = list(parse_file(log_file))
    logger.info("Parsed %d records", len(records))

    # Stage 1b: Template extraction
    assign_template_ids_batch(records)
    for r in records:
        if r.event_type == "UNKNOWN":
            r.event_type = r.service

    # Stage 2: Features
    compute_features_batch(records)
    for r in records:
        compute_frequency(r)

    tracker = NoveltyTracker()
    compute_novelty_batch(records, tracker=tracker)

    # Stage 3: Event weight
    for r in records:
        compute_event_weight(r)

    # Stage 4: Correlation
    engine = CorrelationEngine(window_seconds=corr_window)
    engine.correlate_batch(records)

    # Stage 5: Scoring
    score_batch(records, config_path=config_path)

    # Sort by score
    records_sorted = sorted(records, key=lambda r: r.importance_score, reverse=True)

    # ✅ FIX 1: UTF-8 here
    with open("output.txt", "w", encoding="utf-8") as f:

        for r in records_sorted:
            f.write(format_full_line(r) + "\n")

        f.write("\n")

        f.write("Top Important Logs:\n")
        f.write("-" * 60 + "\n")
        for r in records_sorted[:10]:
            f.write(format_record(r) + "\n")

        f.write("\n")

        from scoring.scoring_utils import label_distribution, noise_suppression_ratio
        dist  = label_distribution(records_sorted)
        total = len(records_sorted)
        nsr   = noise_suppression_ratio(records_sorted)
        actionable = sum(dist[l] for l in ("medium", "high", "critical"))

        f.write(f"\n{'═' * 50}\n")
        f.write(f"  Scoring summary  ({total} records)\n")
        f.write(f"{'═' * 50}\n")

        for label in ("ignore", "low", "medium", "high", "critical"):
            count = dist[label]
            pct   = (count / total * 100) if total else 0
            bar   = "█" * int(pct / 5)
            f.write(f"  {label:8s}  {count:6d}  ({pct:5.1f}%)  {bar}\n")

        f.write(f"{'─' * 50}\n")
        f.write(f"  Noise suppression ratio   : {nsr:.1%}\n")
        f.write(f"  Actionable (med+high+crit): {actionable}\n")
        f.write(f"  Critical                  : {dist['critical']}\n")
        f.write(f"{'═' * 50}\n")

    logger.info("Output saved to output.txt")

    print("\nTop Important Logs:\n" + "-" * 60)
    for r in records_sorted[:10]:
        print(format_record(r))

    print_summary(records_sorted)

    # Removed correlation_clusters.txt generation as requested

    gaps = gap_report(top_n=10)
    if gaps:
        print("\n--- TEMPLATE GAPS ---")
        for g in gaps:
            print(f"  {g['event_type']:15s} | {g['event_action']:20s} → {g['miss_count']} misses")


if __name__ == "__main__":
    main()