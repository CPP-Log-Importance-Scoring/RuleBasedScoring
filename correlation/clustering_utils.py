import math
import hashlib
from datetime import datetime

# Default window (can be overridden from config)
WINDOW_SECONDS: int = 300


def bucket_timestamp(ts: datetime, window_seconds: int = WINDOW_SECONDS) -> int:
    """
    Snap a datetime to the start of its time-window bucket.
    """
    epoch = int(ts.timestamp())
    return epoch - (epoch % window_seconds)


def make_cluster_key(
    host: str,
    event_type: str,
    event_action: str,
    bucket: int,
) -> str:
    """
    Legacy helper (no longer used directly after incident fix).
    """
    return f"{host}|{event_type}|{event_action}|{bucket}"


def compute_correlation_score(cluster_size: int) -> float:
    """
    Normalized correlation score [0.0 → 1.0]
    """
    if cluster_size <= 1:
        return 0.0

    raw = math.log2(cluster_size + 1)

    # Normalize (max ≈3 → scale to 1)
    return round(min(raw / 3.0, 1.0), 4)


def make_correlation_id(cluster_key: str) -> str:
    key_hash = hashlib.sha1(cluster_key.encode("utf-8")).hexdigest()[:8]
    return f"corr-{key_hash}"
