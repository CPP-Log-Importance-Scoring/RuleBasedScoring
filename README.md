# Rule-Based Log Scoring

Rule-Based Log Scoring is a Python pipeline for ranking syslog-style network,
application, web, firewall, routing, identity, and system events. It combines
rule-based semantic parsing with Drain3 template mining, sliding-window
frequency, novelty scoring, event correlation, and configurable importance
thresholds.

The current entry point is `main.py`. It reads logs from `data/logs.txt`, scores
deduplicated correlated events, prints the top records and summary metrics, and
writes the ranked output to `output.txt`.

## Current Pipeline

`main.py` runs the active pipeline in this order:

1. Load `config/weights.yaml`.
2. Parse valid syslog lines from `data/logs.txt`.
3. Extract semantic `event_type` and `event_action` values from service/message rules.
4. Run Drain3 template mining and assign dynamic `TEMPLATE_<cluster_id>` IDs.
5. Fill missing `UNKNOWN` event types with the original service name.
6. Compute base features: severity, event-type score, heuristic anomaly, provisional frequency, and provisional novelty.
7. Recompute frequency with `features.frequency.compute_frequency()`.
8. Recompute novelty with `features.novelty.NoveltyTracker`.
9. Run anomaly proximity using counter data from `data/counters.csv`, assigning anomaly scores based on temporal proximity to anomaly spikes.
10. Compute event weight.
11. Correlate records by event family, host, event type/action, and time bucket.
12. Deduplicate records by `correlation_id`.
13. Compute final importance score and label.
14. Print the top 10 logs, write `output.txt`, and print summary statistics.

## Project Structure

```text
RuleBasedScoring/
  main.py                         # Main pipeline entry point
  requirements.txt                # Python dependencies
  output.txt                      # Generated ranked output
  config/
    weights.yaml                  # Weights, thresholds, and time windows
  data/
    logs.txt                      # Input syslog-style log events
    counters.csv                  # Counter anomaly data (actively used)
  parsing/
    parse_logs.py                 # Syslog parser and semantic event extraction
    drain_parser.py               # Drain3 TemplateMiner wrapper
    schema.py                     # LogRecord dataclass
    template_extraction.py        # Drain-based template ID assignment
  features/
    feature_service.py            # Base feature computation and scoring gaps
    frequency.py                  # Sliding-window template frequency
    novelty.py                    # Frequency-history novelty/spike scoring
    anomaly_proximity.py          # Counter anomaly proximity utilities
  scoring/
    event_weight.py               # Event weight formula
    importance_score.py           # Final score and label logic
    scoring_utils.py              # Formatting, summaries, and label metrics
  correlation/
    correlation_engine.py         # Correlation clustering
    clustering_utils.py           # Cluster buckets, IDs, and normalized scores
```

## Requirements

- Python 3.10 or newer
- PyYAML
- drain3

Install dependencies from inside `RuleBasedScoring`:

```bash
pip install -r requirements.txt
```

Optional virtual environment setup on Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## How To Run

Run from inside the `RuleBasedScoring` directory:

```powershell
python main.py
```

Default paths:

```text
Input logs:       data/logs.txt
Config file:      config/weights.yaml
Scored output:    output.txt
```

`main.py` currently computes cluster summaries internally but does not write a
separate cluster report file.

## Input Format

The parser expects lines in this form:

```text
<PRI>Mon DD HH:MM:SS HOST SERVICE: MESSAGE
```

Example:

```text
<191>Mar 12 10:00:00 fw-01 FW: connection allowed from 192.168.41.29
<187>Mar 12 10:00:00 app-server-01 APP: Service restarted
```

## Feature Scoring

Each `LogRecord` carries these feature fields:

- `severity_score`
- `event_type_score`
- `anomaly_score`
- `frequency`
- `novelty_score`
- `correlation_score`

### Anomaly Scoring (Updated)

The system incorporates anomaly signals from `data/counters.csv`.

- High counter values indicate anomaly spikes.
- Logs occurring within a configurable time window (default ±60 seconds)
  of these timestamps are assigned:

```text
anomaly_score = 1.0
```

- This score is combined with heuristic anomaly detection using:

```text
record.anomaly_score = max(heuristic_score, proximity_score)
```

## Scoring Formulas

### Event Weight

```text
event_weight = (w1 * severity_score)
             + (w2 * event_type_score)
             + (w3 * anomaly_score)
```

Defaults from `config/weights.yaml`:

```yaml
w1: 0.5
w2: 0.3
w3: 0.2
```

### Importance Score

```text
novelty_factor = 0.5 + 0.5 * novelty_score

weighted_event = alpha
               * event_weight
               * event_type_confidence
               * novelty_factor

novelty_bonus    = beta * novelty_score
correlation_term = gamma * correlation_score
rarity_term      = 0.3 * (1 / (1 + frequency))

importance_score = weighted_event
                 + novelty_bonus
                 + correlation_term
                 + rarity_term
```

## Labels

```text
score < 0.5        -> ignore
0.5 <= score < 1.0 -> low
1.0 <= score < 1.6 -> medium
1.6 <= score < 2.0 -> high
score >= 2.0       -> critical
```

## Notes

- Most stages mutate `LogRecord` objects in place.
- Frequency and novelty are order-sensitive.
- Config loading in scoring modules is cached.
- `data/counters.csv` is actively used for anomaly detection via temporal proximity.
- Effectiveness of anomaly scoring depends on alignment between log timestamps and anomaly spikes.
