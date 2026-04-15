# Rule-Based Log Scoring

Rule-Based Log Scoring is a Python pipeline for parsing network/syslog-style log
events, computing rule-based features, assigning importance scores, and grouping
related events into correlation clusters.

The project is designed to reduce alert noise by ranking log entries into
actionable labels such as `ignore`, `low`, `medium`, `high`, and `critical`.

## What It Does

The pipeline reads raw logs from `data/logs.txt`, enriches each parsed log record
with scoring features, computes a final importance score, and writes ranked
results to output files.

Main steps:

1. Parse syslog lines into structured `LogRecord` objects.
2. Extract event templates such as `SECURITY_PORT_SCAN`.
3. Compute feature scores such as severity, event type, anomaly proximity, and
   frequency.
4. Compute an event weight using configurable weights.
5. Correlate related logs by host, event, action, and time bucket.
6. Compute a final importance score.
7. Assign a label and write ranked output.

## Project Structure

```text
RuleBasedScoring/
  main.py                         # Main pipeline entry point
  config/
    weights.yaml                  # Scoring weights, thresholds, and windows
  data/
    logs.txt                      # Input syslog-style events
    counters.csv                  # Counter data used for anomaly proximity
  parsing/
    parse_logs.py                 # Raw log parsing
    schema.py                     # LogRecord dataclass
    template_extraction.py        # Template ID assignment
  features/
    feature_service.py            # Feature orchestration
    frequency.py                  # Frequency feature
    anomaly_proximity.py          # Anomaly proximity feature
  scoring/
    event_weight.py               # Event weight calculation
    importance_score.py           # Final score and label assignment
    scoring_utils.py              # Summary and formatting helpers
  correlation/
    correlation_engine.py         # Correlation cluster engine
    clustering_utils.py           # Cluster key and score helpers
```

## Requirements

- Python 3.10 or newer
- PyYAML

Install dependencies:

```bash
pip install pyyaml
```

If you are using a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install pyyaml
```

## How To Run

Run the project from inside the `RuleBasedScoring` directory so the relative
paths in `main.py` resolve correctly:

```bash
cd RuleBasedScoring
python main.py
```

By default, the pipeline uses:

```text
Input logs:       data/logs.txt
Config file:      config/weights.yaml
Scored output:    output.txt
Cluster report:   correlation_clusters.txt
```

## Input Log Format

The parser expects syslog-style lines like:

```text
<190>Mar 12 10:00:00 sw-core-01 SECURITY: possible port scan detected
```

Expected fields:

```text
<PRI>TIMESTAMP HOST SERVICE: MESSAGE
```

Example:

```text
<185>Mar 12 10:00:03 fw-01 IDM: ACL error - invalid VLAN 10 client AA:BB:CC
```

The syslog priority value is converted into a log level:

```text
0-2 -> CRITICAL
3   -> ERROR
4   -> WARN
5-7 -> INFO
```

## Scoring Model

The scoring process has two main formulas.

### Event Weight

`event_weight` combines severity, event type, and anomaly proximity:

```text
event_weight = (w1 * severity_score)
             + (w2 * event_type_score)
             + (w3 * anomaly_score)
```

The weights come from `config/weights.yaml`:

```yaml
w1: 0.5
w2: 0.3
w3: 0.2
```

### Importance Score

`importance_score` combines event weight, frequency, and correlation:

```text
importance_score = (alpha * event_weight)
                 + (beta * log(frequency + 1))
                 + (gamma * correlation_score)
```

The weights come from `config/weights.yaml`:

```yaml
alpha: 0.60
beta: 0.25
gamma: 0.15
```

## Labels

The final score is mapped to a label using threshold values from
`config/weights.yaml`.

```text
score < 0.5        -> ignore
0.5 <= score < 1.0 -> low
1.0 <= score < 1.6 -> medium
1.6 <= score < 2.0 -> high
score >= 2.0       -> critical
```

These thresholds can be tuned in:

```text
config/weights.yaml
```

## Configuration

The main configuration file is:

```text
config/weights.yaml
```

It controls:

- Event weight coefficients: `w1`, `w2`, `w3`
- Importance score coefficients: `alpha`, `beta`, `gamma`
- Label thresholds: `threshold_low`, `threshold_medium`,
  `threshold_high`, `threshold_critical`
- Frequency window: `frequency_window_seconds`
- Anomaly proximity window: `anomaly_proximity_delta_seconds`
- Correlation grouping window: `correlation_window_seconds`

## Outputs

After a successful run, the pipeline writes two output files.

### `output.txt`

Contains scored log records sorted by importance score, highest first.

Example format:

```text
[CRITICAL] score=2.350  Mar 12 10:00:03  fw-01  IDM  IDM/ACL_ERROR  corr=...
```

### `correlation_clusters.txt`

Contains a human-readable report of correlated event clusters.

Each cluster includes:

- Cluster number
- Cluster size
- Correlation score
- Cluster key
- Member logs and correlation IDs

## Useful Modules

Run individual modules directly when debugging specific parts of the pipeline:

```bash
python -m parsing.parse_logs
python -m scoring.event_weight
python -m scoring.scoring_utils
python -m correlation.correlation_engine
```

Run these commands from the `RuleBasedScoring` directory.

## Notes

- Most functions mutate `LogRecord` objects in place.
- The config loaders cache values to avoid re-reading `weights.yaml` repeatedly.
- Correlation is more accurate in batch mode because every record in a cluster
  receives the final cluster score.
- Malformed or blank log lines are skipped by the parser.
