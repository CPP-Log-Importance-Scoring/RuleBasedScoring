# Rule-Based Log Scoring

Rule-Based Log Scoring is a Python pipeline for parsing, grouping, and ranking
syslog-style infrastructure events. It combines semantic event extraction,
Drain3 template mining, sliding-window frequency, novelty scoring, correlation,
incident collapsing, and configurable scoring weights.

The main entry point is `main.py`. By default it reads all records from
`data/logs.txt`, scores every valid log line, prints the highest-priority
incident groups and summary metrics, and writes the full ranked result to
`output.txt`.

## Current Dataset

The bundled `data/logs.txt` currently contains 19,677 parsed records.

Record coverage by service:

```text
ROUTING             5235
SYS                 5082
PORT                2716
APP                 2622
FW                  2330
WEB                 1632
IDM                   58
SECURITY_PORT_SCAN     2
```

The dataset includes routine noise and actionable incidents, including route
adds/removals, periodic health checks, port up/down changes, application login
and database events, firewall allow/deny events, web HTTP status events,
identity privilege escalation and ACL errors, health-check failures, and
security port-scan detections.

## Current Pipeline

`main.py` runs the active pipeline in this order:

1. Load `config/weights.yaml`.
2. Parse valid syslog lines from `data/logs.txt`.
3. Extract semantic `event_type` and `event_action` values from service/message rules.
4. Run Drain3 template mining and assign dynamic `TEMPLATE_<cluster_id>` IDs.
5. Fill any remaining `UNKNOWN` event types with the original service name.
6. Compute base features: severity, event-type score, confidence tier, frequency, and novelty.
7. Compute event weight from severity and event-type score.
8. Correlate records by event family, host, event type/action, and time bucket.
9. Compute final importance score and label.
10. Collapse repeated matching logs into incident groups.
11. Write `output.txt` with top incidents, scoring summary, and detailed ranked logs.
12. Print the top incidents, summary metrics, and template gap report.

## Project Structure

```text
RuleBasedScoring/
  main.py                         # Main pipeline entry point
  requirements.txt                # Python dependencies
  output.txt                      # Generated ranked output after running main.py
  config/
    weights.yaml                  # Weights, thresholds, and time windows
  data/
    logs.txt                      # Input syslog-style log events
  parsing/
    parse_logs.py                 # Syslog parser and semantic event extraction
    drain_parser.py               # Drain3 TemplateMiner wrapper
    schema.py                     # LogRecord dataclass
    template_extraction.py        # Drain-based template ID assignment
  features/
    feature_service.py            # Severity, event score, confidence, and gap tracking
    frequency.py                  # Sliding-window template frequency
    novelty.py                    # Frequency-history novelty/spike scoring
  scoring/
    event_weight.py               # Event weight formula
    importance_score.py           # Final score and label logic
    scoring_utils.py              # Formatting, summaries, and label metrics
  correlation/
    correlation_engine.py         # Correlation clustering
    clustering_utils.py           # Cluster buckets, IDs, and normalized scores
    collapse_utils.py             # Incident grouping/collapse helpers
```

## Requirements

- Python 3.10 or newer
- PyYAML
- drain3

Install dependencies from inside `RuleBasedScoring`:

```powershell
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

## Output

`output.txt` contains three sections:

1. `Top Important Incidents`
2. `Scoring summary`
3. `Detailed ranked logs`

Incident groups collapse repeated records with the same host, `event_type`, and
`event_action` when consecutive matching logs are within the configured
correlation window. The representative log is the highest-scoring record in the
group, and evidence lines preserve the original raw message values.

The latest run against the bundled records produced:

```text
Scoring summary (19677 records)
ignore  :   2592 ( 13.2%)
low     :   8474 ( 43.1%)
medium  :   5718 ( 29.1%)
high    :   2187 ( 11.1%)
critical:    706 (  3.6%)
Noise suppression ratio: 56.2%
Actionable (med+high+crit): 8611
Critical: 706
```

## Input Format

The parser expects lines in this form:

```text
<PRI>Mon DD HH:MM:SS HOST SERVICE: MESSAGE
```

Examples:

```text
<191>Mar 12 10:00:00 fw-01 FW: connection allowed from 192.168.41.29
<187>Mar 12 10:00:00 app-server-01 APP: Service restarted
<11>Mar 12 16:20:05 fw-01 SECURITY_PORT_SCAN: detected src=10.10.5.99
```

Invalid or blank lines are skipped by `parse_file()`.

## Feature Scoring

Each `LogRecord` carries these active feature fields:

- `severity_score`
- `event_type_score`
- `event_type_confidence`
- `event_type_tier`
- `frequency`
- `novelty_score`
- `event_weight`
- `correlation_id`
- `correlation_score`
- `importance_score`
- `label`

Anomaly scoring is intentionally excluded from this rule-based version. That
signal should be generated dynamically by an ML or statistical detector, not
hard-coded from static input.

## Scoring Formulas

### Event Weight

```text
event_weight = (w1 * severity_score)
             + (w2 * event_type_score)
```

Defaults from `config/weights.yaml`:

```yaml
w1: 0.6
w2: 0.4
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

Defaults from `config/weights.yaml`:

```yaml
alpha: 0.60
beta: 0.25
gamma: 0.35
frequency_window_seconds: 60
correlation_window_seconds: 1800
```

## Labels

Labels use lower-bound inclusive thresholds:

```text
score < 0.85       -> ignore
0.85 <= score < 1.0 -> low
1.0 <= score < 1.6  -> medium
1.6 <= score < 2.0  -> high
score >= 2.0        -> critical
```

## Notes

- Most stages mutate `LogRecord` objects in place.
- Frequency and novelty are order-sensitive.
- Config loading in scoring modules is cached.
- Correlation IDs are generated from hashed cluster keys.
- `main.py` no longer writes a separate `correlation_clusters.txt`; incident and correlation details are included in `output.txt`.
