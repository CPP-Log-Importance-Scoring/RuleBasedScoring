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
9. Run anomaly proximity with an empty `AnomalyIndex`, which currently sets counter-proximity anomaly scores to `0.0`.
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
    counters.csv                  # Counter anomaly data, supported but not loaded by main.py
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

The parser extracts:

- syslog priority
- timestamp
- host
- service
- message
- semantic event type/action

Malformed or blank lines are skipped.

Syslog severity is derived from the lowest three bits of the priority:

```text
severity 0-2 -> CRITICAL
severity 3   -> ERROR
severity 4   -> WARN
severity 5-7 -> INFO
```

## Semantic Event Extraction

`parsing.parse_logs` maps service/message combinations into event categories.
Supported services include:

- `APP`
- `FW`
- `WEB`
- `SYS`
- `ROUTING`
- `IDM`
- `PORT`
- legacy services such as `OSPF`, `SECURITY`, `SNMP`, `DHCP_SNOOP`, `VLAN`, `Manager`, and `syslog`

Examples:

```text
APP: Database timeout        -> APP/Database timeout
WEB: GET /.env ...           -> WEB/GET /.env
IDM: privilege escalation... -> IDM/privilege escalation attempt
SYS: periodic health check   -> SYS/periodic health check
```

## Drain3 Template Mining

`parsing.drain_parser` wraps Drain3's `TemplateMiner` with:

```text
drain_sim_th = 0.4
drain_depth  = 4
```

`template_extraction.py` passes each log message to Drain and writes:

- `template_id`: `TEMPLATE_<cluster_id>`
- `message`: normalized mined template text

Drain templates are used for grouping/frequency support. They do not replace
the semantic `event_action`, so scoring remains explainable.

## Feature Scoring

Each `LogRecord` carries these feature fields:

- `severity_score`: from log level (`CRITICAL`, `ERROR`, `WARN`, `INFO`)
- `event_type_score`: substring match against the rule table in `feature_service.py`
- `anomaly_score`: binary `0.0` or `1.0`
- `frequency`: same-template count in the active sliding window
- `novelty_score`: rarity/spike score from recent frequency history
- `correlation_score`: normalized boost from cluster size

Important current behavior: `feature_service.py` computes a heuristic anomaly
score first, but `main.py` later calls `compute_anomaly_scores_batch()` with
`AnomalyIndex.empty()`. That means the active run overwrites anomaly proximity
to `0.0` for all records. To use `data/counters.csv`, change `main.py` to use
`AnomalyIndex.from_csv("data/counters.csv")`.

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

`scoring.importance_score` uses event weight, event confidence, novelty,
correlation, and rarity:

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

The main coefficients are loaded from `config/weights.yaml`:

```yaml
alpha: 0.60
beta: 0.25
gamma: 0.15
```

## Labels

Final scores are mapped to labels using these thresholds:

```text
score < 0.5        -> ignore
0.5 <= score < 1.0 -> low
1.0 <= score < 1.6 -> medium
1.6 <= score < 2.0 -> high
score >= 2.0       -> critical
```

Thresholds can be tuned in `config/weights.yaml`.

## Correlation

`CorrelationEngine` clusters records using:

- event family
- host
- event type
- event action
- time bucket

Known event families include `NETWORK_DOWN`, `NETWORK_UP`, `SECURITY`, `AUTH`,
and `CONFIG`; unknown combinations fall back to their `event_type`.

Cluster size is converted to a normalized `0.0` to `1.0` score:

```text
correlation_score = min(log2(cluster_size + 1) / 3.0, 1.0)
```

Each record receives a `correlation_id` like:

```text
corr-12345-001
```

`main.py` deduplicates by `correlation_id` before final scoring.

## Output

`output.txt` contains ranked records, highest score first:

```text
[MEDIUM  ] score=1.326  Mar 12 10:00:00  app-server-01  APP  APP/User login success  corr=corr-12345-001
```

The console also prints:

- top 10 important logs
- label distribution
- noise suppression ratio
- actionable count (`medium`, `high`, `critical`)
- critical count

The gap-report helper still exists in `feature_service.py`, but the print block
in `main.py` is currently commented out.

## Configuration

`config/weights.yaml` controls:

- `w1`, `w2`, `w3`: event-weight coefficients
- `alpha`, `beta`, `gamma`: final importance-score coefficients
- `threshold_low`, `threshold_medium`, `threshold_high`, `threshold_critical`: label cutoffs
- `frequency_window_seconds`: configured frequency window
- `anomaly_proximity_delta_seconds`: counter anomaly proximity window
- `correlation_window_seconds`: correlation time bucket size

Note: `main.py` currently calls `compute_frequency(r)` without passing the YAML
window, so the default `60` second frequency window is used.

## Useful Debug Commands

Run from inside `RuleBasedScoring`:

```powershell
python -m parsing.parse_logs
python -m features.frequency
python -m features.novelty
python -m features.anomaly_proximity
python -m scoring.event_weight
python -m scoring.scoring_utils
```

## Notes

- Most stages mutate `LogRecord` objects in place.
- Drain template IDs are dynamic and can change if log order/input changes.
- Frequency and novelty are order-sensitive.
- Config loading in scoring modules is cached.
- `data/counters.csv` is present, but the active main pipeline uses an empty anomaly index.
- Cluster summaries are available through `engine.get_cluster_summary()`, but they are not currently written to disk.
