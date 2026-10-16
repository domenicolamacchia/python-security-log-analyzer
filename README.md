# Python Security Log Analyzer

A beginner-friendly cybersecurity portfolio project that analyses **fictional authentication logs** and highlights patterns that may warrant investigation.

## Features

- Parses a simple, documented log format.
- Counts successful and failed authentication events.
- Flags IP addresses with repeated failed logins within a configurable time window.
- Flags a successful login after repeated failures from the same IP and username.
- Produces a readable summary report and a CSV of alerts.
- Includes fictional sample data and automated unit tests.
- Uses only the Python standard library.

> **Portfolio/lab project:** This tool is for learning and demonstration. Alerts are indicators for investigation, not proof of compromise. The sample logs are fictional and use documentation-only IP addresses.

## Requirements

- Python 3.10 or later
- No third-party packages required

## Quick start

From this repository's root directory:

```bash
python src/log_analyzer.py --input data/sample_auth.log --output-dir reports
```

To customise the failed-login threshold and time window:

```bash
python src/log_analyzer.py --input data/sample_auth.log --output-dir reports --threshold 5 --window-minutes 10
```

On some systems, use `python3` instead of `python`.

## Input format

Each line must use this format:

```text
YYYY-MM-DDTHH:MM:SSZ username=NAME ip=IP_ADDRESS status=success|failure
```

Blank lines and lines beginning with `#` are ignored. Malformed lines are skipped and counted in the summary.

## Example output

Running the command against the sample data creates:

- `reports/analysis_report.txt` — totals and findings.
- `reports/alerts.csv` — machine-readable alert list.

The exact alert count depends on the threshold and time window you select.

## Detection logic

1. **Repeated failures:** An IP address with at least the configured number of failed events in a rolling time window triggers an alert.
2. **Success after failures:** A successful event triggers an alert when the same IP and username had at least three failures during the previous 15 minutes.

These are deliberately simple heuristics. A production system would need baselining, richer identity/device context, log integrity protections, and tuning to reduce false positives.

## Tests

Run the test suite from the repository root:

```bash
python -m unittest discover -s tests -v
```

## Suggested improvements

- Support JSON or syslog input.
- Add severity tuning and allowlisted service accounts.
- Add structured JSON output.
- Build a small dashboard for reviewing alerts.
- Compare detections against a labelled, synthetic dataset.

## Skills demonstrated

Python, log parsing, detection logic, timestamps, CSV reporting, unit testing, security monitoring, and technical documentation.
