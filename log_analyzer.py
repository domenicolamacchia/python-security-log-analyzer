#!/usr/bin/env python3
"""Analyse fictional authentication logs for potentially suspicious patterns."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    username: str
    ip: str
    status: str


@dataclass(frozen=True)
class Alert:
    timestamp: str
    alert_type: str
    severity: str
    ip: str
    username: str
    details: str


def parse_line(line: str) -> AuthEvent | None:
    """Parse one event line. Return None for comments/blank lines."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split()
    if len(parts) != 4:
        raise ValueError("expected timestamp plus username, ip, and status fields")

    timestamp_text = parts[0]
    fields = {}
    for item in parts[1:]:
        if "=" not in item:
            raise ValueError(f"invalid field: {item}")
        key, value = item.split("=", 1)
        fields[key] = value

    required = {"username", "ip", "status"}
    if set(fields) != required:
        raise ValueError("expected exactly username, ip, and status fields")
    if fields["status"] not in {"success", "failure"}:
        raise ValueError("status must be success or failure")

    # Accept a trailing Z as UTC; naive timestamps are treated as UTC.
    normalised = timestamp_text[:-1] + "+00:00" if timestamp_text.endswith("Z") else timestamp_text
    timestamp = datetime.fromisoformat(normalised)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)
    return AuthEvent(timestamp, fields["username"], fields["ip"], fields["status"])


def load_events(path: Path) -> tuple[list[AuthEvent], int]:
    events: list[AuthEvent] = []
    malformed = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                event = parse_line(line)
                if event is not None:
                    events.append(event)
            except (ValueError, TypeError):
                malformed += 1
    events.sort(key=lambda event: event.timestamp)
    return events, malformed


def detect_alerts(
    events: Iterable[AuthEvent],
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Alert]:
    """Return alerts for repeated failures and success following repeated failures."""
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_minutes < 1:
        raise ValueError("window_minutes must be positive")

    ordered = sorted(events, key=lambda event: event.timestamp)
    alerts: list[Alert] = []
    failure_events: list[AuthEvent] = []
    emitted_ip_windows: set[tuple[str, datetime]] = set()

    for event in ordered:
        cutoff = event.timestamp - timedelta(minutes=window_minutes)
        failure_events = [
            previous for previous in failure_events
            if previous.timestamp >= cutoff and previous.timestamp <= event.timestamp
        ]

        if event.status == "failure":
            failure_events.append(event)
            same_ip = [failure for failure in failure_events if failure.ip == event.ip]
            if len(same_ip) >= threshold:
                # Avoid emitting an alert for every event in the same IP/time window.
                bucket = (event.ip, event.timestamp.replace(second=0, microsecond=0))
                if bucket not in emitted_ip_windows:
                    emitted_ip_windows.add(bucket)
                    alerts.append(Alert(
                        timestamp=event.timestamp.isoformat(),
                        alert_type="repeated_failed_logins",
                        severity="HIGH",
                        ip=event.ip,
                        username=event.username,
                        details=f"{len(same_ip)} failed logins from this IP within {window_minutes} minutes",
                    ))
        else:
            recent_same_identity = [
                failure for failure in failure_events
                if failure.ip == event.ip
                and failure.username == event.username
                and event.timestamp - failure.timestamp <= timedelta(minutes=15)
            ]
            if len(recent_same_identity) >= 3:
                alerts.append(Alert(
                    timestamp=event.timestamp.isoformat(),
                    alert_type="success_after_repeated_failures",
                    severity="MEDIUM",
                    ip=event.ip,
                    username=event.username,
                    details=f"Successful login followed {len(recent_same_identity)} failures for the same username and IP",
                ))

    return alerts


def write_outputs(events: list[AuthEvent], malformed: int, alerts: list[Alert], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "analysis_report.txt"
    csv_path = output_dir / "alerts.csv"

    successes = sum(event.status == "success" for event in events)
    failures = sum(event.status == "failure" for event in events)
    with report_path.open("w", encoding="utf-8") as report:
        report.write("PYTHON SECURITY LOG ANALYZER\n")
        report.write("=" * 32 + "\n\n")
        report.write(f"Events analysed: {len(events)}\n")
        report.write(f"Successful logins: {successes}\n")
        report.write(f"Failed logins: {failures}\n")
        report.write(f"Malformed lines skipped: {malformed}\n")
        report.write(f"Alerts generated: {len(alerts)}\n\n")
        report.write("FINDINGS\n")
        report.write("-" * 32 + "\n")
        if not alerts:
            report.write("No alerts generated using the current settings.\n")
        for alert in alerts:
            report.write(f"[{alert.severity}] {alert.alert_type} | {alert.ip} | {alert.username}\n")
            report.write(f"  Time: {alert.timestamp}\n  Details: {alert.details}\n")
        report.write("\nNote: alerts are investigation leads, not proof of compromise.\n")

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "timestamp", "alert_type", "severity", "ip", "username", "details"
        ])
        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert.__dict__)

    return report_path, csv_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Path to authentication log file")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"), help="Directory for output reports")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logins needed to trigger repeated-failure alert")
    parser.add_argument("--window-minutes", type=int, default=10, help="Rolling time window for repeated failures")
    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"input file does not exist: {args.input}")

    try:
        events, malformed = load_events(args.input)
        alerts = detect_alerts(events, args.threshold, args.window_minutes)
    except ValueError as exc:
        parser.error(str(exc))

    report_path, csv_path = write_outputs(events, malformed, alerts, args.output_dir)
    print("Security log analysis complete.")
    print(f"Events analysed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Text report: {report_path}")
    print(f"CSV alerts: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
