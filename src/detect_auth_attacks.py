#!/usr/bin/env python3
"""Detect repeated Windows authentication failures in a synthetic CSV dataset."""
import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

def parse_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def load_events(path):
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["event_id"] = int(row["event_id"])
        row["_time"] = parse_time(row["timestamp"])
    return sorted(rows, key=lambda row: row["_time"])

def detect(events, threshold=5, window_minutes=10):
    """Flag IPs with >= threshold failures in any rolling window.

    Also report whether a successful logon from that IP followed the first
    qualifying failure. This is a triage signal, not proof of compromise.
    """
    window = timedelta(minutes=window_minutes)
    by_ip = defaultdict(list)
    by_account = defaultdict(list)
    for event in events:
        if event["event_id"] == 4625 or event["outcome"].lower() == "failure":
            by_ip[event["source_ip"]].append(event)

    findings = []
    for ip, failures in by_ip.items():
        failures.sort(key=lambda row: row["_time"])
        qualifying = None
        for start in range(len(failures)):
            end = start
            while end < len(failures) and failures[end]["_time"] - failures[start]["_time"] <= window:
                end += 1
            group = failures[start:end]
            if len(group) >= threshold:
                qualifying = group
                break
        if qualifying:
            first = qualifying[0]["_time"]
            last = qualifying[-1]["_time"]
            successes = [
                event for event in events
                if event["source_ip"] == ip
                and (event["event_id"] == 4624 or event["outcome"].lower() == "success")
                and event["_time"] >= first
            ]
            findings.append({
                "source_ip": ip,
                "failure_count_in_window": len(qualifying),
                "window_start": first.isoformat(),
                "window_end": last.isoformat(),
                "accounts": sorted({event["username"] for event in qualifying}),
                "hostnames": sorted({event["host"] for event in qualifying}),
                "success_after_failures": bool(successes),
                "first_success_after_failures": successes[0]["timestamp"] if successes else None,
                "severity": "high" if successes else "medium",
                "triage_note": (
                    "Review successful logon context immediately; this pattern may indicate account compromise."
                    if successes else
                    "Repeated failures detected; validate source, account context, and whether activity is expected."
                ),
            })
    return findings

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/auth_events.csv", help="Path to input CSV")
    parser.add_argument("--output", default="reports/detection_results.json", help="Path to JSON output")
    parser.add_argument("--threshold", type=int, default=5, help="Failures needed to alert")
    parser.add_argument("--window", type=int, default=10, help="Rolling window in minutes")
    args = parser.parse_args()
    events = load_events(args.input)
    findings = detect(events, args.threshold, args.window)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "dataset": args.input,
        "event_count": len(events),
        "threshold": args.threshold,
        "window_minutes": args.window,
        "finding_count": len(findings),
        "findings": findings,
    }, indent=2), encoding="utf-8")
    print(f"Processed {len(events)} events. Findings: {len(findings)}. Output: {output}")

if __name__ == "__main__":
    main()
