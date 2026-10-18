#!/usr/bin/env python3
"""Detect repeated Windows authentication failures in a synthetic CSV dataset."""
import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

def parse_time(value):
    #adding a timezone to the parsed datetime object 
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    #returing a UTC datetime object
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
    
    # Convert the window from minutes into a time duration.
    window = timedelta(minutes=window_minutes)

    # Store failed login events separately for each IP address.
    failed_by_ip = defaultdict(list)

    for event in events:
        # Identify failed login events.
        if event["event_id"] == 4625 or event["outcome"].lower() == "failure":
            ip = event["source_ip"]
            failed_by_ip[ip].append(event)

    # Store all alerts found by the detector.
    findings = []

    # Check each IP address separately.
    for ip, failures in failed_by_ip.items():

        # Put failed logins in time order.
        failures.sort(key=lambda event: event["_time"])

        # Try each failure as the beginning of a 10-minute window.
        for i in range(len(failures)):

            # Start counting from zero for this new window.
            count = 0
            window_events = []

            # Check this failure and the failures that follow it.
            for j in range(i, len(failures)):

                # Calculate how much time passed since the first failure.
                elapsed = failures[j]["_time"] - failures[i]["_time"]

                # Stop if the failure is outside the time window.
                if elapsed > window:
                    break

                # This failure is inside the window, so count it.
                count += 1
                window_events.append(failures[j])

            # Continue only if the threshold has been reached.
            if count >= threshold:

                # Time when the first failure in this window occurred.
                first_failure = window_events[0]["_time"]

                # Time when the threshold number of failures was reached.
                threshold_time = window_events[threshold - 1]["_time"]

                # Time of the last failure in this window.
                last_failure = window_events[-1]["_time"]

                # Look for a successful login from the same IP afterward.
                successful_login = None

                for event in events:
                    is_success = (
                        event["event_id"] == 4624
                        or event["outcome"].lower() == "success"
                    )

                    if (
                        event["source_ip"] == ip
                        and is_success
                        and event["_time"] > threshold_time
                    ):
                        # Save the first successful login we find.
                        if (
                            successful_login is None
                            or event["_time"] < successful_login["_time"]
                        ):
                            successful_login = event

                # Create an alert containing the investigation details.
                findings.append({
                    "source_ip": ip,
                    "failure_count_in_window": count,
                    "window_start": first_failure.isoformat(),
                    "window_end": last_failure.isoformat(),

                    # List the usernames and hosts involved.
                    "accounts": sorted({
                        event["username"] for event in window_events
                    }),
                    "hostnames": sorted({
                        event["host"] for event in window_events
                    }),

                    # Record whether a successful login followed.
                    "success_after_failures": successful_login is not None,
                    "first_success_after_failures": (
                        successful_login["timestamp"]
                        if successful_login else None
                    ),

                    # A later success raises the priority for investigation.
                    "severity": (
                        "high" if successful_login else "medium"
                    ),

                    # Give the analyst a suggested next step.
                    "triage_note": (
                        "Review the successful login and investigate the account."
                        if successful_login else
                        "Investigate the repeated failures and validate the source IP."
                    )
                })

                # Stop to avoid creating overlapping alerts for the same burst.
                break

    # Return all alerts to the main program.
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
