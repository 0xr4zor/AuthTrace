# Windows Authentication Attack Detection and Investigation

A hands-on SOC portfolio project that analyses synthetic Windows authentication events, detects repeated failed logons, correlates later successful logons, and produces structured findings for triage.

> **Safety and scope:** This repository uses synthetic training data only. The IP addresses and usernames are illustrative. No live systems are targeted, and the results do not establish that a real compromise occurred.

## Objectives

- Understand Windows Security Event ID 4625 (failed logon) and 4624 (successful logon).
- Identify repeated authentication failures within a configurable time window.
- Pivot from a detection to a related successful logon.
- Document evidence, confidence, false-positive possibilities, and response recommendations.
- Practise basic detection automation and testing.

## Repository layout

```text
.
├── data/
│   └── auth_events.csv
├── detections/
│   └── splunk_auth_detection.spl
├── reports/
│   └── incident_report.md
├── src/
│   └── detect_auth_attacks.py
├── tests/
│   └── test_detector.py
└── README.md
```

## Requirements

- macOS, Linux, or Windows
- Python 3.10 or later
- No third-party Python packages required

Check Python:

```bash
python3 --version
```

## Run the detector

From the repository root:

```bash
python3 src/detect_auth_attacks.py
```

The default input is `data/auth_events.csv`. The script writes `reports/detection_results.json`.

Change the threshold or time window:

```bash
python3 src/detect_auth_attacks.py --threshold 5 --window 10
```

Use a different output path:

```bash
python3 src/detect_auth_attacks.py --input data/auth_events.csv --output reports/results.json
```

Expected high-level result for the included data: 12 events processed and one flagged source IP. The finding should show eight failed logons and a subsequent successful logon. Validate this yourself by inspecting the generated JSON and the source CSV.

## Detection approach

1. Parse each event timestamp and sort events chronologically.
2. Group failed logons by source IP.
3. Find a rolling ten-minute interval containing at least five failures.
4. Check whether a successful logon from the same IP occurs after the qualifying failures.
5. Emit a JSON finding with affected accounts, hosts, timestamps, severity heuristic, and triage guidance.

The successful-logon correlation is a prioritisation signal, not proof that the same person or device performed both actions. In production, correlate more context such as account, host, logon type, device identity, MFA outcome, and network telemetry.

## Splunk searches

See [`detections/splunk_auth_detection.spl`](detections/splunk_auth_detection.spl). The searches assume events have been ingested and field names mapped to `EventCode`, `src_ip`, `user`, and `host`. Adapt the index and field names to your own lab. The sample query uses fixed ten-minute buckets, which are simpler for learning but can miss events crossing a bucket boundary.

## Investigation findings

Read [`reports/incident_report.md`](reports/incident_report.md) for the timeline, assessment, recommended response, limitations, and tuning considerations.

## Test the detector

Run:

```bash
python3 -m unittest discover -s tests -v
```

## Suggested improvements

- Add detection for many usernames targeted from one source.
- Add detection for one account targeted from many sources.
- Add unit tests for events spanning a window boundary and for missing or malformed fields.
- Add configurable allowlists and explain the risks of exclusions.
- Export a CSV summary for analysts.
- Add a Sigma rule and test it against representative data.
- Create a dashboard from the output.
- Compare fixed-bucket and rolling-window detection behaviour.

## MITRE ATT&CK mapping

Potentially relevant concept: **T1110, Brute Force**. Map this only as a plausible investigative hypothesis. The event sequence alone does not prove that a brute-force technique was used.

Reference: https://attack.mitre.org/techniques/T1110/

## Limitations

This is a learning project, not a production-ready security control. The dataset is small and synthetic. The threshold is configurable and should be tuned against the environment's normal authentication patterns. The detector currently groups by source IP, so shared infrastructure can produce ambiguous attribution.

