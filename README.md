# Windows Authentication Attack Detection and Investigation

A hands-on SOC portfolio project that analyses synthetic Windows authentication events, detects repeated failed logons, correlates later successful logons, and produces structured findings for triage.

> **Safety and scope:** This repository uses synthetic training data only. The IP addresses and usernames are illustrative. No live systems are targeted, and the results do not establish that a real compromise occurred.

## Objectives

- Understand Windows Security Event ID 4625 (failed logon) and 4624 (successful logon).
- Identify repeated authentication failures within a configurable time window.
- Investigate whether a successful logon follows a series of failed attempts.
- Document evidence, confidence, false-positive possibilities, and response recommendations.
- Practise detection automation, Python programming, and unit testing.

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

Check your Python version:

```bash
python3 --version
```

## Run the detector

From the repository root, run:

```bash
python3 src/detect_auth_attacks.py
```

The default input is `data/auth_events.csv`. The script writes its findings to `reports/detection_results.json`.

### Change the detection threshold or time window

By default, the detector looks for at least five failed logons within ten minutes.

```bash
python3 src/detect_auth_attacks.py --threshold 5 --window 10
```

You can change these values to investigate how different thresholds affect detection results.

### Use a different input or output path

```bash
python3 src/detect_auth_attacks.py --input data/auth_events.csv --output reports/results.json
```

### Expected results

The included dataset is intended to produce 12 processed events and one flagged source IP. The finding is expected to contain eight failed logons and indicate whether a successful logon occurred after the detection threshold was reached.

Verify these values by inspecting `reports/detection_results.json` and comparing the finding with the source CSV. The actual output from the current version of the detector should be treated as authoritative.

## Detection approach

The Python detector follows these steps:

1. **Parse timestamps:** Read the event timestamps and sort the events chronologically.
2. **Group failed logons:** Collect failed authentication events by source IP address.
3. **Check a rolling time window:** Try each failed logon as the beginning of a ten-minute window.
4. **Apply the threshold:** Count the failures within each window and generate a finding when the configurable threshold is reached. The default is five failures.
5. **Check for a successful logon:** Search for a successful authentication event from the same source IP after the threshold was reached.
6. **Generate a finding:** Write a JSON result containing the source IP, failure count, time window, affected accounts and hosts, severity, and triage guidance.

The detector assigns **medium severity** when repeated failures are detected and **high severity** when a subsequent successful logon is found. This is a prioritisation heuristic, not proof of compromise.

The successful logon may involve a different account from those targeted by the failed attempts. Analysts should therefore investigate the account, host, logon type, and surrounding activity before drawing conclusions.

The current implementation reports only the first qualifying window for each source IP. It does not create separate findings for later bursts from that IP.

## Splunk searches

See [`detections/splunk_auth_detection.spl`](detections/splunk_auth_detection.spl).

The searches assume events have been ingested and field names mapped to `EventCode`, `src_ip`, `user`, and `host`. Adapt the index and field names to your own lab environment.

The sample query uses fixed ten-minute buckets. These are simpler for learning but can miss events that cross a bucket boundary. The Python detector instead uses a rolling time window.

## Investigation findings

Read [`reports/incident_report.md`](reports/incident_report.md) for the investigation timeline, assessment, recommended response, limitations, and tuning considerations.

The report should distinguish observed evidence from hypotheses, explain possible false positives, and recommend validation steps before concluding that malicious activity occurred.

## Test the detector

Run the unit tests from the repository root:

```bash
python3 -m unittest discover -s tests -v
```

Tests help verify that the detector behaves as expected and that changes do not unintentionally break existing functionality.

## Suggested improvements

- Detect attempts involving many usernames from a single source IP.
- Detect attempts against one account from multiple source IP addresses.
- Add unit tests for events at the time-window boundary and for missing or malformed fields.
- Add configurable allowlists and document the risks of exclusions.
- Export a CSV summary for analysts.
- Add a Sigma rule and test it against representative data.
- Create a dashboard from the detection output.
- Compare fixed-bucket and rolling-window detection behaviour.
- Improve correlation by checking whether the successful logon involves an account targeted by the failed attempts.
- Support detection of multiple distinct bursts from the same source IP.

## MITRE ATT&CK mapping

Potentially relevant technique: **[T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)**.

Repeated failed logons may be consistent with brute-force activity, but the event sequence alone does not prove that this technique was used. Investigators should consider additional evidence before assigning a definitive technique classification.

## Limitations

This is a learning project, not a production-ready security control. The dataset is small and synthetic, and the detection threshold should be tuned against normal authentication patterns.

The detector groups failed logons by source IP, so shared infrastructure such as VPNs or NAT gateways can make attribution ambiguous. A successful logon from the same IP does not necessarily involve the same account or indicate a compromise.

The implementation reports the first qualifying window per IP and may not identify separate bursts later in the dataset. It does not currently use account-specific correlation, allowlists, host-based correlation, or baseline behaviour to reduce false positives.

The severity assigned to a finding is a triage aid, not a confirmed incident classification. Findings should be reviewed alongside relevant authentication records, account context, host information, and other available security telemetry.

## Learning outcomes

Through this project, you can practise:

- Analysing Windows authentication events.
- Translating a detection hypothesis into Python logic.
- Applying thresholds and rolling time windows.
- Investigating authentication patterns and possible false positives.
- Producing structured findings for security triage.
- Testing detection logic and documenting its limitations.
