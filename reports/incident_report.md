# Incident Investigation Report

**Case ID:** SOC-2026-0914-001  
**Status:** Simulated training case  
**Severity:** High priority for validation, not confirmed compromise  
**Affected account:** `j.smith`  
**Source IP:** `10.20.5.77`  
**Host:** `WS-014`  
**Data source:** Synthetic Windows authentication events  

## Executive summary

The synthetic dataset contains eight failed authentication events for `j.smith` from `10.20.5.77` between 09:00:00 and 09:07:30 UTC, followed by a successful logon at 09:08:15 UTC. This meets the project's detection threshold of five failures in ten minutes and raises concern for password guessing or a user repeatedly entering an incorrect password followed by a valid login.

The available data does **not** prove account compromise. The source address is from a private address range, and the dataset does not include endpoint process telemetry, network boundary logs, MFA outcomes, or user confirmation.

## Timeline (UTC)

| Time | Evidence | Interpretation |
|---|---|---|
| 09:00:00 | First 4625 failure for `j.smith` from `10.20.5.77` | Start of suspicious sequence |
| 09:01:10–09:07:30 | Seven additional failures for the same account and source | Eight failures in approximately 7.5 minutes |
| 09:08:15 | Event 4624 successful logon for `j.smith` from same source | Raises priority; determine whether this was expected |
| 09:12:00–09:13:00 | One failure then success for `m.lee` from `10.20.5.44` | Separate, low-volume pattern; does not meet threshold |

## Analysis

- The sequence meets the configured threshold of at least five failed logons within ten minutes.
- A successful logon from the same source follows the failures. Correlation by source IP alone is not conclusive, but the matching account and close timing increase concern.
- The second account has only one failure followed by success, so it does not trigger the threshold.
- `10.20.5.77` is an RFC1918 private address. It cannot be attributed to a public actor based on this dataset. Identify the internal device through DHCP, VPN, NAC, firewall, or asset records.
- The logs supplied here are synthetic and intentionally limited. No real user, device, or attacker has been identified.

## Assessment

**Disposition:** Escalate for validation as a potentially suspicious authentication sequence.  
**Confidence:** Moderate that the sequence is anomalous under the configured rule; insufficient evidence to confirm compromise.  
**Priority rationale:** Repeated failures followed by success against the same account may indicate successful password guessing, but legitimate causes must be checked.

## Recommended response

1. Preserve the relevant authentication events and confirm time synchronisation.
2. Check whether `10.20.5.77` belongs to an authorised workstation, VPN gateway, jump host, or other expected service.
3. Validate with the account owner or service owner whether the login was expected, using an established contact channel.
4. Review MFA results, logon type, workstation name, source device, and surrounding events.
5. Search for subsequent activity by `j.smith`, including privileged access, unusual resource access, account changes, and logons from other hosts.
6. If corroborating evidence suggests compromise, follow the organisation's incident process to revoke sessions, reset credentials, and isolate affected systems where justified.
7. Record the decision, evidence, timestamps, and escalation outcome.

## Detection logic

Alert when one source IP produces at least five failed authentication events within a rolling ten-minute window. Increase triage priority if a successful logon from that source follows the qualifying failures. This is a heuristic, not a verdict.

## Limitations and tuning

- The supplied data has only 12 events and is synthetic.
- A shared NAT, VPN, proxy, or management host can make source IP attribution ambiguous.
- A fixed time bucket in the sample Splunk query may miss events crossing bucket boundaries.
- A high failure threshold can miss slow password guessing; a low threshold can generate noise.
- Tune using known baseline behaviour, account type, logon type, asset criticality, MFA data, and observed false positives.
