# Alert Triage With Splunk

## Investigation Overview
This project documents a series of security alert investigations performed using Splunk SIEM in an authorized TryHackMe lab environment. The investigation focuses on analyzing security alerts, querying log data, identifying suspicious activity, correlating events, collecting evidence, and documenting findings using a structured SOC investigation methodology.

## Lab Information

| Category | Details |
| :--- | :--- |
| **Platform** | TryHackMe |
| **Room** | Alert Triage With Splunk SIEM Splunk |
| **Investigation Type** | Security Alert Triage |
| **Environment** | Authorized Training Lab |

## Learning Objectives
* Investigate security alerts using Splunk.
* Analyze authentication activity and identify brute-force attacks.
* Investigate Windows security-related activity.
* Analyze web shell activity on a vulnerable web server.
* Perform scenario-based alert triage.
* Identify relevant indicators of compromise (IOCs).
* Correlate events across available log sources.
* Document investigation findings and analyst conclusions.

## Investigation Methodology
The investigations in this project follow a structured SOC workflow:
* Alert Identification
* Initial Triage
* Log Search and Analysis
* Event Correlation
* Evidence Collection
* Indicator Identification
* Threat Assessment
* MITRE ATT&CK Mapping
* Analyst Documentation
* Final Disposition


  # Alert Triage With Splunk
## Task 2 — Initial Access Alert

### Investigation Overview
This investigation focuses on a suspected brute-force attack against the Linux host **tryhackme-2404**.

The alert was generated after suspicious authentication activity was detected from the source IP **10.10.242.248**. The investigation was conducted using Splunk SIEM to determine whether the activity represented a genuine brute-force attack and whether the attacker successfully gained access to the target system.

### Alert Details

| Field | Details |
| :--- | :--- |
| **Alert Name** | Brute Force Activity Detection |
| **Date** | 17/09/2025 |
| **Alert Time** | 9:00:21 AM |
| **Target Host** | tryhackme-2404 |
| **Source IP** | 10.10.242.248 |
| **Splunk Index** | linux-alert |
| **Sourcetype** | linux_secure |
| **Alert Type** | Suspected Brute-Force Activity |

### Initial Triage
The first stage of the investigation was to review the alert metadata and determine whether the activity appeared suspicious.

* **Source IP address 10.10.242.248** is a private IP address, indicating that the activity originated from within the internal network or from an environment using private addressing.
* **Target host** was identified as tryhackme-2404. At this stage, the hostname alone did not provide enough information to determine the system's specific role.
* **Alert timing** occurred at approximately 9:00 AM, which falls within normal business hours. However, the timing alone does not determine whether the activity is legitimate or malicious.
