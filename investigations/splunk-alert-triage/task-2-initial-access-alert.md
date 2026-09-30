# Task 2 — Initial Access Alert

## Investigation Overview
This investigation focuses on a suspected brute-force attack against the Linux host **tryhackme-2404**.

The alert was generated after suspicious authentication activity was detected from the source IP address **10.10.242.248**. The investigation uses Splunk SIEM to analyze Linux authentication logs, identify the accounts targeted by the activity, determine whether authentication attempts were successful, and assess whether the alert represents a true security incident.

The investigation also examines activity following the successful authentication to determine whether the attacker was able to escalate privileges or establish persistence on the compromised system.

## Alert Details

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
| **Primary Log Source** | Linux SSH Authentication Logs |
| **Investigation Tool** | Splunk SIEM |
