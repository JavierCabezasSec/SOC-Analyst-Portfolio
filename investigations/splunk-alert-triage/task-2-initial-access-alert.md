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

## Question 1 — Failed Login Attempts

### Question
How many failed login attempts were made on the user john.smith?

### Investigation
The first step was to identify authentication failures associated with the targeted account. The search filtered the `linux-alert` index for events where `user_name = john.smith` and `vendor_action = Failed`.

### Splunk Search
```splunk
index=linux-alert user_name="john.smith" vendor_action=Failed
```

### Investigation Result
The search returned approximately **500 failed authentication attempts**. These repeated failed authentication events against the same account are consistent with automated password-guessing activity.

### Finding
* **john.smith** was targeted by approximately 500 failed login attempts.

---

## Question 2 — Brute-Force Attack Duration

### Question
What was the duration of the brute-force attack in minutes?

### Investigation
After identifying the failed authentication attempts, the next step was to determine how long the activity continued. Rather than manually reviewing hundreds of events, the investigation used Splunk's `_time` field to identify the earliest and latest failed authentication attempts. The difference between these timestamps provides the duration of the attack.

### Splunk Search
```splunk
index=linux-alert user_name="john.smith" vendor_action=Failed
| stats earliest(_time) as first_attempt latest(_time) as last_attempt
| eval duration_seconds=last_attempt-first_attempt
| eval duration_minutes=round(duration_seconds/60,2)
| table first_attempt last_attempt duration_minutes
```

### Investigation Breakdown
```text
earliest(_time) ➔ Find first failed authentication
       ↓
latest(_time) ➔ Find last failed authentication
       ↓
last_attempt - first_attempt ➔ Calculate duration in seconds
       ↓
duration_seconds / 60 ➔ Convert seconds to minutes
       ↓
round(...,2) ➔ Make the result easier to read
```

### Investigation Result

| Field | Result |
| :--- | :--- |
| **First Attempt** | 09:01:50 |
| **Last Attempt** | 09:06:35 |
| **Duration** | 4.75 minutes |

The duration is approximately 5 minutes.

### Finding
* The brute-force attack lasted approximately **5 minutes**.

---

## Question 3 — Privilege Escalation

### Question
What username was the attacker able to privilege escalate to?

### Investigation
After establishing that the attacker successfully authenticated as john.smith, the investigation moved to activity occurring after the successful SSH login. The objective was to determine whether the compromised account was able to obtain elevated privileges. 

The investigation identified a sudo event showing that john.smith executed `/usr/bin/su` with the target user set to `USER=root`.

### Evidence
```text
2025-09-17 09:11:28.976
tryhackme-2404 sudo: john.smith : TTY=pts/1 ; PWD=/home/john.smith ; USER=root ; COMMAND=/usr/bin/su
```
The following event confirmed that a root session was opened:
```text
2025-09-17 09:11:28.979
sudo: pam_unix(sudo:session): session opened for user root(uid=0) by john.smith(uid=1001)
```
A subsequent su event also confirmed the transition:
```text
2025-09-17 09:11:28.984
su[3399]: (to root) root on pts/2
```

### Investigation Breakdown
```text
john.smith ➔ sudo ➔ /usr/bin/su ➔ USER=root ➔ root UID 0
```
* **Original Account:** john.smith (UID 1001)
* **Elevated Account:** root (UID 0)

### Finding
* The attacker successfully escalated privileges to the **root** account.

---

## Question 4 — Persistence Account

### Question
What is the name of the user account created by the attacker for persistence?

### Investigation
After confirming root-level access, the investigation examined subsequent activity for commands that could establish persistence. A new Linux user account is a potential persistence mechanism because it can provide the attacker with another account for future access. Instead of searching directly for a known username, the investigation searched the logs for Linux account-creation commands.

### Splunk Search
```splunk
index=linux-alert
| search "useradd" OR "adduser"
| table _time _raw
| sort _time
```

### Investigation Result
The search identified the following command:
```text
2025-09-17 09:12:10.762
tryhackme-2404 sudo: root : TTY=pts/2 ; PWD=/home/john.smith ; USER=root ; COMMAND=/usr/sbin/adduser system-utm
```
Additional account-creation events confirmed the new account:
```text
adduser[3419]: Adding new user `system-utm'
useradd[3430]: new user: name=system-utm, UID=1002, GID=1002, home=/home/system-utm, shell=/bin/bash
```
The account was also added to the users group:
```text
adduser[3419]: Adding user `system-utm' to group `users' ...
```

### Account Details

| Field | Value |
| :--- | :--- |
| **Username** | system-utm |
| **UID** | 1002 |
| **GID** | 1002 |
| **Home Directory** | /home/system-utm |
| **Shell** | /bin/bash |
| **Group** | users |
| **Creation Command** | /usr/sbin/adduser system-utm |

### Investigation Breakdown
```text
root access ➔ /usr/sbin/adduser system-utm ➔ New Linux account created ➔ UID 1002 assigned ➔ /home/system-utm created ➔ /bin/bash assigned ➔ Added to users group
```

### Finding
* The attacker created the **system-utm** account for persistence.

---

## Investigation Timeline

| Time | Activity | Finding |
| :--- | :--- | :--- |
| **09:01:50** | Failed authentication begins | john.smith targeted |
| **09:01:50–09:06:35** | Repeated failed authentication | ~500 attempts |
| **09:06:01** | Successful SSH authentication | john.smith authenticated from 10.10.242.248 |
| **09:11:28** | sudo /usr/bin/su executed | Privilege escalation to root |
| **09:11:28** | Root session opened | UID 0 confirmed |
| **09:12:10** | /usr/sbin/adduser system-utm executed | Persistence account created |
| **09:12:10** | system-utm created | UID 1002 |
| **09:12:21** | Account added to users group | Persistence established |

---

## Investigation Findings Summary

| Question | Finding |
| :--- | :--- |
| **Question 1** | Approximately 500 failed login attempts against john.smith |
| **Question 2** | Brute-force activity lasted approximately 5 minutes |
| **Question 3** | Attacker escalated privileges to root |
| **Question 4** | Attacker created the system-utm account for persistence |

---

## Attack Chain
```text
Source IP: 10.10.242.248
        ↓
Brute-Force Activity (~500 failed login attempts)
        ↓
Successful SSH Authentication: john.smith
        ↓
Privilege Escalation: sudo /usr/bin/su
        ↓
Root Access (UID 0)
        ↓
Persistence: adduser system-utm
        ↓
New Account: system-utm (UID 1002)
        ↓
Account Added to users Group
```

---

## Final Assessment
The Splunk investigation established a sequence of related authentication and post-authentication events.

The activity began with approximately 500 failed authentication attempts against john.smith over approximately 5 minutes. The attacker then successfully authenticated to the Linux host using SSH from 10.10.242.248. Following successful authentication, john.smith used `sudo /usr/bin/su` to obtain root-level privileges. Shortly afterward, the attacker executed `/usr/sbin/adduser system-utm`, creating a new Linux account with UID 1002, a home directory, a Bash shell, and membership in the users group.

The evidence establishes the following attack sequence:
```text
Brute Force ➔ Successful Authentication ➔ Privilege Escalation ➔ Root Access ➔ Account Creation ➔ Persistence
```
The investigation demonstrates the use of Splunk to correlate authentication failures, successful SSH authentication, privilege escalation, and account-creation activity into a single attack timeline.
