# Linux Threat Detection Investigation Series

## Threat Detection 1 — Initial Access

<table width="120%">
<tr>
<td width="100%">

### Lab Environment

This investigation was conducted in a controlled TryHackMe lab environment using the Linux Threat Detection 1 machine.

- **Platform:** TryHackMe
- **Room:** Linux Threat Detection 1 v5
- **Lab Target:** `10.66.178.85`
- **Focus:** Linux initial access and threat detection

</td>
</tr>
</table>

<table width="120%">
<tr>
<td width="100%">

### Investigation Overview

The purpose of this lab is to investigate how attackers can gain initial access to Linux systems through common attack techniques. The investigation focuses on SSH security, Internet-exposed services, and process analysis to identify how suspicious activity originated and how it can be detected through available Linux logs.

The exercises build on Linux logging concepts and provide hands-on practice identifying activity that could indicate an attempted or successful compromise.

Rather than treating a single suspicious event as proof of compromise, this investigation focuses on **correlating multiple pieces of evidence**, determining what each artifact actually establishes, and identifying what additional evidence would be required to reach a stronger conclusion.

### Investigation Objectives

- Analyze the security risks associated with SSH in Linux environments.
- Identify how exposed services can provide attackers with an entry point.
- Use process and parent-child relationships to trace suspicious activity back to its origin.
- Analyze Linux logs for evidence of initial-access activity.
- Correlate authentication, application, and host-level evidence.
- Develop a better understanding of how a SOC analyst can detect and investigate Linux attacks.

</td>
</tr>
</table>

---

# Task 2 — Initial Access via SSH

<table width="120%">
<tr>
<td width="100%">

## Question 1 — First SSH Login

**Question:** When did the `ubuntu` user log in via SSH for the first time?

**Answer:** `October 22 at 08:28:00`

### Investigation Approach

To determine when the `ubuntu` user first logged in through SSH, I reviewed the Linux authentication log:

```bash
cat /var/log/auth.log | grep "sshd"
```

I selected `/var/log/auth.log` because it contains authentication-related events on Ubuntu systems. I then filtered the results for `sshd`, the SSH daemon, to narrow the investigation specifically to SSH-related activity.

This produced several SSH events, including SSH service startup messages and successful authentication events.

![SSH authentication evidence](task2-ssh-authentication.png)

### Reviewing the Results

The first two entries showed the SSH service starting and listening on port 22:

```text
Oct 22 08:27:52 ip-10-10-249-101 sshd[661]: Server listening on 0.0.0.0 port 22.
Oct 22 08:27:52 ip-10-10-249-101 sshd[661]: Server listening on :: port 22.
```

These entries establish that the SSH service was listening for connections, but they do **not** indicate that the `ubuntu` user had logged in.

I therefore looked for the first authentication event involving the `ubuntu` account.

The relevant entry was:

```text
Oct 22 08:28:00 ip-10-10-249-101 sshd[809]: Accepted publickey for ubuntu from 10.9.254.186 port 64824 ssh2: RSA SHA256:krhp4o9yYOyVKmAd7PAsdHrKQGJtjIQjt4w0K9R4kXg
```

This event contains several important pieces of evidence:

- **`Oct 22 08:28:00`** — The timestamp of the authentication event.
- **`sshd[809]`** — The SSH daemon process that handled the authentication.
- **`Accepted`** — The authentication attempt was successful.
- **`publickey`** — Public-key authentication was used.
- **`for ubuntu`** — The account that successfully authenticated was `ubuntu`.
- **`from 10.9.254.186`** — The connection originated from `10.9.254.186`.
- **`port 64824`** — The source system used port `64824` for the connection.
- **`RSA SHA256:...`** — The log records the fingerprint associated with the SSH key used for authentication.

A second authentication event occurred at the same timestamp:

```text
Oct 22 08:28:00 ip-10-10-249-101 sshd[869]: Accepted publickey for ubuntu from 10.9.254.186 port 64825 ssh2: RSA SHA256:krhp4o9yYOyVKmAd7PAsdHrKQGJtjIQjt4w0K9R4kXg
```

This shows another successful `ubuntu` authentication from the same source IP using the same public-key fingerprint, but through a different source port.

The authentication events were also followed by:

```text
Oct 22 08:28:00 ip-10-10-249-101 sshd[809]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)
```

This provides additional evidence that an SSH session was opened for the `ubuntu` account after successful authentication.

### SOC Analyst Interpretation

From an investigation perspective, the important distinction is between **SSH service availability** and **successful user authentication**.

The `Server listening` messages show that SSH was available on port 22, but the `Accepted publickey for ubuntu` event is the evidence that the `ubuntu` account successfully authenticated.

The subsequent `session opened for user ubuntu` event further confirms that a session was established.

Therefore, the first observed successful SSH login for the `ubuntu` account in the available authentication log occurred on:

**October 22 at 08:28:00**

### Why This Finding Is Significant

This establishes an important point in the SSH authentication timeline.

As a SOC analyst, I would use this event as a starting point for further investigation because it provides:

- The **account** that authenticated.
- The **timestamp** of the authentication.
- The **source IP address**.
- The **authentication method**.
- The **SSH key fingerprint**.
- Evidence that a **session was opened**.

This information can then be correlated with other activity before and after the login.

For example, if this were an active investigation, I would investigate whether the source IP had generated previous failed authentication attempts, whether the login time was expected, and what commands or processes were executed after the session was established.

### Important Investigation Limitation

The authentication log establishes that the `ubuntu` account successfully authenticated through SSH. It does **not**, by itself, establish that the login was malicious or that the system was compromised.

A successful SSH login could represent legitimate administrative activity, an authorized user, or potentially an attacker using valid credentials or a compromised SSH key.

Additional evidence would therefore be required to determine whether the authentication was authorized or malicious.

### Finding

**First observed successful SSH login for `ubuntu`: `October 22 at 08:28:00`**

**Source IP:** `10.9.254.186`

**Authentication method:** `publickey`

**Result:** Successful authentication followed by an opened SSH session.

</td>
</tr>
</table>

<table width="120%">
<tr>
<td width="100%">

## Question 2 — SSH Authentication Method

**Question:** Did the `ubuntu` user use SSH keys instead of a password for the above found date?

**Answer:** **Yes**

### Investigation Approach

I reviewed the SSH authentication logs using:

```bash
cat /var/log/auth.log | grep "sshd"
```

The relevant authentication event was:

```text
Oct 22 08:28:00 ip-10-10-249-101 sshd[809]: Accepted publickey for ubuntu from 10.9.254.186 port 64824 ssh2: RSA SHA256:krhp4o9yYOyVKmAd7PAsdHrKQGJtjIQjt4w0K9R4kXg
```

### Analysis

The most important portion of the event is:

```text
Accepted publickey for ubuntu
```

This can be broken down into:

- **`Accepted`** — The authentication succeeded.
- **`publickey`** — SSH public-key authentication was used.
- **`for ubuntu`** — The authenticated account was `ubuntu`.

The log therefore indicates that the account authenticated using an SSH key rather than password authentication.

The event also identifies:

```text
from 10.9.254.186
```

which identifies the source IP associated with the successful authentication.

The RSA SHA256 value is the fingerprint associated with the SSH key presented during authentication.

### SOC Analyst Significance

Authentication method is useful during an investigation because it helps establish **how access was obtained**.

However, the authentication method alone does not determine whether the activity was legitimate or malicious.

Public-key authentication can be completely legitimate, but a compromised or stolen private key could also potentially be used by an unauthorized party.

Therefore, in a real investigation, I would correlate the authentication event with:

- The source IP address.
- Previous authentication failures.
- The expected owner of the account.
- The expected SSH key or key fingerprint.
- Login timing.
- Commands executed after authentication.
- Process and network activity following the session.

### Finding

The `ubuntu` account successfully authenticated through SSH using **public-key authentication** from `10.9.254.186` at **08:28:00 on October 22**.

</td>
</tr>
</table>

---

# Task 3 — Detecting SSH Attacks

<table width="120%">
<tr>
<td width="100%">

## Investigation Overview

SSH attacks can occur when public SSH access is exposed, password-based authentication is allowed, and users have weak passwords. Attackers can repeatedly attempt passwords through brute force until they successfully gain access.

When investigating SSH attacks, a useful starting point is to review successful and failed SSH authentication events and look for relationships between them.

Key indicators include:

- **Authentication method:** Determine whether password, public-key, or another authentication method was used and whether that method is expected for the account and environment.
- **Source IP:** Identify where the authentication attempts originated and determine whether the source is expected or suspicious.
- **Authentication history:** Determine whether successful authentication occurred after repeated failures.
- **Targeted accounts:** Identify which usernames were repeatedly targeted.
- **Timing and frequency:** Look for repeated authentication attempts occurring over a short period.
- **Post-authentication activity:** Determine what happened after successful access.

A suspicious SSH login should not automatically be considered malicious. Additional investigation should include the username and whether the login was expected, the reputation and ownership of the source IP, previous login attempts or brute-force activity, and what actions occurred after the login.

The goal of this task is to use SSH authentication logs to identify suspicious login activity and determine what additional evidence is needed before reaching a final conclusion.

</td>
</tr>
</table>

<table width="120%">
<tr>
<td width="100%">

## Question 1 — SSH Brute Force Start

**Question:** When did the SSH password brute force start?

**Answer:** The brute force began at: `2025-08-21`

### Investigation Approach

I reviewed the SSH authentication log using:

```bash
cat /var/log/auth.log | grep "Failed password"
```

This search filters the authentication log for failed password-based SSH authentication attempts.

The purpose of this search was to isolate authentication failures from other SSH activity and identify the earliest observed failed-password activity associated with the attack.

![SSH Brute Force Discovery](task-3-question-1.png)

### SOC Analyst Interpretation

A failed password event indicates that an authentication attempt was unsuccessful.

Multiple failed attempts occurring against accounts from the same source, or against multiple accounts in a short period, can provide evidence of password-guessing or brute-force activity.

The date shown by the lab represents the beginning of the observed failed-password activity:

**August 21, 2025**

However, failed authentication attempts alone do not prove that an account was compromised.

To determine whether the attack resulted in successful access, I would correlate these failures with:

- Successful `Accepted` authentication events.
- The usernames being targeted.
- Source IP addresses.
- Number and frequency of attempts.
- Authentication methods.
- Activity occurring after any successful login.

### Finding

The earliest observed SSH failed-password activity associated with the lab's brute-force investigation began on:

**`2025-08-21`**

</td>
</tr>
</table>

<table width="120%">
<tr>
<td width="100%">

## Question 2 — Which four users did the botnet attempt to breach?

**Answer Format:** Separate by a comma, in alphabetical order.

**Answer:** `root, roy, sol, user`

### Initial Search

I initially searched the authentication log using:

```bash
cat /var/log/auth.log | grep -E 'Accepted'
```

This produced authentication events for users who successfully authenticated.

However, this search did not directly answer the question because the investigation was asking which usernames the botnet attempted to compromise, not which users successfully authenticated.

### Investigative Pivot

The initial query demonstrated an important SOC investigation principle: **the first search does not always produce the evidence required to answer the investigative question.**

The `Accepted` filter is useful for identifying successful authentication, but it is not the appropriate filter for identifying attempted access against invalid usernames.

I therefore changed the search based on the evidence I needed.

### Refined Search

I searched specifically for invalid-user authentication attempts:

```bash
grep -E "Invalid user" /var/log/auth.log
```

![Task 3 - Question 2 Continued](task-3-question-2-continued.png)

This produced a more targeted view of SSH attempts against usernames that did not exist on the system.

The usernames identified by the lab were:

```text
root
roy
sol
user
```

### Why This Search Was More Relevant

The `Invalid user` message is generated when SSH receives an authentication attempt for a username that is not recognized as a valid account on the system.

This makes the search useful for identifying usernames being tested by an automated attacker or botnet.

The search is more directly aligned with the investigative question because it focuses on **attempted access**, rather than successful authentication.

### Evidence Limitation

The `Invalid user` search identifies invalid or nonexistent usernames targeted during the observed attack activity.

It does **not** necessarily identify every account the botnet attempted to compromise.

If the attacker also targeted valid usernames, those attempts would appear through different authentication events, such as failed password attempts.

### Finding

The four usernames identified by the lab were:

**`root, roy, sol, user`**

</td>
</tr>
</table>

<table width="120%">
<tr>
<td width="100%">

## Analysis — Why I Used This Command

### Command

```bash
grep -E "Invalid user" /var/log/auth.log
```

### Breaking Down the Command

- **`grep`** — Searches a file for matching text.
- **`-E`** — Enables Extended Regular Expressions, allowing more complex search patterns.
- **`"Invalid user"`** — Searches specifically for SSH attempts made against usernames that were not valid on the system.
- **`/var/log/auth.log`** — The authentication log containing SSH login activity.

### My Reasoning

Because the investigation focused on identifying **usernames that the botnet attempted to compromise**, I narrowed the search to `"Invalid user"`.

This provided a more targeted and concise view of the attack activity compared to searching for multiple SSH authentication events at once.

The refined search demonstrates an investigative workflow:

```text
Initial Question
      ↓
Broad Search
      ↓
Review Results
      ↓
Determine Evidence Gap
      ↓
Refine Search
      ↓
Identify Relevant Events
      ↓
Validate Finding
```

This is an important SOC workflow because the objective is not simply to run commands, but to select searches based on the evidence required to answer the investigative question.

</td>
</tr>
</table>

<table width="120%">
<tr>
<td width="100%">

## Question 3 — Which IP managed to breach the root user?

**Objective:** Identify the source IP address associated with the successful SSH authentication of the `root` account.

### Step 1 — Review the Authentication Log

```bash
cat /var/log/auth.log
```

![Task 3 - Question 3](task-3-question-3.png)

I initially reviewed the full authentication log to understand the available SSH activity.

**Issue:** The results were too broad and contained multiple types of authentication events.

### Step 2 — Search for Successful Authentications

```bash
grep "Accepted" /var/log/auth.log
```

![Task 3 - Question 3](task-3-question-3.png)

I narrowed the search to `Accepted` events because the investigation required a successful authentication event.

This reduced the amount of unrelated authentication data and allowed me to focus on accounts that successfully authenticated.

**Issue:** The results still included successful authentications for multiple users, including `ubuntu`.

For example:

![Task 3 - Question 3 — Continued II](task-3-question-3-continued-II.png)

```text
Accepted password for ubuntu from 10.66.86.216
Accepted password for ubuntu from 10.66.105.3
Accepted password for ubuntu from 10.66.96.246
```

These events demonstrate successful SSH authentication, but they do not answer the question because the authenticated account was `ubuntu`, not `root`.

### Step 3 — Filter for the Root Account

I refined the search again:

```bash
grep "Accepted.*root" /var/log/auth.log
```

This search combines the successful-authentication indicator with the specific account being investigated.

- **`Accepted`** → The authentication was successful.
- **`.*`** → Allows any characters between `Accepted` and `root`.
- **`root`** → Limits the results to events involving the `root` account.

This removes successful authentications for unrelated accounts and isolates the relevant `root` authentication event.

### Conclusion

The final search produced the relevant event:

```text
Accepted ... for root from 91.224.92.79
```

The event establishes:

- **`Accepted`** → Authentication succeeded.
- **`for root`** → The authenticated account was `root`.
- **`from 91.224.92.79`** → The source IP was `91.224.92.79`.

Therefore, the source IP associated with the successful SSH authentication of the `root` account was:

**Answer:** `91.224.92.79`

![Task 3 - Question 3 — Continued III](task-3-question-3-continued-III-three.png)

### Investigation Limitation

The authentication event establishes that the `root` account successfully authenticated through SSH from `91.224.92.79`.

It does not independently establish everything that occurred after authentication.

A complete investigation would continue by examining:

- Commands executed after authentication.
- Process creation.
- File modifications.
- Network connections.
- Privilege-related activity.
- Additional authentication events.
- Persistence mechanisms.

This distinction is important because **successful authentication is evidence of access, but not necessarily evidence of the full scope of compromise**.

</td>
</tr>
</table>

---

# Task 4 — Initial Access via Services

<table width="120%">
<tr>
<td width="100%">

## Investigation Overview

This task focuses on identifying **initial access through publicly exposed services**, with an emphasis on web applications running on Linux systems. Public-facing services can become an entry point for attackers when applications contain vulnerabilities or are improperly configured.

The investigation uses application and web server logs to identify suspicious requests that may indicate exploitation, command injection, or other malicious activity. These logs can provide valuable evidence of attacker activity, although they may not reveal the complete sequence of events occurring on the underlying Linux system.

A key part of the investigation is distinguishing normal application requests from activity that may indicate an attacker is attempting to execute commands or exploit a vulnerable service.

## Objective

The objective is to analyze the available web application logs, identify suspicious requests, and determine whether the activity provides evidence of exploitation against the public-facing service.

The investigation focuses on:

- Identifying the **source IP address** associated with suspicious activity.
- Identifying the **public-facing service or application** being targeted.
- Analyzing request parameters for evidence of **command injection or exploitation**.
- Determining whether the attacker appears to have attempted **OS command execution**.
- Assessing whether the available evidence indicates a potential compromise of the underlying **Linux system**.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Linux and Public-Facing Services

Linux systems commonly host services that are accessible over a network, including:

- Web servers
- Email servers
- Databases
- VPN services
- Firewall software
- Development and IT management tools

When these services are exposed to the Internet, vulnerabilities within the applications can provide attackers with an entry point into the underlying system.

A vulnerability in one public-facing application can potentially allow an attacker to execute commands, access sensitive information, or gain additional control over the host.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Application Log Analysis

Application and web server logs can provide valuable evidence when investigating suspicious activity.

Depending on the service, logs may reveal:

- Source IP addresses
- Requested URLs
- HTTP methods
- Request parameters
- Authentication activity
- Application errors
- Suspicious commands or payloads

For example, web server logs may reveal suspicious requests against a vulnerable endpoint, while database logs may reveal unusual SQL queries.

However, application logs do not always provide the complete execution chain. Additional host-level evidence may be required to determine what happened after a suspicious request reached the application.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## MITRE ATT&CK Mapping

The activity investigated in this task maps to **MITRE ATT&CK T1190 — Exploit Public-Facing Application**.

The technique describes adversaries exploiting weaknesses in Internet-facing applications or services to gain initial access to a system.

**Technique:** T1190 — Exploit Public-Facing Application

**MITRE ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/)

In this investigation, the suspicious requests were directed at the publicly accessible `/ping` endpoint of the TryPingMe application.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Application Vulnerability

The TryPingMe application accepts user-supplied input through the `host` parameter.

A normal request might look like:

```text
GET /ping?host=3.109.33.76
```

The application is intended to execute a ping command against the supplied host.

However, if the input is not properly validated or sanitized, an attacker may attempt to inject additional operating-system commands into the parameter.

This creates a potential **command injection** vulnerability.

For example:

```text
GET /ping?host=;whoami
```

The semicolon can be used to separate commands in a shell command line, allowing the attacker to attempt execution of an additional command after the intended `ping` operation.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Attack Progression

The access log demonstrates a progression from normal requests to increasingly suspicious activity.

| Stage | Example Activity | Interpretation |
|---|---|---|
| Normal request | `host=3.109.33.76` | Normal use of the ping functionality |
| Normal request | `host=54.36.19.83` | Normal-looking host input |
| Testing | `host=hello` | Invalid or unusual host value |
| Command testing | `host=whoami` | Possible attempt to execute an OS command |
| Command injection | `host=;whoami` | Shell command injection attempt |
| Command injection | `host=;ls` | Attempt to execute `ls` |
| File targeting | `host=;cat+/opt/trypingme/main.py` | Attempt to read a Python source file |

This progression provides context for understanding how the attacker moved from testing the application to attempting operating-system command execution.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Question 4 — What is the path to the Python file the attacker attempted to open?

**Question:** What is the path to the Python file the attacker attempted to open?

**Answer:** `/opt/trypingme/main.py`

### Step 1 — Review the Nginx Access Log

I began by reviewing the Nginx access log to identify suspicious requests against the web application.

```bash
cat /var/log/nginx/access.log
```

While reviewing the requests, I noticed activity from the same external IP address:

```text
10.14.105.255
```

The requests were targeting the `/ping` endpoint and included values such as:

```text
GET /ping?host=hello HTTP/1.1
GET /ping?host=whoami HTTP/1.1
```

The `whoami` request stood out because `whoami` is a Linux command used to identify the current user.

This suggested that the attacker may have been testing whether input supplied to the `host` parameter was being interpreted as a system command.

![Task 4 Question 1 - The Path](Task-4Question-1-thepath.png)

### Step 2 — Search for Python File References

Since the question asks specifically for a Python file, I narrowed the search to requests containing the `.py` extension.

```bash
grep -E "\.py" /var/log/nginx/access.log
```

![Task 4 Question 1 - The Path Continued](Task-4Question-1-thepath-pt2.png)

The escaped period (`\.`) searches for the literal `.py` extension rather than treating `.` as a regular-expression wildcard.

This reduces the large access log to requests that reference Python files, making it easier to identify the file involved in the attack.

### Step 3 — Identify the Suspicious Request

The search revealed the following request:

```text
10.14.105.255 - - [26/Aug/2025:20:10:49 +0000] "GET /ping?host=;cat+/opt/trypingme/main.py HTTP/1.1" 200 330 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
```

The important portion is:

```text
host=;cat+/opt/trypingme/main.py
```

This is significant because the attacker is no longer simply supplying a hostname or IP address to the `/ping` function.

Instead, the `host` parameter contains a shell command:

```text
cat /opt/trypingme/main.py
```

The `cat` command is commonly used on Linux to read and display the contents of a file.

Therefore, the request indicates an attempt to use the application's `host` parameter to execute a command that would read a Python source file from the server.

### Step 4 — Understand the Request Structure

The relevant portion of the request can be broken down as:

```text
/ping
   ↓
host=
   ↓
;
   ↓
cat
   ↓
/opt/trypingme/main.py
```

The semicolon is significant because it can be used to separate commands in a shell command line.

The attacker therefore appears to have attempted to inject a command into the `host` parameter and use `cat` to read the Python source file.

The `+` character in the HTTP request represents a space when interpreted as form-style URL encoding, resulting in:

```text
cat /opt/trypingme/main.py
```

The file path is directly visible in the request:

```text
/opt/trypingme/main.py
```

### Conclusion

The Nginx access log provides a direct connection between the suspicious `/ping` request and the Python file targeted by the attacker.

The evidence shows:

- **Source:** `10.14.105.255`
- **Endpoint:** `/ping`
- **Parameter:** `host`
- **Command:** `cat`
- **Target file:** `/opt/trypingme/main.py`

The request demonstrates an attempted command injection through the `/ping` endpoint, with the attacker attempting to use `cat` to read the Python source file.

The HTTP `200` status alone does not independently prove that the file contents were successfully returned to the attacker. It establishes that the web server returned a successful HTTP response to the request. Additional application or host-level evidence can provide stronger confirmation of execution and file access.

**Answer:** `/opt/trypingme/main.py`

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Question 5 — Looking inside the opened file, what's the flag you see there?

**Answer:** `THM{i_am_vulnerable!}`

### Investigation

Since Question 4 identified `/opt/trypingme/main.py` as the file the attacker attempted to read, I next inspected that file to determine what information may have been exposed.

```bash
cat /opt/trypingme/main.py
```

![Task 4 Question 2 - Flag](Task-4Question-2-Flag.png)

The source code revealed the following comment:

```text
# THM{i_am_vulnerable!}
```

![Task 4 Question 2 - Flag Captured](Task-4Question-2-Flag-Captured.png)

The flag was embedded directly within the Python application's source code.

### Conclusion

The Nginx access log showed an attempted command injection targeting `/opt/trypingme/main.py`. After identifying the targeted file, I inspected its contents and found the flag embedded in the source code.

This creates a useful evidence chain:

```text
Suspicious HTTP Request
        ↓
/ping Endpoint
        ↓
Command Injection Attempt
        ↓
Targeted Python File
        ↓
Local File Inspection
        ↓
Flag Identified
```

**Answer:** `THM{i_am_vulnerable!}`

</td>
</tr>
</table>

---

# Task 5 — Building Process Tree

<table width="120%">
<tr>
<td width="100%">

## Investigation Overview

Application logs can provide valuable evidence when investigating **suspected service exploitation**, as demonstrated in the previous task. However, application logs may not always be available, complete, or sufficient to determine how an attacker gained initial access.

Process tree analysis provides another method for investigating suspicious activity by tracing a process back through its parent and grandparent processes. This allows a SOC analyst to determine what launched a suspicious command and whether it originated from legitimate activity, a system process, or a potentially compromised application.

In this task, I will use Linux `auditd` logs and the `ausearch` command to trace suspicious processes back to their origin.

The investigation will focus on the **TryPingMe application** examined in the previous task and use process relationships to determine how suspicious commands were executed.

## What to Expect

This task will focus on using **process IDs (`PID`)** and **parent process IDs (`PPID`)** to reconstruct the sequence of processes involved in suspicious activity.

The investigation will include:

- Searching `auditd` logs for suspicious commands.
- Identifying the `PID` and `PPID` associated with a process.
- Using `ausearch` to trace a suspicious process back to its parent.
- Continuing up the process tree until identifying the process responsible for launching the suspicious activity.
- Examining other child processes launched by the application.
- Identifying commands that may provide stronger evidence of service exploitation or compromise.
- Using the process tree to understand how initial access may have led to command execution.

The goal is to move beyond identifying **what command was executed** and determine **why it was executed and what process caused it to run**.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Investigation Objective

The objective of this task is to use **process tree analysis** to trace suspicious command execution back to its originating process.

By examining the relationship between **PIDs** and **PPIDs**, I can determine:

- Which process executed the suspicious command.
- Which parent process launched it.
- Whether the command originated from the TryPingMe application.
- Whether additional child processes were created.
- How the activity may connect the public-facing application to command execution.

This provides additional context that may not be visible from application access logs alone.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Why Process Tree Analysis Matters

A process tree shows the relationship between processes by identifying which process created or launched another process.

For example, suspicious activity may follow a sequence such as:

```text
Web Server
    |
    └── Application
            |
            └── Shell
                    |
                    └── Suspicious Command
```

A SOC analyst can use this relationship to determine whether a suspicious command was:

- Executed directly by a user.
- Launched by a legitimate system process.
- Spawned by a web server or application.
- Created through a shell.
- Potentially associated with exploitation of a vulnerable service.

This is especially useful when investigating command injection because the command itself may not explain **how it was executed**.

The process tree can provide the missing relationship between the vulnerable application and the command that ultimately ran on the system.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Linux `auditd` Logs

Linux `auditd` can record process execution and other security-relevant activity.

For this investigation, the audit logs can provide information such as:

- Process ID (`PID`)
- Parent Process ID (`PPID`)
- Executed command
- Executable path
- User associated with the process
- Time of execution

This information can be used to reconstruct the sequence of events surrounding suspicious process activity.

The `ausearch` command can then be used to search and filter the audit logs for specific events.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Process IDs and Parent Process IDs

A **Process ID (`PID`)** uniquely identifies a running process.

A **Parent Process ID (`PPID`)** identifies the process that launched the current process.

For example:

```text
PID: 2500
PPID: 1800
```

This indicates that process `2500` was launched by process `1800`.

By following the `PPID` relationship, an analyst can move backward through the process tree and determine where suspicious execution originated.

For example:

```text
PID 2500
   |
   └── PPID 1800
          |
          └── PPID 1200
                 |
                 └── PPID 1
```

This allows the analyst to reconstruct the parent-child relationship between processes.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Searching the Audit Logs

The first step is to search the Linux audit logs for suspicious process activity.

```bash
ausearch -m EXECVE
```

The `EXECVE` audit event is useful because it records information associated with program execution.

The results can then be reviewed for suspicious commands or processes associated with the TryPingMe application.

### Investigative Reasoning

The purpose of this search is not simply to find a suspicious command.

The objective is to identify the **process execution event** associated with the command and obtain the identifiers needed to trace its origin.

Once a suspicious execution event is identified, the `PID` and `PPID` can be used to continue the investigation.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Tracing a Suspicious Process

Once a suspicious process is identified, its **PID** can be used to investigate the associated audit events.

For example:

```bash
ausearch -p <PID>
```

This searches the audit logs for events associated with the specified process ID.

The resulting information can be used to identify the process's:

- Command
- Executable
- PID
- PPID
- User
- Execution details

The PPID can then be used to identify the process responsible for launching the suspicious process.

### Investigative Reasoning

This step is important because identifying the suspicious command alone does not tell me what caused it to execute.

By obtaining the `PPID`, I can move one level backward in the process hierarchy and determine which process launched the suspicious process.

I can then repeat the process until the originating application or service is identified.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Following the Parent Process

After identifying the suspicious process, I can use its **PPID** to trace the activity backward.

For example:

```text
Suspicious Command
        |
        └── PID
              |
              └── PPID
                    |
                    └── Parent Process
                          |
                          └── Parent's PPID
                                |
                                └── Previous Process
```

This process can be repeated until the originating process is identified.

The purpose is not simply to find the suspicious command, but to establish the **execution chain** that caused the command to run.

### Investigative Questions

At each stage of the process tree, I would ask:

- What process created this process?
- Was the parent process expected?
- What executable launched it?
- Which user was associated with the process?
- Does the parent process belong to the TryPingMe application?
- Were additional child processes created?
- Does the process relationship support the command-injection hypothesis identified in Task 4?

These questions help distinguish a suspicious command from evidence of an actual execution chain.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Investigation Analysis

The process tree provides additional evidence that can be correlated with the application logs from the previous task.

In Task 4, the Nginx access logs showed suspicious requests against the `/ping` endpoint, including command-injection attempts such as:

```text
GET /ping?host=;whoami
```

and:

```text
GET /ping?host=;ls
```

The application log established that commands were being supplied through the vulnerable `host` parameter.

Process analysis provides another layer of evidence by determining **which process actually executed the resulting command**.

This creates a stronger investigation chain:

```text
External Source
      |
      v
Public-Facing Web Application
      |
      v
Vulnerable /ping Endpoint
      |
      v
Command Injection
      |
      v
Shell / Process Execution
      |
      v
Suspicious Command
```

Correlating these sources allows a SOC analyst to connect network/application activity with operating-system-level process execution.

### Evidence Standard

The goal is to determine whether the process evidence **supports or contradicts** the hypothesis developed from the application logs.

For example, if the process tree shows the TryPingMe application launching a shell followed by `whoami` or `ls`, that would provide stronger host-level evidence connecting the web request to command execution.

If the expected process relationship is not present, the analyst should not assume execution occurred simply because the HTTP request contained a command-injection payload.

This distinction is important when separating:

- **Attack attempt**
- **Successful execution**
- **Potential compromise**

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Evidence Correlation

Process tree analysis should not be performed in isolation.

The strongest investigation results come from correlating multiple sources of evidence.

For this investigation, relevant evidence includes:

| Evidence Source | What It Can Show |
|---|---|
| Nginx access logs | HTTP requests sent to the application |
| Application logs | Application-level activity and errors |
| `auditd` logs | Process execution and process relationships |
| PID | Specific process involved in execution |
| PPID | Process responsible for launching another process |
| Command-line information | Commands executed by the process |

By correlating these sources, the analyst can build a more complete timeline of the activity.

The investigation can therefore progress from:

```text
Network Request
      ↓
Application Request
      ↓
Suspicious Input
      ↓
Process Execution
      ↓
Parent Process
      ↓
Originating Application
```

Each additional evidence source can increase confidence in the reconstructed sequence of events.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Why Application Logs Alone May Not Be Enough

Application logs can show what requests reached an application, but they may not provide the complete execution chain.

For example, an access log may show:

```text
GET /ping?host=;whoami
```

This indicates that a command-injection payload was submitted to the application.

However, the access log alone may not show:

- Which shell interpreted the command.
- Which process executed the command.
- Which parent process launched it.
- What additional child processes were created.
- What other commands were executed afterward.
- Whether the attempted command actually executed successfully.

Process-level evidence can help answer these questions.

This is why a SOC investigation should correlate **application-level evidence with operating-system-level evidence** whenever possible.

### Example of the Evidence Gap

An application log may establish:

```text
Attacker
   ↓
Submitted command-injection payload
```

But additional host-level evidence is needed to establish:

```text
Attacker
   ↓
Submitted command-injection payload
   ↓
Application processed payload
   ↓
Shell/process created
   ↓
Command executed
   ↓
Child process activity occurred
```

The process tree therefore helps bridge the gap between **what was requested** and **what actually executed on the host**.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Investigation Takeaway

The key lesson from this task is that identifying a suspicious command is only one part of an investigation.

A SOC analyst should also determine:

1. **What command was executed?**
2. **Which process executed it?**
3. **What process launched it?**
4. **Where did that parent process originate?**
5. **Was the execution associated with a legitimate application or suspicious activity?**
6. **What additional processes or commands were created afterward?**

Following these relationships allows the analyst to move from a single suspicious event toward a more complete execution chain.

The investigation should continually distinguish between what the evidence **directly proves**, what it **suggests**, and what still requires additional validation.

</td>
</tr>
</table>

---

<table width="120%">
<tr>
<td width="100%">

## Investigation Conclusion

Process tree analysis provides an important layer of evidence when investigating suspected exploitation of a public-facing Linux application.

By using `auditd`, `ausearch`, PIDs, and PPIDs, a SOC analyst can trace suspicious commands through their parent-child relationships and determine how the activity originated.

When combined with the Nginx access logs from the previous task, process analysis can help connect an external request to application execution and ultimately to operating-system-level activity.

This demonstrates the importance of correlating **network, application, and host-based evidence** when investigating potential initial access and command execution.

The overall investigation follows an evidence-driven progression:

```text
SSH Authentication Logs
        ↓
Identify Initial Access Activity
        ↓
Public-Facing Application
        ↓
Suspicious HTTP Requests
        ↓
Command Injection Attempt
        ↓
Targeted File
        ↓
Process Execution Analysis
        ↓
Parent/Child Process Relationships
        ↓
Determine the Execution Chain
```

This approach demonstrates how a SOC analyst can move from an individual log entry toward a broader understanding of **how access occurred, what activity followed, and what evidence supports the investigation's conclusions**.

</td>
</tr>
</table>
