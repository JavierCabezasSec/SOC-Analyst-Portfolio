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

### Investigation Objectives

- Analyze the security risks associated with SSH in Linux environments.
- Identify how exposed services can provide attackers with an entry point.
- Use process and parent-child relationships to trace suspicious activity back to its origin.
- Analyze Linux logs for evidence of initial-access activity.
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

**Answer:** `2024-10-02`

### Evidence

![SSH authentication evidence](task2-ssh-authentication.png)

```bash
cat /var/log/auth.log | grep "sshd"
```

</td>
</tr>
</table>

<table width="120%">
<tr>
<td width="100%">

## Question 2 — SSH Authentication Method

**Question:** Did the `ubuntu` user use SSH keys instead of a password for the above found date?

**Answer:** **Yes**

### Evidence

I reviewed the SSH authentication logs using the following command:

```bash
cat /var/log/auth.log | grep "sshd"
```

The relevant log entry contains:

```text
Oct 22 08:28:00 ip-10-10-249-101 sshd[809]: Accepted publickey for ubuntu from 10.9.254.186 port 64824 ssh2: RSA SHA256:krhp4o9yYOyVKmAd7PAsdHrKQGJtjIQjt4w0K9R4kXg
```

The `Accepted publickey` portion confirms that the `ubuntu` account authenticated using an SSH public key rather than password authentication.

> **Verification note:** The evidence shown above is dated **Oct 22**, while Question 1 currently lists **2024-10-02**. These dates should be verified against the original Task 2 Question 1 evidence before considering this section final.

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

When investigating SSH attacks, a useful starting point is to review successful SSH logins and look for signs that separate normal activity from suspicious activity. Key indicators include:

- **Authentication method:** Determine whether password, public-key, or another authentication method was used and whether that method is expected for the account and environment.
- **Source IP:** External or untrusted IP addresses should be investigated.
- **Login timing and history:** Unusual login times or successful logins following repeated failed attempts may indicate a compromise.

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

### Evidence

I reviewed the SSH authentication logs using the following command:

```bash
cat /var/log/auth.log | grep "Failed password"
```

This command filters the authentication log for failed password attempts, allowing me to identify when repeated SSH password failures began.

![SSH Brute Force Discovery](task-3-question-1.png)

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

This produced authentication events for users who successfully authenticated, resulting in a broad list that did not identify the usernames the botnet attempted to breach.

The search was not useful for this question because `Accepted` filters for successful authentication attempts, while the question is asking which users the botnet attempted to compromise. Failed authentication attempts and attempts against invalid users provide more relevant evidence for identifying targeted usernames.

### Evidence

![Task 3 - Question 2](task-3-question-2.png)

### Refined Search

Since the scenario involves a botnet attempting to compromise user accounts, I focused on authentication events that indicated attempted access rather than successful authentication. I therefore changed my search to specifically identify attempts made against invalid or nonexistent usernames.

```bash
grep -E "Invalid user" /var/log/auth.log
```

![Task 3 - Question 2 Continued](task-3-question-2-continued.png)

This produced a more concise result and allowed me to identify the invalid usernames targeted during this portion of the SSH attack activity.

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

The `Invalid user` results identify invalid or nonexistent usernames targeted during the observed attack activity. They should not automatically be interpreted as every account the botnet attempted to compromise if valid usernames were also targeted.

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

I narrowed the search to `Accepted` events because the question asks which IP managed to breach the account, indicating that a successful authentication should be present.

**Issue:** The results still included successful authentications for multiple users, such as `ubuntu`.

For example:

![Task 3 - Question 3 — Continued II](task-3-question-3-continued-II.png)

```text
Accepted password for ubuntu from 10.66.86.216
Accepted password for ubuntu from 10.66.105.3
Accepted password for ubuntu from 10.66.96.246
```

These IP addresses successfully authenticated, but they authenticated as `ubuntu`, not `root`.

### Step 3 — Filter for the Root Account

```bash
grep "Accepted.*root" /var/log/auth.log
```

I further narrowed the search by combining `Accepted` with `root`.

- **`Accepted`** → The authentication was successful.
- **`.*`** → Allows any characters between `Accepted` and `root`.
- **`root`** → Limits the results to successful authentication involving the root account.

This removes successful authentications for other accounts and isolates the relevant successful `root` login.

### Conclusion

The final search is the most relevant because it specifically identifies **successful authentication events involving the `root` account**, rather than successful logins to other accounts such as `ubuntu`.

The relevant log entry identifies:

```text
Accepted ... for root from 91.224.92.79
```

The evidence establishes three important points:

- **`Accepted`** → The authentication was successful.
- **`for root`** → The account successfully authenticated was `root`.
- **`from 91.224.92.79`** → `91.224.92.79` was the source IP address.

Therefore, the IP associated with the successful SSH authentication of the `root` account was:

**Answer:** `91.224.92.79`

![Task 3 - Question 3 — Continued III](task-3-question-3-continued-III-three.png)

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

Process-level evidence can help answer these questions.

This is why a SOC investigation should correlate **application-level evidence with operating-system-level evidence** whenever possible.

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

</td>
</tr>
</table>
