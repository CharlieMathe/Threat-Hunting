<p align="center"><img src="Screenshots/QUARTZFANG%20banner.png" alt="Operation QUARTZFANG banner: quartz-fang logo and the attack chain from SSRF to exfiltration" width="100%"></p>

# Operation QUARTZFANG: an AI agent, a document preview button and a two-hour intrusion

A hunt by Károly Mathe, Log(n) Pacific. A Microsoft Sentinel threat hunt across four Linux hosts and nine tables, reproducing an AI-orchestrated espionage campaign. The company, hosts and data are simulated.

**Source:** [Disrupting AI espionage](https://www.anthropic.com/news/disrupting-AI-espionage), Anthropic, November 2025, and [MITRE ATT&CK campaign C0062](https://attack.mitre.org/campaigns/C0062/).
**Full report:** [HTML version](https://charliemathe.github.io/Threat-Hunting/Operation_QUARTZFANG/) | [Markdown version](QUARTZFANG_Threat_Hunt_Report.md)

---

## In 60 seconds

- **What happened.** The customer portal of a simulated semiconductor company was broken into through its document preview feature (server-side request forgery). Seconds later the attacker had a root shell on the portal server.
- **Who did it.** An AI agent did the typing, with commands seconds apart. A human operator approved each stage, five times in two hours.
- **What it reached.** It used two stolen service passwords to read the customer database (including user password hashes) and browse the build registry. It was refused (403) on the admin secrets.
- **What left.** An encrypted archive was uploaded to `198.51.100.210:443` at 08:15. What it held, and whether it arrived, is not in the logs.
- **What it left behind.** A hidden administrator account, `svc_monitor`, with sudo rights and an SSH key.
- **The twist.** The agent reported two successes that never happened. Checking its claims against server logs separated fact from fiction.
- **What I built.** Three detection rules, backtested on this data, in [detections/](detections/).
- **Decisions needed now.** Isolate the portal server, delete `svc_monitor`, block the attacker addresses, rotate both stolen service passwords in a planned change, and start a breach assessment for the customer data.

**Where to start, depending on who you are**

| You are | Read |
|---|---|
| Hiring manager or team lead | This section, [What I can prove and what I can't](#what-i-can-prove-and-what-i-cant) and [What I'd improve](#what-id-improve-and-what-i-changed) |
| Detection engineer | [Detection rules I built](#detection-rules-i-built) and the [detections/](detections/) folder (KQL, Sentinel YAML, backtests) |
| Threat hunter or SOC analyst | [What I did in this hunt](#what-i-did-in-this-hunt), then the flag-by-flag walkthrough in the [full report](https://charliemathe.github.io/Threat-Hunting/Operation_QUARTZFANG/) |
| New to the topic | [What is an AI-orchestrated intrusion?](#what-is-an-ai-orchestrated-intrusion) |

---

## What is an AI-orchestrated intrusion?

A human operator gives an AI agent a target and a goal, then approves it moving from one stage to the next. The agent does the typing: it scans, exploits, steals credentials, reads databases and stages data at machine speed. In Campaign C0062 the AI did roughly 80 to 90 percent of the work, and it sometimes reported successes that never happened.

> **The analogy.** A chef who cooks fast and never stops, and a restaurant owner who only walks in four times to say "next course". The owner never chops a vegetable, and the chef sometimes says a dish is ready when it is not.

---

## What I did in this hunt

The chain ran for about two hours (06:30 to 08:30 UTC) across `sc-portal01`, `sc-db01`, `sc-registry01` and `sc-admin01`, using process, network, file, account, syslog, web, registry and agent logs. Every query carried an explicit time interval.

| Stage | What I found |
|-------|--------------|
| Recon | Three external IPs sent the same 15-path sweep in under two minutes. The preview endpoint answered 400, not 404, revealing its `url` parameter |
| Entry | SSRF on `/api/v1/preview`: `file://` refused, then `gopher://` to the local Redis accepted 18 seconds later |
| Execution | Cron, running as root, started a Python reverse shell (PID 4401) to `203.0.113.87:443` seconds after the Redis request. The cron entry itself was not logged |
| Credentials | `cat /etc/semicrest/portal.conf` under the shell: a database login and a registry login in plain text |
| Lateral movement | The stolen logins ran `SELECT *` and system catalogue reads on `sc-db01`, browsed `sc-registry01`, and got a 403 on the admin secrets |
| Staging and exfiltration | `tar`, `gzip`, `openssl` into `/tmp/.portal-cache/report.tar.gz.enc`, then a `curl` upload to `198.51.100.210:443` |
| Persistence | `svc_monitor` created, added to sudo, SSH key generated |

I also:

- Ruled out look-alikes with a field and value each: a Nessus scan (`UserAgent` `Nessus/10.6.2`), a nightly `pg_dump` (OS account `backup`, same command on three days), a connection spike (`FATAL` connection-limit errors, fewer successful statements) and normal HTTPS (gunicorn workers as `www-data`)
- Tested two of the agent's claims against the infrastructure: "extracted Kubernetes secrets" met a 403, and "admin credentials in an image layer" was only a vulnerability report request
- Mapped 20 MITRE ATT&CK techniques, the OWASP Top 10, and MITRE ATLAS for the agent's jailbreak trace
- Wrote down what the data could not answer: the Redis file write, the `env` output, the archive contents and whether the upload completed

![The rejected file:// request and the accepted gopher:// request](Screenshots/S1%20SSRF%20self-correct%20file%20to%20gopher.png)

---

## What I can prove and what I can't

**Observed in the logs:** the scan, the rejected `file://` and accepted `gopher://` preview requests, the root shell started by cron, every command it ran, its connections to the database, registry and admin API, what it asked each one for, the encrypted archive, the upload command and connection, and the backdoor account.

**Inferred, with my confidence:**
- Redis wrote the cron entry. Likely, high confidence: the shell started seconds after the request to Redis, but Redis is not logged.
- The 07:45 database reads were the attacker's. Likely, moderate confidence: they match by pattern and timing, but no connection record ties them to the shell.
- A human approved each stage. Moderate confidence: the agent log is tied to this intrusion by the session ID in the upload header, and it holds five operator messages, but the approvals could in principle have been automated.

**Unknown:** what the database returned, what `env` printed, what the archive held, whether the upload arrived, whether `svc_monitor` was ever used, and when access ended.

---

## Detection rules I built

Each rule keys on behaviour that survives a change of payload, IP or account name. The rule files, Sentinel analytics rule YAML and backtest queries are in [detections/](detections/).

### DR-01: Interpreter or shell started by cron (T1053.003)

Alerts when `cron` is the parent of python, perl, sh, bash or nc on the portal.

```kql
DeviceProcessEvents_CL
| where Timestamp > ago(1h)
| where DeviceName =~ "sc-portal01"
| where InitiatingProcessFileName =~ "cron" and FileName in~ ("python3", "python", "perl", "sh", "bash", "nc")
| project Timestamp, DeviceName, AccountName, FileName, ProcessId, ProcessCommandLine
```

**Result:** 1 hit in the attack window (the reverse shell, 06:52:52), 0 in 1,219 baseline events, 0 after.
**Blind spot:** estates that run every cron job through `sh -c` need a command-line filter.

### DR-02: Database enumeration statements (T1213.006)

Alerts on bare `SELECT * FROM table` and on reads of `information_schema`, `pg_catalog`, `pg_shadow` or `password_hash`.

**Result:** 6 hits in the attack window, all attacker statements. 4 hits on 19 Sep at 23:12, the same six statements on an application-labelled connection, cause not established. Draft.
**Blind spot:** targeted queries that name columns pass.

### DR-03: Account created or added to sudo by an interpreter (T1136.001)

Alerts when `useradd`, `adduser` or `usermod` runs with an interpreter or cron as its parent.

**Result:** 2 hits in the attack window (`useradd` and `usermod` for `svc_monitor`), 0 in the baseline.
**Blind spot:** editing `/etc/passwd` directly.

![Account creation, sudo and SSH key for svc_monitor](Screenshots/S5%20svc_monitor%20useradd%20sudo%20ssh-keygen.png)

---

## What I learned

- **The attacker's own log is a claim, not a fact.** The agent wrote that it had all the Kubernetes secrets; the admin API had returned 403.
- **The process is the identity.** Attacker and application shared the account and the source IP; every attacker connection came from one root process, PID 4401.
- **Volume is not content.** The 07:30 connection spike looked like enumeration and was connection-limit errors.
- **Tempo tells you who is typing.** Commands 6 seconds apart, then 56 minutes of silence that lines up with the operator's approvals.

---

## What I'd improve and what I changed

### 1. Verify before concluding (Flags S1.4, S3.2, S4.2)

- **What didn't work as well as it should.** Some conclusions rested on the first query that looked right. Once, the answer was hidden in a column I had not projected: `inspect_layer` was a vulnerability report request, not a layer pull. Elsewhere there was no proof at all (the Redis cron write, the 07:45 database wave), and I had to infer.
- **Why it matters.** A single query can be wrong in either direction: reporting a leak that never happened, or missing one that is in the logs.
- **What I do now.** At least one verification query per finding, from a second table or field, and every finding labelled Observed, Inferred or Unknown.

### 2. Reading the wrong port (Flag S5.1)

- **What didn't work as well as it should.** I first gave the exfiltration port as 51240. That was the local ephemeral port; the destination was 443.
- **Why it matters.** The wrong port goes into firewall blocks and IOC lists and misses the real channel.
- **What I do now.** Read `RemotePort` for the destination and sanity-check it against the protocol.

**Added to my report template after this hunt:** Observed / Inferred / Unknown labels, a `detections/` folder per hunt, and an "In 60 seconds" summary for each type of reader. **Still to add:** a validation row for a baseline hit that is neither a true nor a false positive.

---

## AI disclosure

I used Claude (Anthropic) as a hunt partner: it explained techniques, reviewed and corrected my KQL, and helped draft and format this report. I ran the queries, checked every finding against the logs and made the calls. Where the agent's claims and the logs disagreed, the logs won, the same rule I applied to Claude's suggestions.

---

## Files in this folder

| File | What it is |
|------|------------|
| `index.html` | The full report as a web page |
| `QUARTZFANG_Threat_Hunt_Report.md` | The full report as markdown |
| `detections/` | The three rules as `.kql`, as Sentinel analytics rule YAML (`detections/sentinel/`), and their backtest queries (`detections/validation/`) |
| `Screenshots/` | Evidence screenshots used in the report |

---

*Károly Mathe | Log(n) Pacific | Scenario based on public research from Anthropic and MITRE (Campaign C0062)*
