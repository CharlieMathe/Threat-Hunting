<p align="center">
  <img src="Screenshots/Jadepuffer%20logo.png" alt="JadePuffer logo" width="170">
</p>

# JadePuffer: Hunting an AI Agent That Runs Ransomware

An internship threat hunt by Károly Mathe, Log(n) Pacific. A guided exercise in Microsoft Sentinel and KQL, built on Sysdig's public disclosure of JADEPUFFER. The company, hosts and data in the exercise are fictional.

**Source:** [JADEPUFFER: Agentic Ransomware for Automated Database Extortion](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion), Sysdig Threat Research Team, 1 July 2026.
**Full report:** [HTML version](index.html) | [Markdown version](JadePuffer_Threat_Hunt_Report.md)

---

## What is JadePuffer?

Sysdig describes JadePuffer as the first documented case of agentic ransomware: an extortion operation driven from start to finish by a large language model (LLM).

The operator got in through an internet-facing Langflow server using CVE-2025-3248, a missing-authentication flaw that allows remote code execution without logging in. From there the agent looked for credentials, used default passwords to reach other services, set up persistence, and went after a database server. It encrypted 1,342 configuration items with MySQL's `AES_ENCRYPT()`, dropped the original tables, and left a ransom note in a new table. The encryption key was random, printed once and never stored, so paying would not have brought the data back.

**Why it is called agentic.** Sysdig points to payloads that contain the agent's own reasoning about priorities, failures diagnosed and fixed in seconds (one failed login became a working fix in 31 seconds), and an agent that appeared to act on planted text in the target environment.

> **The analogy.** A normal attacker is a locksmith working down a checklist. JadePuffer is a locksmith who reads the lock, thinks out loud, and corrects his own mistakes before you can blink. The thinking out loud is what gives defenders something to read.

---

## What I did in this hunt

I reconstructed a chain that ran for about 17 minutes across four hosts, using only the logs. Every query carried an explicit time interval and the run ID.

| Stage | What I found |
|-------|--------------|
| Entry | POST to `/api/v1/validate/code` on the Langflow host, CVE-2025-3248, from `64.20.53.230` |
| Execution | `python3.11` (PID 4471) spawned directly by `langflow run`, with an inline base64 payload |
| Command and control | Beacon to `45.131.66.106:4444`, restarted by a `*/30` cron job under the `langflow` account |
| Credential theft | `pg_dump` run by `langflow`, not the nightly `backup` account; secrets for 8 provider families classified in one pass |
| Discovery | A second interpreter (PID 4491) reached MinIO, MySQL and Nacos within five seconds |
| Lateral movement | MinIO accepted `minioadmin:minioadmin`; `terraform-state/credentials.json` was retrieved |
| Privilege escalation | Nacos rejected the first admin request (403), then accepted a corrected one 31 seconds later and created `svc_maint` |
| Impact | `AES_ENCRYPT` on 1,342 rows, `config_info` and `history` dropped, `README_RANSOM` table written |
| Autonomy | One human instruction at the start of the session and nothing after it: human-tasked, machine-executed |

I also:

- Ruled out look-alike activity (nightly backups, routine cron jobs, legitimate traffic on port 443, the estate's own agent) with a named field and value for each.
- Tested a colleague's claim that the payload was fileless, and showed the evidence does not support it.
- Mapped each step to MITRE ATT&CK, the Pyramid of Pain, OWASP and MITRE ATLAS.
- Wrote down the telemetry I could not answer from, instead of guessing.

![Single human instruction in the agent log](Screenshots/Only%20one%20human%20instruction.png)

---

## Detection rules I built

Both rules key on behaviour that survives a change of payload, CVE or IP. Both were validated against the full day of data.

### DR-01: Web service spawns an inline interpreter (T1190, T1059.006)

Alerts when a web or app service forks a scripting interpreter that runs inline code (`-c`, `-e`) or contains base64. The binary name `python3.11` is everywhere on an AI estate, so the rule keys on lineage.

```kql
let WebParents = dynamic(["langflow run", "uvicorn", "gunicorn", "nginx", "apache2", "php-fpm"]);
LinuxProcess_CL
| where todatetime(EventStartTime) between (datetime(2026-07-30 00:00:00) .. datetime(2026-07-31 00:00:00))
| where ActingProcessCommandLine has_any (WebParents)
| where TargetProcessName matches regex @"^(python[0-9.]*|perl|ruby|node|sh|bash|dash)$"
| where (TargetProcessCommandLine matches regex @"\s-[ce]\s") or (TargetProcessCommandLine has "base64")
| distinct EventStartTime, DvcHostname, ActingProcessCommandLine, TargetProcessName, TargetProcessId, TargetProcessCommandLine
| order by EventStartTime asc
```

**Result:** 1 hit over the full day, a true positive (PID 4471 at 19:20:04). No false positives.
**Blind spot:** the second interpreter (PID 4491) has a non-web parent, so it was not caught. A second-stage rule is the next step.

![DR-01 result](Screenshots/Detection%20rule%2001.png)

### DR-02: `pg_dump` run by a non-backup account (T1552)

Alerts when `pg_dump` runs under any account except `backup`. The tool name alone would fire every night.

```kql
LinuxProcess_CL
| where todatetime(EventStartTime) >= datetime(2026-07-30 00:00:00) and todatetime(EventStartTime) < datetime(2026-07-31 00:00:00)
| where TargetProcessName =~ "pg_dump"
| where TargetUsername !~ "backup"
| distinct EventStartTime, DvcHostname, TargetUsername, TargetProcessCommandLine, ActingProcessName
| order by EventStartTime asc
```

**Result:** 1 hit, a true positive (`langflow` on `ff-lf-01` at 19:25:07). The baseline showed 26 routine `backup` runs on `ff-db-01` that the rule correctly ignored. No false positives.
**Blind spot:** an attacker running as `backup`, renaming the binary, or using `psql` or `COPY` instead.

![DR-02 result](Screenshots/Detection%20rule%2002.png)

Both rules are one day of data only, so behaviour over longer periods is untested.

---

## What I learned

- **Lineage beats names, identity beats tools.** The same binary is benign and hostile depending on who started it and which account ran it.
- **An empty field is a collection gap, not evidence.** The SHA256 was blank on every process event, so it said nothing about this payload.
- **Pivot on a known indicator, but build the content filter too.** I found the cron entry by pivoting on the C2 IP. In a real case the IP is not known in advance.
- **Count the right unit.** I answered 10 provider families; the answer was 8, because two of the tokens were secret categories, not providers.
- **One timestamp cannot give an interval.** The `*/30` schedule was in the install command in shell history, not in the cron execution log.
- **An agent's narration is evidence, but corroborate it.** The agent logged its own reasoning, and I checked every claim against audit and syslog.
- **An unanswerable question is a finding.** The container log recorded the Docker socket request but not the response, so what the attacker saw cannot be established.

---

## What I changed

**In my own approach.** I now check that a field is populated for known-normal activity before reading meaning into emptiness. My first reading of the blank SHA256 as proof of a fileless payload would have reported a technique I had not proved, and could have stopped a reader looking for the files the attacker did write (`/tmp/.lf/keys.sql` and `/tmp/.lf/creds.json`). The full write-up is in the report under *What I'd Improve*.

**In my queries.** My second rule failed with a string-versus-datetime error. Casting the column with `todatetime()` fixed it, and I now check column types with a small `take 5` before writing a rule.

**In my report template.** This hunt added three sections that the template did not have: a TTP and MITRE analysis, a Detection Rules Built section with real validation, and a What I'd Improve section with three parts (what did not work as well as it should, why that matters, what I would do next time).

---

## Files in this folder

| File | What it is |
|------|------------|
| `index.html` | The full report as a web page |
| `JadePuffer_Threat_Hunt_Report.md` | The full report as markdown |
| `Karoly Jadepuffer notes.md` | My working notes, flag by flag |
| `Screenshots/` | Evidence screenshots used in the report |

---

*Károly Mathe | Log(n) Pacific internship | Hunt scenario based on the public Sysdig JADEPUFFER research*
