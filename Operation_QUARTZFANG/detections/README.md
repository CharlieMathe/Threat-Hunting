# Detections: Operation QUARTZFANG

Three detection rules built and backtested during the QUARTZFANG hunt by Károly Mathe. The environment is simulated (Log(n) Pacific cyber range), so these results are not a production false-positive rate.

| Rule | Catches | Data source | ATT&CK | Backtest on this hunt | Status |
|---|---|---|---|---|---|
| [DR-01](DR-01_cron_spawned_interpreter_portal.kql) | Cron starting python, perl, sh, bash or nc on the portal | `DeviceProcessEvents_CL` | T1053.003, T1059.006 | Attack 1 hit, baseline 0 of 1,219 events, after 0 of 359 | Tested |
| [DR-02](DR-02_postgres_enumeration_statements.kql) | Catalogue reads, `password_hash` reads and bare `SELECT *` on the database | `Syslog` (postgres) | T1213.006 | Attack 6 hits; baseline 4 hits, unresolved | Draft |
| [DR-03](DR-03_account_created_by_interpreter.kql) | `useradd`, `adduser` or `usermod` started by an interpreter or cron | `DeviceProcessEvents_CL` | T1136.001, T1098 | Attack 2 hits, baseline 0 of 1,219 events | Tested |

## What is in this folder

| Path | Contents |
|---|---|
| `DR-0x_*.kql` | The scheduled form of each rule (runs every hour, looks back one hour), with purpose, validation and blind spots in the header |
| `sentinel/` | Each rule as a Microsoft Sentinel scheduled analytics rule in YAML, with tactics, techniques and entity mappings |
| `validation/` | The backtest query for each rule: baseline (15 to 20 Sep), attack window (20 Sep 06:30 to 08:30) and after |

## Tuning caveats

- **DR-01:** estates that run every cron job through `/bin/sh -c` will flood it. Add a command-line filter there (for example `socket` or `connect`).
- **DR-02:** the same six statements appeared on 19 Sep at 23:12 on a connection labelled as the application. I could not prove what that was, so the rule stays a draft. It also misses targeted reads that name their columns.
- **DR-03:** misses direct edits to `/etc/passwd` or `/etc/sudoers`. Next step is file events on those paths and `authorized_keys`.

The custom table names (`_CL`) come from the hunt workspace. In a standard workspace the tables are `DeviceProcessEvents` and `Syslog`, and Sentinel's time column is `TimeGenerated`, so adjust the names before importing.

Full reasoning for each rule: [Detection Rules Built](../QUARTZFANG_Threat_Hunt_Report.md#-detection-rules-built) in the report.
