<!--
UPDATE WITH EVERY NEW HUNT (checked by hunt_preflight.py):
1. Add a row to "The hunts" table with the live link.
2. Update the Totals line: N hunts, N flags, N unique MITRE ATT&CK IDs, N hosts analysed. Keep that wording. The numbers must equal the top stats on index.html.
3. Upload to the repo root next to index.html.
-->

# Threat Hunting Portfolio

Threat hunt investigations by **Károly Mathe**, built during the Log(n) Pacific internship. Each hunt reconstructs an attack chain from initial access to impact using Microsoft Sentinel, KQL and MITRE ATT&CK, then turns what it found into detection rules and lessons.

**Live site:** [charliemathe.github.io/Threat-Hunting](https://charliemathe.github.io/Threat-Hunting/)

> All scenarios run in simulated environments on the Log(n) Pacific cyber range. Companies, hosts, users and data are fictional. Nothing here is live production data.

---

## The hunts

| # | Hunt | Theme | Flags | Report |
|---|------|-------|-------|--------|
| 01 | EmberForge | Source leak, Active Directory breach | 20 | [Open](https://charliemathe.github.io/Threat-Hunting/EmberForge-Source-Leak/) |
| 02 | Signals After the Noise 2 | Post-intrusion, healthcare, Defender for Endpoint | 29 | [Open](https://charliemathe.github.io/Threat-Hunting/Signals-After-the-Noise-2/) |
| 03 | Second Vector | M365 identity compromise, BEC, silent exfiltration | 37 | [Open](https://charliemathe.github.io/Threat-Hunting/Second-Vector/) |
| 04 | JadePuffer | Agentic ransomware on a Linux estate, 2 detection rules | 25 | [Open](https://charliemathe.github.io/Threat-Hunting/JadePuffer/) |

**Totals:** 4 hunts, 111 flags, 58 unique MITRE ATT&CK IDs, 10 hosts analysed.

---

## How a hunt folder is organised

```
<Hunt-Name>/
  index.html      The full report as a web page (collapsible sections)
  <Report>.md     The same report as markdown
  README.md       Short summary: what it is, what I did, rules, what I learned
  Screenshots/    Evidence used in the report
```

Start with the hunt's `README.md` for the ten-second version, then open the HTML report for the full flag-by-flag analysis.

---

## What every report contains

- Executive summary and key findings
- Attack timeline and attacker profile
- Flag analysis: finding, evidence, KQL query, screenshot, detection recommendation
- MITRE ATT&CK summary table and OWASP mapping (MITRE ATLAS when AI is involved)
- Benign look-alikes ruled out, and telemetry gaps written down instead of guessed
- Remediation checklist
- **What I'd Improve:** what didn't work, why it matters, what I would do next time

---

## Toolkit

| | |
|---|---|
| **Platform** | Microsoft Sentinel, Azure Log Analytics, Microsoft Defender for Endpoint, KQL |
| **Telemetry** | Sysmon, Defender device tables, Entra ID sign-in logs, Microsoft Graph activity logs, M365 email and cloud app events, Linux audit, syslog and container logs, LLM agent logs |
| **Frameworks** | MITRE ATT&CK, MITRE ATLAS, OWASP Top 10, OWASP LLM Top 10, Pyramid of Pain |
| **Output** | Detection rules (KQL), hunt reports (HTML and markdown), timeline reconstruction |

---

## Method in one line

Hypothesis, then queries with an explicit time interval, then evidence, then a detection that survives a change of payload or IP. Counts in the reports are my own observed values.

---

## Contact

[LinkedIn](https://www.linkedin.com/in/karoly-mathe/) | [GitHub](https://github.com/CharlieMathe/Threat-Hunting)

*Károly Mathe | Log(n) Pacific internship portfolio*
