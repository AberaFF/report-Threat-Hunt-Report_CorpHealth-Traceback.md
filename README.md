# report-Threat-Hunt-Report_CorpHealth-Traceback.md
Advanced KQL-based threat hunt and intrusion reconstruction using Microsoft Defender for Endpoint to analyze remote access, privilege escalation, payload delivery, and persistence techniques.
# 🛡️ Cyber Range Threat Hunt — CorpHealth: Traceback

**Analyst:** Fikerte Fersha  
**Platform:** Microsoft Defender for Endpoint  
**Language:** Kusto Query Language (KQL)  
**Scenario Type:** Operations Activity Review → Confirmed Intrusion Reconstruction  

---

## 📌 Project Overview

This repository documents a full end-to-end threat hunt investigation conducted in a simulated enterprise environment.

Using Log Analytics, and Entra ID logs, I reconstructed the complete intrusion chain on the endpoint:

`ch-ops-wks02`

The investigation identified:

- Initial remote access
- Credential file discovery
- Local reconnaissance
- Privilege escalation simulation
- Defender exclusion attempt
- Reverse shell delivery via ngrok
- External C2 communication
- Persistence via Startup folder
- Account pivoting

This was originally categorized as an *“Operations Activity Review.”*  
Telemetry analysis confirmed malicious behavior.

---

## 🎯 Investigation Objectives

- Determine whether abnormal maintenance activity was legitimate or malicious
- Identify initial access vector
- Reconstruct attacker timeline
- Detect privilege manipulation
- Confirm payload staging and execution
- Identify persistence mechanisms
- Attribute geographic origin of attacker IPs

---

## 🧰 Tools & Platforms Used

- Microsoft Defender for Endpoint
- Defender Advanced Hunting
- Azure Log Analytics
- Entra ID SigninLogs
- Kusto Query Language (KQL)

---

## 📂 Repository Structure

CorpHealth-Traceback/
├─ README.md
├─ report/
│  └─ Threat-Hunt-Report_CorpHealth-Traceback.md
└─ evidence/
   ├─ Flag-00/
   │  └─ evidence.png
   ├─ Flag-01/
   │  └─ evidence.png
   ├─ Flag-02/
   │  └─ evidence.png
   └─ ...

   ---

   
Each flag folder contains:
- The KQL query used
- The query results
- Combined screenshot evidence

---

## 🔍 Key Findings Summary

| Stage | Finding |
|-------|----------|
| Initial Access | Remote logon using `chadmin` from `104.164.168.17` |
| Region | Vietnam (Ha Noi) |
| Recon | Accessed `CH-OPS-WKS02 user-pass.txt` |
| PrivEsc | Token modification (Process ID 4888) |
| Payload Delivery | `revshell.exe` via ngrok tunnel |
| C2 IP | `13.228.171.119:11746` |
| Persistence | Startup folder placement |
| Account Pivot | `ops.maintenance` |

---

## 📊 Attack Chain Overview

1. Remote logon to `ch-ops-wks02`
2. Explorer session launch
3. Credential file opened
4. Recon via `ipconfig.exe`
5. Privilege escalation simulation
6. AV exclusion attempt
7. Encoded PowerShell execution
8. Reverse shell download
9. Outbound C2 attempt
10. Startup folder persistence
11. Account pivot

---

## 🧠 MITRE ATT&CK Techniques Observed

- T1078 — Valid Accounts
- T1059.001 — PowerShell
- T1547.001 — Startup Folder Persistence
- T1053 — Scheduled Task
- T1562 — Impair Defenses
- T1105 — Ingress Tool Transfer
- T1041 — Exfiltration Over C2 Channel
- T1021 — Remote Services
- T1087 — Account Discovery
- T1082 — System Information Discovery

---

## 🚨 Why This Matters

This investigation demonstrates how low-severity operational telemetry can mask:

- Credential abuse
- Script misuse
- Token manipulation
- Reverse shell deployment
- Stealth persistence

Without behavioral hunting using KQL, this activity could easily be misclassified as routine maintenance.

---

## 🧩 Skills Demonstrated

- Advanced KQL querying
- Timeline reconstruction
- Privilege escalation detection
- Process-chain analysis
- Network telemetry correlation
- Remote session metadata analysis
- Geolocation enrichment via Entra logs
- SOC-style documentation

---

## 📌 Analyst Notes

This project reflects a realistic SOC investigation workflow:

- Start with anomaly
- Pivot across telemetry tables
- Anchor timestamps
- Correlate process, network, registry, and logon events
- Validate each stage with evidence
- Reconstruct attacker narrative

---

## ✅ Investigation Status

All 32 flags successfully identified and validated with telemetry evidence.

Intrusion chain fully reconstructed.

---

