# report-Threat-Hunt-Report_CorpHealth-Traceback.md
Advanced KQL-based threat hunt and intrusion reconstruction using Microsoft Defender for Endpoint to analyze remote access, privilege escalation, payload delivery, and persistence techniques.
# 🛡️ Cyber Range Threat Hunt — CorpHealth: Traceback

**Analyst:** Fikerte Fersha  
**Platform:** Microsoft Defender for Endpoint,Log Analytics  
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

Executive Summary

During an operations activity review, I identified activity on ch-ops-wks02 that exceeded normal CorpHealth automation behavior. The telemetry revealed script misuse, outbound beaconing, credential exposure, privilege manipulation, external payload delivery via ngrok, reverse shell activity, and persistence establishment.

The intrusion began with a suspicious remote logon using chadmin from 104.164.168.17 (Vietnam, Ha Noi region). The attacker accessed a credential-related file, performed reconnaissance, pivoted into the ops.maintenance account, downloaded revshell.exe, attempted outbound communication to 13.228.171.119:11746, and established Startup folder persistence.

This activity reflects deliberate malicious behavior rather than routine maintenance automation.

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

- Defender Advanced Hunting
- Azure Log Analytics
- Entra ID SigninLogs
- Kusto Query Language (KQL)

Flag-by-Flag Findings (0–31)
---
## Flag 0 — Identify the Device

**What I was trying to prove:** Which workstation generated the suspicious cluster.  
**How I approached it:** To establish scope, I reviewed the clustered telemetry and confirmed that the suspicious activity repeatedly pointed back to a single endpoint. I used the consistent device name across process, file, and network events as the anchor for the rest of the hunt.   
**Evidence (query + results):**  
![Flag 00 evidence](<img width="975" height="615" alt="image" src="https://github.com/user-attachments/assets/99ff19c4-bf16-4ec6-99f4-46f039934637" />
)

---

## Flag 1 — Unique Maintenance File

**What I was trying to prove:** Which maintenance script was unique to this host.  
**How I approached it:** To identify what was “unique vs normal,” I searched for script-like files across devices and compared filenames. I specifically looked for a script that appeared on `ch-ops-wks02` but not elsewhere, because unique scripts are often the best signal of misuse or tampering.  
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 2 — Outbound Beacon Indicator (First Timestamp)

**What I was trying to prove:** When outbound network communication first occurred from the suspicious script.  
**How I approached it:** After identifying the unique script, I pivoted into `DeviceNetworkEvents` and filtered for events on `ch-ops-wks02` where the initiating process command line referenced `MaintenanceRunner_Distributed.ps1`. I then sorted by time ascending to identify the earliest outbound activity tied to that script.  
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 3 — Identify the Beacon Destination (IP:Port)

**What I was trying to prove:** The network destination the script attempted to reach.  
**How I approached it:** Using the same filtered set of network events, I extracted the `RemoteIP` and `RemotePort` values associated with the beacon attempt. This allowed me to express the destination in the required `IP:Port` format.   
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 4 — Confirm Successful Beacon Timestamp

**What I was trying to prove:** When the beacon succeeded (`ConnectionSuccess`).  
**How I approached it:** To confirm a successful handshake, I filtered `DeviceNetworkEvents` to `ActionType == "ConnectionSuccess"` and kept only events whose command line referenced the maintenance script and matched the same destination IP/port. I then sorted by time descending to find the most recent successful connection.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 5 — Unexpected Staging Activity (First Staging Artifact Path)

**What I was trying to prove:** The first staged artifact created in CorpHealth operational folders.  
**How I approached it:** After confirming successful outbound communication, I pivoted to `DeviceFileEvents` and filtered for file creation activity under CorpHealth and Diagnostics-related directories. I sorted by time ascending to identify the first staged artifact created during the attack window.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 6 — SHA-256 Hash of the Staged File

**What I was trying to prove:** The cryptographic fingerprint of the staged file.  
**How I approached it:** Once I had the exact file path, I queried `DeviceFileEvents` for that file and extracted the SHA-256 value from the file event metadata. This allowed me to validate the file’s integrity and support later correlation.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 7 — Identify the Duplicate Staged Artifact (Second Path)

**What I was trying to prove:** A second, similar file staged elsewhere with a different hash.  
**How I approached it:** To locate an alternate “working copy,” I searched `DeviceFileEvents` for other files containing `inventory` created around the same timeframe. I compared names, locations, and hash values to find a near-duplicate artifact stored in a different directory.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 8 — Suspicious Registry Activity

**What I was trying to prove:** Which registry key was created or touched during credential/agent-like activity.  
**How I approached it:** After identifying staging artifacts, I pivoted to `DeviceRegistryEvents` and filtered for `RegistryKeyCreated` and `RegistryValueSet` events around the same period. I focused on abnormal keys that did not match standard CorpHealth automation behavior.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 9 — Scheduled Task Persistence (First Task Created)

**What I was trying to prove:** The first scheduled task persistence artifact created by the attacker.  
**How I approached it:** To find scheduled task persistence, I searched registry event telemetry for TaskCache paths under `...\Schedule\TaskCache\Tree\`. I filtered for key creation/value set events and identified the earliest task that did not align with approved CorpHealth task naming.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 10 — Registry-based Persistence (Run Key Value Name)

**What I was trying to prove:** The value name added to the Run key.  
**How I approached it:** To confirm ephemeral Run-key persistence, I filtered registry events for Run-key activity and looked for a value being created and then deleted shortly after. I extracted the `RegistryValueName` associated with that short-lived persistence attempt.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 11 — Privilege Escalation Simulation Timestamp (ConfigAdjust)

**What I was trying to prove:** The first timestamp of the ConfigAdjust application event.  
**How I approached it:** Because the flag specifically referenced an Application log event rather than process creation, I queried `DeviceEvents` for application-type telemetry and searched `AdditionalFields` for the `ConfigAdjust` indicator. I then sorted ascending to capture the first occurrence.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 12 — AV Exclusion Attempt (ExclusionPath)

**What I was trying to prove:** The folder path the attacker attempted to exclude from Defender scanning.  
**How I approached it:** To identify Defender exclusion attempts, I searched process execution telemetry for PowerShell commands like `Add-MpPreference` / `Set-MpPreference` and extracted the `-ExclusionPath` value from the command line. I validated the folder path exactly as shown in telemetry.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 13 — PowerShell EncodedCommand (Decoded Payload)

**What I was trying to prove:** The first decoded PowerShell command executed via `-EncodedCommand`.  
**How I approached it:** I filtered `DeviceProcessEvents` for `-EncodedCommand`, extracted the Base64 blob from the command line, and decoded it using `base64_decode_tostring()` to recover the plaintext command.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 14 — Privilege Token Modification (InitiatingProcessId)

**What I was trying to prove:** Which process performed the token modification.  
**How I approached it:** I searched `DeviceEvents` for `ProcessPrimaryTokenModified` and filtered `AdditionalFields` for token change text such as `tokenChangeDescription` and `Privileges were added`. I then extracted the `InitiatingProcessId` from the event record.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 15 — Whose Token Was Modified (SID)

**What I was trying to prove:** The SID associated with the modified token.  
**How I approached it:** Using the same token modification event, I parsed the JSON in `AdditionalFields` and pulled out the user SID field (`OriginalTokenUserSid`). This allowed me to identify which principal’s token was affected.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 16 — Ingress Tool Transfer (Dropped Executable Name)

**What I was trying to prove:** Which executable was written to disk after curl activity.  
**How I approached it:** I pivoted into `DeviceFileEvents` and filtered for `.exe` file creation in user profile locations immediately after `curl.exe` network activity. I then identified the executable name that appeared in that post-download window.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 17 — External Download Source (URL/Domain)

**What I was trying to prove:** The remote URL/domain used to retrieve the tool.  
**How I approached it:** I queried `DeviceNetworkEvents` and filtered for outbound requests initiated by `curl.exe`. I reviewed the `RemoteUrl` field to capture the exact external destination used for the download.   
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 18 — Execution of the Staged Unsigned Binary (Parent Process)

**What I was trying to prove:** Which process executed `revshell.exe`.  
**How I approached it:** I searched `DeviceProcessEvents` for the execution of `revshell.exe` and examined the initiating process fields. This allowed me to confirm the parent process responsible for launching the binary.   
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 19 — External IP Contacted by Executable (Port 11746)

**What I was trying to prove:** The external IP that `revshell.exe` attempted to contact.  
**How I approached it:** I pivoted to `DeviceNetworkEvents`, filtered for events where the initiating process was `revshell.exe`, and constrained the results to the known destination port (`11746`). I then pulled the destination IP from the failed/attempted connection events.   
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 20 — Persistence via Startup Folder Placement

**What I was trying to prove:** Where persistence was established via Startup folder placement.  
**How I approached it:** I queried `DeviceFileEvents` for `.exe` file writes outside the normal user profile path and searched specifically for directories containing “Start” consistent with Startup folder abuse. I confirmed the full path used for persistence.   
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 21 — Remote Session Source Device Name

**What I was trying to prove:** The remote session device label consistently tied to attacker events.  
**How I approached it:** I reviewed multiple suspicious events and focused on the `InitiatingProcessRemoteSessionDeviceName` field. I used the value that appeared repeatedly across file, process, and network activity as the remote session identifier.  
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 22 — Remote Session IP Address

**What I was trying to prove:** The source IP associated with the attacker’s remote session metadata.  
**How I approached it:** I queried for suspicious events with remote session metadata and extracted `InitiatingProcessRemoteSessionIP`. I confirmed the IP that was consistently present across the attacker’s activity.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 23 — Internal Pivot Host Used by Attacker (10.x IP)

**What I was trying to prove:** The internal pivot IP associated with attacker remote session metadata.  
**How I approached it:** I listed distinct remote session IPs and excluded the CGNAT/relay range (`100.64.0.0/10`). From the remaining addresses, I identified the internal Azure VNet-style IP that consistently appeared in attacker metadata.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 24 — First Suspicious Logon Event (Earliest Timestamp)

**What I was trying to prove:** The earliest suspicious logon timestamp to the device.  
**How I approached it:** To identify the attacker’s earliest presence, I queried `DeviceLogonEvents` for successful logons on `ch-ops-wks02` and focused on remote-capable logon types (Network/RemoteInteractive). Sorting ascending revealed the earliest logon event in the sequence.  
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 25 — IP Used During First Suspicious Logon

**What I was trying to prove:** The remote IP associated with the earliest suspicious logon.  
**How I approached it:** Using the timestamp from Flag 24 as an anchor, I isolated the exact logon record and extracted the `RemoteIP` field. This ensured I captured the IP tied to the first event rather than later activity.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)
---

## Flag 26 — Account Used During First Suspicious Logon

**What I was trying to prove:** Which account was used in the earliest suspicious logon.  
**How I approached it:** I used the same anchored logon event and extracted the `AccountName`. Anchoring to the earliest event prevented me from accidentally selecting a later logon from the same IP.    
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 27 — Attacker Geographic Region

**What I was trying to prove:** The country/region of the attacker IPs.  
**How I approached it:** Since IP geo functions weren’t available in my workspace, I pivoted to Entra `SigninLogs` and filtered on the suspicious IP. I then used `LocationDetails` fields to retrieve the geolocation enrichment.   
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 28 — First Process Launched After Attacker Logged In

**What I was trying to prove:** The first attacker-controlled session process after logon.  
**How I approached it:** I anchored on the earliest suspicious logon timestamp and queried `DeviceProcessEvents` for processes executed under `chadmin` immediately after login. I then sorted ascending and selected the first interactive session indicator process.   
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)

---

## Flag 29 — First File the Attacker Accessed

**What I was trying to prove:** The first meaningful file opened after the attacker’s session started.  
**How I approached it:** After confirming the attacker’s interactive session, I pivoted into the earliest meaningful file access tied to that session. I focused on evidence consistent with attacker intent rather than background noise, and the first meaningful file action was the credential-related file `CH-OPS-WKS02 user-pass.txt`.  
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 30 — Next Action After Reading the File

**What I was trying to prove:** The next attacker action after viewing the credential file.  
**How I approached it:** After the file access event, I queried `DeviceProcessEvents` for the next processes executed by the attacker account and looked for an action that reflected intent rather than session noise. The first meaningful follow-on action was reconnaissance via `ipconfig.exe`.  
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

---

## Flag 31 — Next Account Accessed After Recon

**What I was trying to prove:** Which account the attacker used next after enumeration.  
**How I approached it:** Once I established the recon window, I returned to `DeviceLogonEvents` and looked for the next successful logon after enumeration completed. I filtered using the attacker’s remote IP / remote session metadata to avoid unrelated logons, then identified the next account accessed.  
**Evidence (query + results):**  
![Flag 00 evidence](../evidence/Flag-00/evidence.png)  

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

## ✅ Investigation Status

All 32 flags successfully identified and validated with telemetry evidence.

Intrusion chain fully reconstructed.

---

