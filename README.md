# Threat Hunt Report: Suspected Data Exfiltration from PIP'd Employee

## Platforms and Languages Leveraged
- Windows Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Scenario

An employee named John Doe, working in a sensitive department, recently was placed on a performance improvement plan (PIP). After reacting poorly to the news, management raised concerns that John may attempt to steal proprietary information before leaving the company. John is a local administrator on his device and is not restricted in which applications he can run, raising the possibility that he could archive sensitive data and move it to a private location or external destination. The goal of this hunt is to investigate John's device activity and determine whether any exfiltration attempt is underway.

### High-Level IoC Discovery Plan

- **Check `DeviceFileEvents`** for creation or movement of archive files (e.g. `.zip`) that could contain staged company data.
- **Check `DeviceProcessEvents`** for execution of archive utilities (WinRAR, 7-Zip, WinZip, PeaZip, etc.) around the time any archives were created.
- **Check `DeviceNetworkEvents`** for outbound connections in the same window that could indicate the archived data left the host.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table for Archive Activity

Searched for any `.zip` file activity on the target device. Results showed a pattern of `.zip` files being created and moved into a local **"backup"** folder at regular intervals.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ty-win-vm"
| where FileName endswith ".zip"
| order by Timestamp desc
```

---

### 2. Searched the `DeviceProcessEvents` Table Around the Archive Timestamp

Took the timestamp of one of the discovered `.zip` file creation events and searched `DeviceProcessEvents` for activity ±2 minutes around it. This revealed a PowerShell script that **silently installed 7-Zip** and then used it to compress employee data into an archive.

**Query used to locate events:**

```kql
let VMName = "ty-win-vm";
let specificTime = datetime(2026-06-16T15:14:02.6031458Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

---

### 3. Searched the `DeviceNetworkEvents` Table for Exfiltration Evidence

Searched the same time window for any outbound network activity that would indicate the archived data was transmitted off the host. **No corresponding network exfiltration activity was found** in the current log scope.

**Query used to locate events:**

```kql
let VMName = "ty-win-vm";
let specificTime = datetime(2026-06-16T15:14:02.6031458Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

---

## Timeline Summary and Findings

A search of `DeviceFileEvents` surfaced repeated `.zip` archive creation on the target device, with files being moved into a local "backup" folder. Pivoting to `DeviceProcessEvents` around the timestamp of one of these archive events showed a PowerShell script silently installing 7-Zip and using it to compress employee data — consistent with data staging behavior. A follow-up search of `DeviceNetworkEvents` in the same window found no evidence of the archived data leaving the network.

---

## MITRE ATT&CK TTP Alignment

| Technique | Tactic | Reason |
|---|---|---|
| **T1059.001** — Command and Scripting Interpreter: PowerShell | Execution | A PowerShell script silently installed 7-Zip and automated the archiving of employee data. |
| **T1560.001** — Archive Collected Data: Archive via Utility | Collection | 7-Zip was used to compress employee data into `.zip` archives, a classic pre-exfiltration staging technique. |
| **T1560** — Archive Collected Data | Collection | Parent technique covering the systematic archiving of sensitive data into compressed files at regular intervals. |
| **T1074.001** — Data Staged: Local Data Staging | Collection | Archives were moved to a local "backup" folder, consistent with staging data before potential exfiltration. |
| **T1105** — Ingress Tool Transfer *(partial/suspected)* | Command and Control | 7-Zip was silently installed via PowerShell, suggesting it was downloaded or dropped onto the host to support the operation. |
| **T1036** — Masquerading *(potential)* | Defense Evasion | Storing archives in a folder named "backup" may indicate an attempt to blend in with legitimate backup activity. |
| **T1053.005** — Scheduled Task/Job *(to investigate)* | Execution / Persistence | Archives were created at regular intervals, consistent with a scheduled task automating the collection. |
| **T1048 / T1041** — Exfiltration *(unconfirmed, monitor)* | Exfiltration | No network exfiltration was observed in current log scope, but staged/archived data is a common precursor and remains on the watchlist. |

---

## Summary

The investigation confirmed repeated, automated archiving of employee data on John Doe's device via a silently-installed instance of 7-Zip, triggered through PowerShell, with archives staged locally in a "backup" folder. No evidence of the data leaving the network over the observed window was identified, meaning exfiltration itself could not be confirmed — but the staging behavior alone represents a significant risk indicator.

---

## Response Taken

The system was immediately isolated upon discovering the archiving activity. Findings — including the regular PowerShell-driven archive creation — were relayed to the employee's manager. No evidence of exfiltration was found. The team is standing by for further instructions from management.
