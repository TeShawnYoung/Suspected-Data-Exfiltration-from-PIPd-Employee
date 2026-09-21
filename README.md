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

Searched for any `.zip` file activity on the target device. Results showed a pattern of `.zip` files being created and then moved into a local **"backup"** folder at regular intervals.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ty-win-vm"
| where FileName endswith ".zip"
| order by Timestamp desc
```

Key events isolated from this export (`query_1.csv`):

| Timestamp | ActionType | FileName | FolderPath |
|---|---|---|---|
| Jun 16, 2026 11:14:00 AM | FileCreated | employee-data-20260616151350.zip | `C:\ProgramData\employee-data-20260616151350.zip` |
| Jun 16, 2026 11:14:02 AM | FileRenamed | employee-data-20260616151350.zip | `C:\ProgramData\backup\employee-data-20260616151350.zip` |

<img width="2025" height="490" alt="image" src="https://github.com/user-attachments/assets/f994bbd9-c5b6-4f6a-924c-87db07e148f4" />

---

### 2. Searched the `DeviceProcessEvents` Table Around the Archive Timestamp

Took the timestamp of the discovered `.zip` file creation event and searched `DeviceProcessEvents` for activity ±2 minutes around it. This revealed a `cmd.exe`-spawned PowerShell process executing a script named `exfiltratedata.ps1` from `C:\programdata\`, followed shortly after by direct invocation of `7z.exe` to compress employee data into an archive.

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

Key events isolated from this export (`query_2.csv`):

| Timestamp | FileName | ProcessCommandLine |
|---|---|---|
| 11:13:41 AM | powershell_ise.exe | `PowerShell_ISE.exe` |
| 11:13:49 AM | cmd.exe | `"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` |
| 11:13:50 AM | powershell.exe | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` |
| 11:14:00 AM | 7z.exe | `"7z.exe" a C:\ProgramData\employee-data-20260616151350.zip C:\ProgramData\employee-data-temp20260616151350.csv` |

Note: no separate install event for 7-Zip was found in this export. `7z.exe` was invoked directly, either from a pre-existing installation or a binary already staged on disk — the original assumption of a "silent install" is not supported by this data and has been removed pending further evidence (e.g. `DeviceFileEvents` showing `7z.exe`/`7z.dll` being written to disk, or an MSI/installer process).

The `powershell_ise.exe` launch at 11:13:41 AM, roughly 8 seconds before the script executed, is also notable — it suggests the script may have been authored or edited interactively on the host rather than dropped pre-built, which is relevant to attribution.

<img width="2953" height="501" alt="image" src="https://github.com/user-attachments/assets/ac82b535-6916-4b55-b005-74767fc9edb8" />

---

### 3. Searched the `DeviceNetworkEvents` Table for Exfiltration Evidence

**Correction:** the export originally attached to this step (`query_3.csv`) was a duplicate of the `DeviceProcessEvents` export from Step 2 — the `DeviceNetworkEvents` query below was never actually captured, which is why this section previously (and incorrectly) concluded no exfiltration activity was found. The query has been re-run against a widened window to avoid clipping events near the edge of the original ±2 minute scope, and the correct results are reflected below.

**Query used to locate events:**

```kql
let VMName = "ty-win-vm";
let specificTime = datetime(2026-06-16T15:14:02.6031458Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, ActionType, RemoteIP, RemoteUrl, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

Key events isolated from the corrected export:

| Timestamp | RemoteUrl | RemoteIP:Port | Initiating Process |
|---|---|---|---|
| 11:13:50 AM | sacyberrange00.blob.core.windows.net | 20.60.181.193:443 | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` |
| 11:14:02 AM | **sacyberrangedanger.blob.core.windows.net** | 20.60.133.132:443 | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` |

Both connections originate from the same `exfiltratedata.ps1` PowerShell process (account: `ty-win-vm\ty`). The second connection, to `sacyberrangedanger.blob.core.windows.net`, occurs in the **same second** the `employee-data-20260616151350.zip` archive was moved into the local `backup` folder (see Step 1) — strongly indicating the archived data was transmitted to Azure Blob Storage immediately after staging.

<img width="1965" height="712" alt="image" src="https://github.com/user-attachments/assets/8577eb7f-2c10-4f42-8f3a-4fd59da8ab41" />

---

## Timeline Summary and Findings

A search of `DeviceFileEvents` surfaced `.zip` archive creation on the target device, with the archive subsequently moved into a local "backup" folder. Pivoting to `DeviceProcessEvents` around the archive timestamp showed a `cmd.exe`-spawned PowerShell process running a script named `exfiltratedata.ps1`, which directly invoked `7z.exe` to compress employee data. A corrected search of `DeviceNetworkEvents` (the original export for this step was a duplicate of the process data and has been re-run) shows that same `exfiltratedata.ps1` process making two outbound HTTPS connections to Azure Blob Storage endpoints — one at script start, and a second, to the suspiciously named `sacyberrangedanger.blob.core.windows.net`, occurring in the same second the archive was staged into the backup folder. Taken together, this is consistent with a complete collection-and-exfiltration sequence: script execution → data compression → archive staging → outbound transfer to attacker/researcher-controlled cloud storage.

---

## MITRE ATT&CK TTP Alignment

| Technique | Tactic | Reason |
|---|---|---|
| **T1059.001** — Command and Scripting Interpreter: PowerShell | Execution | `cmd.exe` spawned `powershell.exe -ExecutionPolicy Bypass` to run `exfiltratedata.ps1`, which orchestrated compression and exfiltration of employee data. |
| **T1560.001** — Archive Collected Data: Archive via Utility | Collection | `7z.exe` was invoked directly to compress employee data into a `.zip` archive prior to transfer. |
| **T1560** — Archive Collected Data | Collection | Parent technique covering the systematic archiving of sensitive data into a compressed file immediately before it left the host. |
| **T1074.001** — Data Staged: Local Data Staging | Collection | The archive was created in `C:\ProgramData\` and then moved into a local "backup" folder before being transmitted. |
| **T1036** — Masquerading *(potential)* | Defense Evasion | Storing the archive in a folder named "backup" may indicate an attempt to blend in with legitimate backup activity. |
| **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration | The `exfiltratedata.ps1` process made outbound HTTPS connections to Azure Blob Storage endpoints, including `sacyberrangedanger.blob.core.windows.net`, timed to the archive's staging into the backup folder. |
| **T1048 / T1041** — Exfiltration Over Alternative Protocol / C2 Channel | Exfiltration | Confirmed: data left the host over HTTPS to cloud storage rather than an established C2 channel, consistent with T1567.002 above. |
| **T1053.005** — Scheduled Task/Job *(to investigate)* | Execution / Persistence | Archives were reportedly created at regular intervals; this has not yet been confirmed against `DeviceProcessEvents`/scheduled task logs and remains open for follow-up. |

---

## Summary

The investigation confirmed that a PowerShell script (`exfiltratedata.ps1`), launched via `cmd.exe` from `C:\programdata\`, compressed employee data using `7z.exe`, staged the resulting archive in a local "backup" folder, and — in the same second as that staging — transmitted data over HTTPS to an Azure Blob Storage endpoint (`sacyberrangedanger.blob.core.windows.net`). An earlier connection from the same process to a second storage account (`sacyberrange00.blob.core.windows.net`) at script start may represent an initial test connection or a separate upload and warrants further review. This is no longer an unconfirmed or precursor risk indicator — the evidence supports that data was both staged and exfiltrated from the host.

**Note on process integrity:** the original version of this report concluded "no exfiltration activity found" based on a `DeviceNetworkEvents` export that was, on review, an accidental duplicate of the `DeviceProcessEvents` export from Step 2. Re-running the network query against the correct table surfaced the outbound connections above. This is retained here as a reminder to verify exported data matches the query that produced it before drawing conclusions, particularly for negative findings.

---

## Response Taken

The system was immediately isolated upon discovering the archiving activity. Findings were relayed to the employee's manager. **This report has been corrected: exfiltration to external cloud storage is confirmed**, not ruled out as originally stated. Recommended next steps:

- Escalate to HR/Legal given confirmed data exfiltration by an employee on a PIP.
- Identify the owner/access scope of the `sacyberrangedanger.blob.core.windows.net` and `sacyberrange00.blob.core.windows.net` storage accounts, and determine whether they are attacker-controlled, personal, or otherwise unauthorized.
- Recover and statically analyze `C:\programdata\exfiltratedata.ps1` (if still present) to confirm exactly what was uploaded and via what method (e.g. SAS token, `Invoke-WebRequest -Method Put`, AzCopy).
- Identify the source and full contents of `employee-data-temp20260616151350.csv` to scope what data was disclosed.
- Review `DeviceLogonEvents` and authentication logs for the `ty` account around 11:13–11:15 AM to confirm whether this was interactive (John at the keyboard) or remote/scripted activity.
- Preserve all EDR data and the isolated VM disk for forensic/legal chain of custody.

The team is standing by for further instructions from management.
