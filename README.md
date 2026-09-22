# Threat Hunt Report: Data Exfiltration by PIP'd Employee

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

### 1. File Activity — Archive Creation and Staging

Searched for `.zip` file activity on the target device.

```kql
DeviceFileEvents
| where DeviceName == "ty-win-vm"
| where FileName endswith ".zip"
| order by Timestamp desc
```

| Timestamp | ActionType | FileName | FolderPath |
|---|---|---|---|
| Jun 16, 2026 11:14:00 AM | FileCreated | employee-data-20260616151350.zip | `C:\ProgramData\employee-data-20260616151350.zip` |
| Jun 16, 2026 11:14:02 AM | FileRenamed | employee-data-20260616151350.zip | `C:\ProgramData\backup\employee-data-20260616151350.zip` |

An archive was created and moved into a local "backup" folder within two seconds.

<img width="2339" height="508" alt="image" src="https://github.com/user-attachments/assets/7d626d81-f0f1-43cb-8aac-53d86253f980" />

---

### 2. Process Activity — Script Execution and Compression

Searched `DeviceProcessEvents` for activity ±2 minutes around the archive creation timestamp.

```kql
let VMName = "ty-win-vm";
let specificTime = datetime(2026-06-16T15:14:02.6031458Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

| Timestamp | FileName | ProcessCommandLine |
|---|---|---|
| 11:13:41 AM | powershell_ise.exe | `PowerShell_ISE.exe` |
| 11:13:49 AM | cmd.exe | `"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` |
| 11:13:50 AM | powershell.exe | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` |
| 11:14:00 AM | 7z.exe | `"7z.exe" a C:\ProgramData\employee-data-20260616151350.zip C:\ProgramData\employee-data-temp20260616151350.csv` |

`PowerShell_ISE.exe` was launched at 11:13:41 AM, roughly 8 seconds before `exfiltratedata.ps1` was executed via `cmd.exe` → `powershell.exe -ExecutionPolicy Bypass`, suggesting the script was authored or edited interactively on the host. The script then directly invoked `7z.exe` to compress the employee data.

<img width="2953" height="501" alt="image" src="https://github.com/user-attachments/assets/ac82b535-6916-4b55-b005-74767fc9edb8" />

---

### 3. Network Activity — Outbound Transfer

Searched `DeviceNetworkEvents` for outbound connections around the same window.

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

| Timestamp | RemoteUrl | RemoteIP:Port | Initiating Process |
|---|---|---|---|
| 11:13:50 AM | sacyberrange00.blob.core.windows.net | 20.60.181.193:443 | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` |
| 11:14:02 AM | **sacyberrangedanger.blob.core.windows.net** | 20.60.133.132:443 | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` |

Both connections originate from the `exfiltratedata.ps1` process (account: `ty-win-vm\ty`). The second connection, to `sacyberrangedanger.blob.core.windows.net`, occurs in the same second the archive was moved into the `backup` folder — indicating the archived data was transmitted to Azure Blob Storage immediately after staging.

<img width="1965" height="712" alt="image" src="https://github.com/user-attachments/assets/8577eb7f-2c10-4f42-8f3a-4fd59da8ab41" />

---

## Timeline Summary

| Time | Activity |
|---|---|
| 11:13:41 AM | `PowerShell_ISE.exe` opened — script likely authored/edited interactively |
| 11:13:49 AM | `cmd.exe` spawns `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` |
| 11:13:50 AM | `exfiltratedata.ps1` connects to `sacyberrange00.blob.core.windows.net` |
| 11:14:00 AM | `7z.exe` compresses employee data into `employee-data-20260616151350.zip` |
| 11:14:02 AM | Archive moved to `C:\ProgramData\backup\`, and `exfiltratedata.ps1` connects to `sacyberrangedanger.blob.core.windows.net` |

The sequence reflects a complete collection-and-exfiltration chain: script execution → data compression → archive staging → outbound transfer to Azure Blob Storage.

---

## MITRE ATT&CK TTP Alignment

| Technique | Tactic | Reason |
|---|---|---|
| **T1059.001** — Command and Scripting Interpreter: PowerShell | Execution | `cmd.exe` spawned `powershell.exe -ExecutionPolicy Bypass` to run `exfiltratedata.ps1`, orchestrating compression and exfiltration of employee data. |
| **T1560.001** — Archive Collected Data: Archive via Utility | Collection | `7z.exe` was invoked directly to compress employee data into a `.zip` archive prior to transfer. |
| **T1560** — Archive Collected Data | Collection | Parent technique covering the systematic archiving of sensitive data into a compressed file immediately before it left the host. |
| **T1074.001** — Data Staged: Local Data Staging | Collection | The archive was created in `C:\ProgramData\` and moved into a local "backup" folder before being transmitted. |
| **T1036** — Masquerading *(potential)* | Defense Evasion | Storing the archive in a folder named "backup" may indicate an attempt to blend in with legitimate backup activity. |
| **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration | `exfiltratedata.ps1` made outbound HTTPS connections to Azure Blob Storage endpoints, including `sacyberrangedanger.blob.core.windows.net`, timed to the archive's staging. |
| **T1048 / T1041** — Exfiltration Over Alternative Protocol / C2 Channel | Exfiltration | Data left the host over HTTPS to cloud storage rather than an established C2 channel, consistent with T1567.002 above. |
| **T1053.005** — Scheduled Task/Job *(to investigate)* | Execution / Persistence | Archives were reportedly created at regular intervals; not yet confirmed against scheduled task logs. |

---

## Summary

`exfiltratedata.ps1`, launched via `cmd.exe` from `C:\programdata\`, compressed employee data using `7z.exe`, staged the resulting archive in a local "backup" folder, and — in the same second — transmitted data over HTTPS to an Azure Blob Storage endpoint (`sacyberrangedanger.blob.core.windows.net`). An earlier connection from the same process to a second storage account (`sacyberrange00.blob.core.windows.net`) at script start may represent an initial test connection or a separate upload and warrants further review. The evidence supports that data was both staged and exfiltrated from the host using a valid exfiltration technique. The security team has visibility into and access to both destination storage accounts, so the data did not reach an external or unauthorized third party — but the exfiltration technique itself executed successfully and represents a real detection and access-control gap that needs to be addressed.

---

## Response Taken

The system was immediately isolated upon discovering the archiving activity. Findings were relayed to the employee's manager. Because the destination storage accounts are within the company's own visibility and control, the exfiltrated data did not reach an external party — but this does not lessen the severity of an employee deliberately staging and transmitting company data without authorization. Recommended next steps:

- Escalate to HR/Legal given confirmed unauthorized data exfiltration by an employee on a PIP.
- Confirm who created and controls the `sacyberrangedanger.blob.core.windows.net` and `sacyberrange00.blob.core.windows.net` storage accounts, and whether John had any legitimate business reason to access them.
- Recover and statically analyze `C:\programdata\exfiltratedata.ps1` (if still present) to confirm exactly what was uploaded and via what method (e.g. SAS token, `Invoke-WebRequest -Method Put`, AzCopy).
- Identify the source and full contents of `employee-data-temp20260616151350.csv` to scope what data was disclosed.
- Review `DeviceLogonEvents` and authentication logs for the `ty` account around 11:13–11:15 AM to confirm whether this was interactive (John at the keyboard) or remote/scripted activity.
- Preserve all EDR data and the isolated VM disk for forensic/legal chain of custody.
- Revoke or rotate any credentials/SAS tokens used to reach the destination storage accounts to prevent further unauthorized access.

The team is standing by for further instructions from management.
