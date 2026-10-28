# InsiEDR Scenario Execution & Forensic Guide: SIM_IT_SABOTAGE

> **Scenario ID:** `SIM_IT_SABOTAGE`  
> **Friendly Name:** Hostile IT Sabotage, Mass File Purge & Defense Impairment  
> **Target Persona:** Terminated System Administrator / Malicious IT Insider  
> **MITRE ATT&CK:** [T1485](https://attack.mitre.org/techniques/T1485/) (Data Destruction), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) (Impair Defenses: Disable or Modify Tools), & [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Boot or Logon Autostart: Registry Run Keys)  
> **Operating Mode:** Ingestion-Only Forensics (**Detection Pipeline OFF**)  

---

## 1. Quick Reference Card

| Field | Specification |
| :--- | :--- |
| **Difficulty Level** | ⭐ Beginner (Safe Simulation in Documents Workspace) |
| **Execution Duration** | 3 – 5 minutes |
| **Required Privilege** | Local Administrator (required to write to `RunOnce` registry key) |
| **Target Operating System** | Windows 10, Windows 11, Windows Server 2016+ |
| **Primary InsiEDR Collectors** | `file-feature`, `persistence-monitor`, `process-watcher` |
| **Target Staging Path** | `$HOME\Documents\ProductionDB\` and `HKLM\...\RunOnce` |
| **Expected Sensor Signal** | `file_delete_count >= 10.0`, `modifications_detected = true`, `added_keys` containing defense tampering |

> [!NOTE]
> **Sensor Clarification:**  
> The metric `file_delete_count` is captured by **`file-feature`** (`file_feature.py`) which monitors the `$HOME` profile. `file-integrity-monitor` (`file_integrity_monitor.py`) watches for file additions and modifications (`CREATE`/`MODIFY`). Both corroborate the sabotage timeline.

---

## 2. Threat Profile & Operational Context

### Executive Summary & Operational Metaphor
Imagine a senior database administrator or infrastructure engineer who is informed on a Friday afternoon that their contract is being terminated. Filled with resentment and knowing they have approximately 30 minutes of elevated domain access remaining before their active directory credentials are revoked, they execute a scorched-earth campaign:
1. They target primary SQL database shards and backups (`.mdf`, `.ldf`, `.bak`), executing a permanent purge to destroy business operational continuity.
2. Anticipating that endpoint detection tools or system recovery scripts will react, they register a persistent startup command designed to stop security daemons upon subsequent reboots (`sc stop WinDefend`).

In cybersecurity, this destructive pattern is classified as **Hostile IT Sabotage**. Unlike intellectual property espionage—where the primary adversary objective is stealth and confidentiality loss—sabotage is characterized by sudden, high-velocity destruction of data availability (`T1485`), frequently coupled with proactive defense impairment (`T1562.001`).

### MITRE ATT&CK Alignment

| Dimension | Identifier | Description |
| :--- | :--- | :--- |
| **Tactic** | **TA0040** (Impact) | Denying system availability and destroying enterprise data assets. |
| **Technique** | **[T1485](https://attack.mitre.org/techniques/T1485/)** | **Data Destruction:** Mass deleting primary database files (`.mdf`) and recovery backups (`.bak`). |
| **Tactic** | **TA0005** (Defense Evasion) | Preventing endpoint tools from alerting or interfering with the malicious operation. |
| **Technique** | **[T1562.001](https://attack.mitre.org/techniques/T1562/001/)** | **Impair Defenses (Disable or Modify Tools):** Injecting commands into system autostart keys to terminate antivirus and EDR daemons (`sc stop WinDefend`). |
| **Technique** | **[T1547.001](https://attack.mitre.org/techniques/T1547/001/)** | **Boot or Logon Autostart Execution (Registry Run Keys):** Writing payloads into `HKLM\...\RunOnce` to execute commands at subsequent logon. |

---

## 3. InsiEDR Telemetry & Sensor Architecture

### Active Collectors & Telemetry Delta

```mermaid
flowchart LR
    Act["Insider Purges DB Files & Modifies RunOnce"] --> S1["file-feature"]
    Act --> S2["persistence-monitor"]
    Act --> S3["process-watcher"]
    
    S1 -->|Calculates file_delete_count & mass_deletion_burst| P1["Telemetry Ingestion Payload"]
    S2 -->|Audits RunOnce Autostart Key Alterations (added_keys)| P1
    S3 -->|Logs Privileged Shell & Command Execution| P1
```

#### 1. `file-feature` (Primary Destruction Sensor — `agent/collectors/file_feature.py`)
* **Underlying Engine:** Watchdog file system event collector tracking `DELETE` operations on the watched profile.
* **Sensor Baseline vs. Attack Delta:**

| Feature Name | Clean Baseline Value | Active Attack Value | Description |
| :--- | :---: | :---: | :--- |
| `file_delete_count` | `0.0` | **$\ge 16.0$** | Spike in file deletion events within a single interval. |
| `mass_deletion_burst_count` | `0` | **$\ge 1$** | Flagged when rapid mass file deletions occur. |
| `daily_file_access_entropy` | Nominal | **Elevated** | Shift in filesystem activity entropy. |

#### 2. `persistence-monitor` (Defense Impairment Sensor — `agent/collectors/persistence_monitor.py`)
* **Underlying Win32 API:** Windows Registry enumeration of `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`.
* **Sensor Baseline vs. Attack Delta:**

| Feature Name | Clean Baseline Value | Active Attack Value | Description |
| :--- | :---: | :---: | :--- |
| `modifications_detected` | `false` | **`true`** | Confirms a new or modified autorun persistence entry was discovered. |
| `added_keys` | `[]` | **`[{"command": "...sc stop WinDefend"}]`** | Exact command added to the autorun location. |

* **Raw JSON Payload Snapshot (Exact schema logged in `spool.db` and PostgreSQL):**
  ```json
  {
    "collector": "persistence-monitor",
    "status": "success",
    "collected_at": "2026-10-27T16:50:08.430Z",
    "payload": {
      "added_keys": [
        {
          "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\KillDefender",
          "command": "cmd.exe /c sc stop WinDefend"
        }
      ],
      "modified_keys": [],
      "deleted_keys": [],
      "total_monitored_keys": 48,
      "entry_count": 48,
      "modifications_detected": true
    }
  }
  ```

---

## 4. SOC Analyst Inspection Protocol (Detection Pipeline OFF)

With automated detection rules disabled (`INSIEDR_ENABLE_MODEL_PIPELINE=false`), all telemetry is committed cleanly to the database. Manually audit the scenario using **Telemetry Explorer**.

### Telemetry Explorer Inspection Steps:

```
[1. Select Time Range: 15m] ──► [2. Filter Collector: File Feature] ──► [3. Inspect Log Drawer (file_delete_count >= 16.0)]
                                  │
                                  └──► [4. Switch Collector: Persistence] ──► [5. Verify modifications_detected = true]
```

1. **Access Viewport:** Log in to the InsiEDR Web Dashboard (`http://localhost:5000/dashboard/`) and click **Telemetry Explorer**.
2. **Set Temporal Range:** Select **`15m`**.
3. **Filter Primary Destruction Sensor:** In the **Collector** dropdown, select **`File Feature`** (`file-feature`).
4. **Inspect Raw Payload:** Click on the latest log row:
   * Verify `"file_delete_count"` displays **$\ge 10.0$** (typically `16.0`).
   * Verify `"mass_deletion_burst_count"` displays **$\ge 1$**.
5. **Cross-Check Persistence Sensor:** Switch the Collector filter to **`Persistence & Run Keys`** (`persistence-monitor`):
   * Confirm `"modifications_detected": true` is visible.
   * In `"added_keys"`, confirm the `KillDefender` command targeting `sc stop WinDefend` is documented.

---

## 5. Multi-Vector Attack Execution Playbooks

Below are **5 distinct execution playbooks** to simulate hostile IT sabotage on a live Windows machine.

### Vector 1: Manual GUI / Desktop Method (Zero-Code Desktop Workflow)
*Ideal for non-technical evaluators reproducing human administrator behavior.*
1. **Create Simulated Database Files in Watched Profile:**
   * Open **File Explorer** (**Windows Key + E**), navigate to your **Documents** folder, and create `Documents\ProductionDB`.
   * Inside `Documents\ProductionDB`, create 16 dummy files named `Database_1.mdf`, `Database_2.ldf`, `Backup_1.bak`, etc.
2. **Permanent Mass Deletion (Shift + Delete):**
   * Inside `Documents\ProductionDB`, press **Ctrl + A** to select all files.
   * Press **Shift + Delete** (bypasses the Recycle Bin).
   * Click **Yes** on the confirmation prompt.
3. **Manual Autorun Key Injection:**
   * Press **Windows Key + R**, type `regedit`, and press **Enter** (approve UAC elevation).
   * Navigate to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`.
   * Right-click the right pane $\rightarrow$ **New** $\rightarrow$ **String Value**. Name it `KillDefender`.
   * Double-click `KillDefender`, set its value to `cmd.exe /c sc stop WinDefend`, and click **OK**.
*Forensic Outcome:* `file-feature` captures the rapid deletion burst, and `persistence-monitor` flags `added_keys`.

---

### Vector 2: PowerShell Automated Execution (Scripted Reproducibility)
Open an **Administrator PowerShell** terminal and run:

```powershell
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " EXECUTING SCENARIO: SIM_IT_SABOTAGE (PowerShell Vector)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Step 1: Seed 16 Simulated Database Files in User Documents
$DocsPath = [Environment]::GetFolderPath("MyDocuments")
$DbDir = Join-Path $DocsPath "ProductionDB"
if (-not (Test-Path $DbDir)) { New-Item -Path $DbDir -ItemType Directory -Force | Out-Null }

Write-Host "[+] Seeding mock production database files (.mdf, .ldf, .bak) in $DbDir..." -ForegroundColor Yellow
@("mdf", "ldf", "bak", "sql") | ForEach-Object {
    $ext = $_
    1..4 | ForEach-Object {
        $path = Join-Path $DbDir "CustomerDB_Shard_$($_).$ext"
        Set-Content -Path $path -Value "MOCK_ENTERPRISE_DATABASE_HEADER_DATA_$_"
    }
}
Write-Host "[✔] 16 simulated database assets created." -ForegroundColor Green

# Step 2: Execute Permanent Mass File Deletion
Write-Host "[+] Executing permanent mass file deletion..." -ForegroundColor Yellow
Get-ChildItem -Path $DbDir | ForEach-Object {
    Remove-Item $_.FullName -Force
    Write-Host "    [-] Purged: $($_.Name)" -ForegroundColor DarkRed
}
Write-Host "[✔] Mass deletion complete. 16 database records destroyed." -ForegroundColor Green

# Step 3: Register Defense Impairment Command in RunOnce
$RunOncePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
Write-Host "[+] Registering defense tampering payload in $RunOncePath..." -ForegroundColor Yellow
Set-ItemProperty -Path $RunOncePath -Name "KillDefender" -Value "cmd.exe /c sc stop WinDefend"
Write-Host "[✔] Defense impairment command injected into RunOnce." -ForegroundColor Green

Write-Host "`n[*] Execution finished. Wait 15 to 20 seconds for the InsiEDR agent collection sweep." -ForegroundColor Cyan
```

---

### Vector 3: Classic Windows Command Prompt (`cmd.exe`)
Open Command Prompt as **Administrator** (`cmd.exe`) and execute:

```cmd
:: 1. Seed dummy database files in Documents
mkdir "%USERPROFILE%\Documents\ProductionDB" 2>nul
echo [+] Seeding 16 dummy database files...
for /L %i in (1,1,16) do (echo DATABASE_PAYLOAD > "%USERPROFILE%\Documents\ProductionDB\CustomerDB_%i.mdf")

:: 2. Execute permanent mass file deletion
echo [+] Purging files via native del command...
del /f /q "%USERPROFILE%\Documents\ProductionDB\*.*"
echo [✔] Files deleted via cmd.exe del command!

:: 3. Simulate defense impairment command in RunOnce
echo [+] Injecting RunOnce registry persistence...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v KillDefender /t REG_SZ /d "cmd.exe /c sc stop WinDefend" /f
echo [✔] IT Sabotage simulated via cmd.exe!
```

---

### Vector 4: Shadow Copy Deletion Query / Inhibit System Recovery
*Simulates adversaries querying or purging Volume Shadow Copies (MITRE T1490).*
In an **Administrator PowerShell**:

```powershell
Write-Host "[!] Auditing Volume Shadow Copies via native vssadmin (T1490)..." -ForegroundColor Red
vssadmin list shadows
Write-Host "[✔] Shadow copy administrative query logged by process-watcher." -ForegroundColor Green
```

---

### Vector 5: Python Script / Programmatic Sabotage Simulation
If executing programmatically in Python:

```python
import winreg
from pathlib import Path

print("[+] Executing SIM_IT_SABOTAGE via Python...")

# 1. Create and mass delete 16 files in Documents
db_dir = Path.home() / "Documents" / "ProductionDB"
db_dir.mkdir(parents=True, exist_ok=True)

print(f"[+] Creating 16 database shards in {db_dir}...")
for i in range(16):
    (db_dir / f"CoreShard_{i}.mdf").write_text(f"DATABASE_HEADER_DATA_{i}")

print("[+] Executing mass deletion...")
for file in db_dir.glob("*.mdf"):
    file.unlink()
    print(f"    [-] Deleted: {file.name}")

# 2. Modify RunOnce persistence
key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
try:
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "KillDefender", 0, winreg.REG_SZ, "cmd.exe /c sc stop WinDefend")
    winreg.CloseKey(key)
    print("[✔] Successfully injected defense tampering command into RunOnce.")
except PermissionError:
    print("[!] Administrator privilege required to modify HKLM RunOnce.")

print("[✔] Python execution finished. InsiEDR agent will record the delta on next tick.")
```

---

### Wait for the Agent Sweep:
Wait **15 to 20 seconds** for the agent's 10-second tick to sweep the filesystem and registry!

---

## 6. Post-Incident Remediation & Baseline Restoration

To clean the host and return the sensor to baseline:

```powershell
Write-Host "[+] Restoring baseline: Cleaning up sabotage simulation artifacts..." -ForegroundColor Yellow

# Step 1: Remove Test Directory
$DocsPath = [Environment]::GetFolderPath("MyDocuments")
$DbDir = Join-Path $DocsPath "ProductionDB"
if (Test-Path $DbDir) {
    Remove-Item -Path $DbDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[✔] Successfully removed $DbDir." -ForegroundColor Green
}

# Step 2: Remove RunOnce Registry Entry
$RunOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
Remove-ItemProperty -Path $RunOnceKey -Name "KillDefender" -ErrorAction SilentlyContinue
Write-Host "[✔] Successfully removed RunOnce registry entry." -ForegroundColor Green

Write-Host "[✔] Host returned to pristine baseline state." -ForegroundColor Green
```

---

## 7. Machine Learning Dataset Ground-Truth Specification

When exporting ingested telemetry rows from PostgreSQL (`features` table) or ClickHouse:

### Labeling Standard
* **Evidence-Bearing Slicing:** Rows generated by `file-feature` and `persistence-monitor` falling strictly within the execution interval $[t_{\text{start}}, t_{\text{end}})$ receive **`ground_truth_label = 1`**.
* **Feature Vector Output:**

| Exported Feature Column | Value During Scenario | Standard Baseline Value | Description |
| :--- | :---: | :---: | :--- |
| **`file_delete_count`** | **$\ge 10.0$** (typically `16.0`) | `0.0` | Primary indicator of bulk file purge. |
| **`mass_deletion_burst_count`** | **$\ge 1$** | `0` | Rapid deletion heuristic flag. |
| **`modifications_detected`** | **`True`** | `False` | Boolean flag indicating autorun key tampering. |
| **`ground_truth_label`** | **`1`** | `0` | Supervised binary classification ground truth (Threat). |
| **`multiclass_label`** | **`IT_SABOTAGE`** | `BENIGN` | Multi-class threat category. |
| **`mitre_technique`** | **`T1485 / T1562.001 / T1547.001`** | `None` | MITRE ATT&CK technique mapping. |
