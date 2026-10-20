# InsiEDR Telemetry Feature Dictionary & Data Contract Specification

**Document Version**: 1.0 (Production Data Contract)  
**Target Audience**: Machine Learning Engineers, Detection Engineers, Data Scientists, and Threat Researchers  
**Dataset Reference**: [`D:\Projects\AISH\Dataset_Simulated\`](file:///D:/Projects/AISH/Dataset_Simulated/)  
**Ground Truth Manifest**: [`D:\Projects\AISH\simulation_manifest.json`](file:///D:/Projects/AISH/simulation_manifest.json)  
**Total Collector Feeds**: 20 Feeds | **Total Exported Columns**: 751 Columns (including flattened array slots)  

---

## 1. Executive Overview & Data Ingestion Contracts

### 1.1 Purpose of this Specification
This dictionary defines the official data contract between the **InsiEDR Endpoint Agent** (Rust/Python), the **Server Ingestion & Aggregation Pipeline** (FastAPI / ClickHouse / PostgreSQL), and downstream **Machine Learning Consumers** (Tier 1: Domain Isolation Forests, Tier 2: XGBoost Scenario Classifier, Tier 3: RedRVFL Temporal Risk Predictor).

To prevent label leakage, feature distortion, and double-counting during aggregation, every feature exported across all 20 CSV collector feeds is cataloged with its exact:
1. **Measurement Scope**: Host-wide, User-scoped, Process-scoped, or Session-scoped.
2. **Measurement Kind**: Instantaneous Gauge, Monotonic Counter, Rolling Window Aggregation, Event Delta, or Sampled Array Slot.
3. **Lookback & Update Interval**: Snapshot rate (~5 seconds), 300-second rolling window, 1-hour rolling window, or 24-hour cumulative.
4. **Formula & Dependencies**: Authoritative mathematical formulas and coupled denominators.
5. **Missing & Default Behavior**: Distinction between genuine zero activity, sensor offline, and uncollected indicators.
6. **Reset & Cap Behavior**: Resets on agent service restart, FIFO buffer truncation, or array slot limits.
7. **Operational Collection Status**: `LIVE_AGENT`, `SERVER_DERIVED`, or `SYNTHETIC_ONLY`.
8. **Supported Aggregation**: Valid aggregation operations (Last value, Max, Delta sum, Distribution statistics).

---

## 2. Global Envelope Fields (Present in All 20 Collector Feeds)

Every row in every collector CSV contains five standard envelope fields:

| Field Name | Type | Scope | Kind | Lookback | Formula / Origin | Default / Missing | Reset / Cap | Collection Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `timestamp` | `string` (ISO8601 UTC) | Global | Timestamp | Instantaneous | Event generation timestamp from agent high-res clock (`%Y-%m-%dT%H:%M:%S.%f`) | Non-nullable | Monotonic | `LIVE_AGENT` | Order / Sort key |
| `username` | `string` | Context | Identifier | Instantaneous | Active interactive desktop session username from `GetUserNameW` or primary logon token | `"unknown"` if no active session | N/A | `LIVE_AGENT` | Group / Filter |
| `hostname` | `string` | Host | Identifier | Static | NetBIOS / DNS workstation hostname from `GetComputerNameW` (e.g. `SOCL2-64`) | Non-nullable | N/A | `LIVE_AGENT` | Primary Entity Key |
| `agent_id` | `string` | Host | Identifier | Static | Standardized InsiEDR agent identifier (`AGENT-{hostname}`) | Non-nullable | N/A | `LIVE_AGENT` | Primary Entity Key |
| `status` | `string` | Collector | Status Gauge | Instantaneous | Execution outcome of collector cycle: `"success"`, `"failed"`, `"critical"` | Non-nullable | N/A | `LIVE_AGENT` | Filter (`status == "success"`) |

---

## 3. Operational Collection Status Taxonomy

To protect model training from shortcut learning and synthetic leakage, every feature is categorized into one of three operational statuses:

1. **`LIVE_AGENT` (Real Sensor Telemetry)**:
   * Telemetry acquired natively from endpoint operating system APIs (ETW providers, Win32 APIs, socket tables, registry hooks, NTFS USN journal).
   * Present in both baseline background and attack periods. Safe for unsupervised anomaly baselines and supervised training.
2. **`SERVER_DERIVED` (Pipeline Feature Aggregation)**:
   * Rolling rates, baseline deviation vectors, entropies, and time-window aggregations calculated by server-side workers (`BaselineEngine`, `RiskAggregator`).
   * Valid for feature tables if calculated strictly using past observations.
3. **`SYNTHETIC_ONLY` (Simulation Injections & Diagnostic Markers)**:
   * Explicit boolean flags (e.g., `credential_dumping_suspected`, `mimikatz_signatures`, `modifications_detected`) or synthetic-only fields (e.g. `post_requests`, `large_uploads` in HTTP) that were populated only during scenario injection.
   * **MANDATORY ML CONSTRAINT**: `SYNTHETIC_ONLY` fields must be **stripped or excluded** when training behavioral anomaly models to avoid trivial label leakage.
4. **`HARMONIZATION_DERIVED` (Offline Candidate Adjustments)**:
   * Features synthesized, aligned, or clamped by offline dataset preparation scripts (e.g., `clamp_dataset_invariants.py`) to explore numerical consistency and research heuristic floors in candidate research datasets.
   * **Explicit Scope**: These values are NOT computed by the live production server or endpoint agent; they represent offline research feature derivations for sensitivity benchmarking. Features incorporating `SYNTHETIC_ONLY` components inherit synthetic exclusion rules.

---

## 4. Comprehensive Feature Dictionary by Collector (All 20 Feeds)

### 4.1 `activity-monitor` (User Presence & Desktop Interaction)
*File*: `activity-monitor_dataset_*.csv` | *Scope*: Host / Active User Desktop

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `is_user_active` | `bool` | User | Gauge | ~5s | `user_idle_seconds < 60.0` | `False` | Real-time | `LIVE_AGENT` | Mode, Any |
| `last_input_tick` | `int` [ms] | Host | Counter | Monotonic | Win32 `GetLastInputInfo(&plii)` | `0` | Resets on reboot (tick count) | `LIVE_AGENT` | Last |
| `user_idle_seconds` | `float` [s] | User | Gauge | ~5s | `(GetTickCount() - last_input_tick) / 1000.0` | `0.0` | Resets on user interaction | `LIVE_AGENT` | Min, Mean, Last |

---

### 4.2 `clipboard-monitor` (Clipboard Data Staging & Harvesting)
*File*: `clipboard-monitor_dataset_*.csv` | *Scope*: Host / Desktop Session

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `clipboard_copy_count` | `int` [events] | Host | Delta | ~5s | Count of clipboard sequence increments observed during sampling interval | `0` | Zero if no change | `LIVE_AGENT` | Sum over disjoint intervals, Max |
| `clipboard_sequence` | `int` [seq] | Host | Monotonic | Cumulative | Win32 `GetClipboardSequenceNumber()` | `0` | Monotonic increment per copy; resets on reboot | `LIVE_AGENT` | Last |
| `monitor_active` | `bool` | Host | Health | Instantaneous | Clipboard hook registration status | `True` | N/A | `LIVE_AGENT` | Filter |

---

### 4.3 `decoy-monitor` (Canary Honeytoken Deception Traps)
*File*: `decoy-monitor_dataset_*.csv` | *Scope*: Host Filesystem Traps

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `current_size` | `int` [bytes] | Host | Gauge | Instantaneous | File size of planted canary files on disk | `0` | N/A | `LIVE_AGENT` | Last |
| `events_recorded` | `bool` | Host | Gauge | ~5s | True if any I/O event touched canary paths | `False` | Resets each sample | `LIVE_AGENT` | Any |
| `monitored_decoys` | `int` [files] | Host | Gauge | Static | Count of active planted honeytokens (e.g. `Admin_Passwords.xlsx`) | `1` | Static config | `LIVE_AGENT` | Last |
| `threat_triggered` | `bool` | Host | Alert | Instantaneous | `True` when unauthorized access/read to decoy is confirmed | `False` | Latched on threat | `LIVE_AGENT` / `SYNTHETIC_ONLY` | Any, Max |

---

### 4.4 `devices` (Removable Storage & USB Monitor)
*File*: `devices_dataset_*.csv` | *Scope*: Host Hardware Subsystem

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `after_hours_usb_usage` | `bool` | Host | Rule Gauge | ~5s | `usb_devices_count > 0` and timestamp outside 08:00–18:00 Mon–Fri | `False` | Real-time | `SERVER_DERIVED` | Any |
| `daily_device_connect_count` | `int` [events] | Host | Cumulative | 24 Hours | Count of distinct USB device arrivals today | `0` | Resets at midnight UTC | `SERVER_DERIVED` | Last, Max |
| `daily_device_usage_flag` | `bool` | Host | Flag | 24 Hours | True if any removable storage was connected today | `False` | Resets at midnight UTC | `SERVER_DERIVED` | Last |
| `first_usb_usage_time` | `string` | Host | Timestamp | 24 Hours | Timestamp of first USB connection today | `""` | Resets at midnight UTC | `SERVER_DERIVED` | First |
| `unauthorized_usb_detected` | `bool` | Host | Alert | ~5s | USB mass storage vendor ID / product ID not in corporate whitelist | `False` | Real-time | `LIVE_AGENT` | Any, Max |
| `usb_connect_count` | `int` [events] | Host | Delta | ~5s | USB plug-in arrival notifications (`WM_DEVICECHANGE` / ETW) | `0` | Zero if no arrival | `LIVE_AGENT` | Sum over disjoint intervals |
| `usb_device_names` | `string` | Host | Inventory | Instantaneous | Semicolon-delimited volume names and mount paths (e.g. `SanDisk Ultra USB 3.0 (E:)`) | `""` | Current mounts | `LIVE_AGENT` | Last |
| `usb_devices_count` | `int` [devices] | Host | Gauge | Instantaneous | Count of currently mounted removable drive letters | `0` | Real-time gauge | `LIVE_AGENT` | Max, Last |
| `usb_disconnect_count` | `int` [events] | Host | Delta | ~5s | USB device removal/eject events in window | `0` | Zero if no removal | `LIVE_AGENT` | Sum over disjoint intervals |

---

### 4.5 `dns-monitor` (DNS Client Resolution Telemetry)
*File*: `dns-monitor_dataset_*.csv` | *Scope*: Host Network Stack

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `channel` | `string` | Host | Config | Static | ETW channel: `"Microsoft-Windows-DNS-Client"` | `"etw"` | N/A | `LIVE_AGENT` | Identity |
| `etw_realtime_active` | `bool` | Host | Health | Instantaneous | ETW trace session active status | `True` | N/A | `LIVE_AGENT` | Filter |
| `suspicious_queries_count` | `int` [queries] | Host | Delta | ~5s | DNS queries matching DGA, dynamic DNS, or excessive length | `0` | Real-time delta | `LIVE_AGENT` | Sum, Max |
| `total_queries_captured` | `int` [queries] | Host | Delta | ~5s | Total DNS resolution queries captured in sampling cycle | `0` | Real-time delta | `LIVE_AGENT` | Sum, Mean |
| `tunneling_detected` | `bool` | Host | Alert | ~5s | Query entropy and frequency matching TXT/subdomain tunneling | `False` | Real-time | `LIVE_AGENT` | Any, Max |

---

### 4.6 `driver-monitor` (Kernel Drivers & Module Integrity)
*File*: `driver-monitor_dataset_*.csv` | *Scope*: OS Kernel

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `driver_count` | `int` [drivers] | Host | Gauge | Instantaneous | Count of loaded kernel modules from `EnumDeviceDrivers()` | `0` | Current state | `LIVE_AGENT` | Mean, Last |
| `drivers_sample` | `string` | Host | Inventory | Instantaneous | Semicolon-delimited driver base filenames (`ntoskrnl.exe;hal.dll;...`) | `""` | Current state | `LIVE_AGENT` | Set union |
| `running_drivers` | `int` [drivers] | Host | Gauge | Instantaneous | Active system service drivers in running state | `0` | Current state | `LIVE_AGENT` | Mean, Last |

---

### 4.7 `email-monitor` (Messaging & Outbound Attachment Monitor)
*File*: `email-monitor_dataset_*.csv` | *Scope*: Client Messaging Applications

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `email_clients_installed` | `int` [apps] | Host | Inventory | Static | Count of detected mail clients (Outlook, Thunderbird) | `0` | Static inventory | `LIVE_AGENT` | Max |
| `external_recipient_ratio` | `float` [ratio] | Host | Ratio | ~5s | External recipients divided by total message recipients ($0.0 - 1.0$) | `0.0` | `0.0` if no mail | `LIVE_AGENT` | Mean, Max |
| `monitor_active` | `bool` | Host | Health | Instantaneous | MAPI / mail client integration status | `False` | Real-time | `LIVE_AGENT` | Filter |
| `outbound_attachment_count` | `int` [files] | Host | Delta | ~5s | Count of file attachments in sent outbound email messages | `0` | Zero if no email | `LIVE_AGENT` | Sum over disjoint intervals |

---

### 4.8 `file-integrity-monitor` (Filesystem Activity & Sampled Deletions)
*File*: `file-integrity-monitor_dataset_*.csv` | *Scope*: Host Storage Volumes

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `daily_file_access_entropy` | `float` [entropy] | Host | Entropy | 24 Hours | Shannon entropy over accessed file paths and extensions | `0.0` | Resets daily | `SERVER_DERIVED` | Last, Mean |
| `daily_new_filename_count` | `float` [count] | Host | Cumulative | 24 Hours | Count of distinct new filenames created in last 24h | `0.0` | Resets daily | `SERVER_DERIVED` | Last |
| `daily_unique_filename_count` | `float` [count] | Host | Cumulative | 24 Hours | Count of distinct filenames touched in last 24h | `0.0` | Resets daily | `SERVER_DERIVED` | Last |
| `event_count` | `int` [events] | Host | Delta | ~5s | Total filesystem change notifications in cycle | `0` | Real-time | `LIVE_AGENT` | Sum over disjoint intervals |
| `file_access_count` | `int` [events] | Host | Delta | ~5s | File read/open operations | `0` | Real-time | `LIVE_AGENT` | Sum |
| `file_create_count` | `int` [events] | Host | Delta | ~5s | File creation operations | `0` | Real-time | `LIVE_AGENT` | Sum |
| `file_delete_count` | `int` [events] | Host | Sampled Gauge | ~5s | **Sampled DELETE operations in FIFO buffer**. *Audit note*: Represents sampled delete slots, not all filesystem deletions. | `0` | Capped by buffer size | `LIVE_AGENT` | Max, Distribution |
| `file_modify_count` | `int` [events] | Host | Delta | ~5s | File content modification/write operations | `0` | Real-time | `LIVE_AGENT` | Sum |
| `file_rename_count` | `int` [events] | Host | Delta | ~5s | File move or rename operations | `0` | Real-time | `LIVE_AGENT` | Sum |
| `mass_deletion_suspected` | `bool` | Host | Alert | ~5s | `file_delete_count >= 10` within sampling window | `False` | Real-time | `SERVER_DERIVED` / `SYNTHETIC_ONLY` | Any, Max |
| `monitor_active` | `bool` | Host | Health | Instantaneous | USN / directory watcher listener active flag | `True` | N/A | `LIVE_AGENT` | Filter |
| `rapid_file_operations` | `bool` | Host | Alert | ~5s | File operations rate exceeded burst threshold | `False` | Real-time | `LIVE_AGENT` | Any |
| `ransomware_entropy_suspected` | `bool` | Host | Alert | ~5s | File modification wrote high-entropy (encrypted) content | `False` | Real-time | `LIVE_AGENT` | Any |
| `staging_directory_access` | `bool` | Host | Alert | ~5s | Files created or modified in `Temp`, `AppData`, or staging paths | `False` | Real-time | `LIVE_AGENT` | Any |
| `integrity_events_{0..9}_op` | `string` | Event | Slot Category | Sampled | Operation for slot $X$: `"CREATE"`, `"MODIFY"`, `"DELETE"`, `"RENAME"` | `""` | 10 FIFO slots | `LIVE_AGENT` | Slot analysis |
| `integrity_events_{0..9}_path` | `string` | Event | Slot Path | Sampled | Normalized target filesystem path for slot $X$ | `""` | 10 FIFO slots | `LIVE_AGENT` | Slot analysis |
| `integrity_events_{0..9}_sha256` | `string` | Event | Slot Hash | Sampled | SHA256 file hash for created/modified file, or empty for delete | `""` | 10 FIFO slots | `LIVE_AGENT` | Threat Intel lookup |
| `integrity_events_{0..9}_target_type`| `string` | Event | Slot Type | Sampled | Target type for slot $X$: `"FILE"` or `"DIRECTORY"` | `""` | 10 FIFO slots | `LIVE_AGENT` | Slot analysis |

---

### 4.9 `http` (Web Traffic, Cloud Uploads & Browser Activity)
*File*: `http_dataset_*.csv` | *Scope*: Host Web Activity (Browser History SQLite + Network Socket Hooks)  
*Collector Implementation*: [`InsiEDR-agent/src/collectors/browser_history.rs`](file:///D:/Projects/AISH/InsiEDR-agent/src/collectors/browser_history.rs)

> [!IMPORTANT]
> **Candidate Harmonized Feature Scope vs. Raw Live Collector Semantics**:
> * **Browser History Lookback**: In [`browser_history.rs:66`](file:///D:/Projects/AISH/InsiEDR-agent/src/collectors/browser_history.rs#L66), Chrome/Edge SQLite databases are queried over a **rolling 24-hour lookback window** (`cutoff_us = now_us - 86400 * 1e6`). Both `daily_external_domain_ratio` and `external_url_ratio` are **direct aliases** emitted natively from the exact same calculation (`browser_history.rs:210, 216`).
> * **`http_count` Heuristic Scope**: In the raw agent collector, `http_count` is strictly the 24-hour browser SQLite visit count (`stats.http_count`). In [`Dataset_Simulated_Harmonized`](file:///D:/Projects/AISH/Dataset_Simulated_Harmonized/), `http_count` is an offline **derived research heuristic floor** ($\max(\text{browser history}, \text{file sharing}, \text{suspicious}, \text{cloud uploads}, \text{POSTs}, \text{large uploads})$). **It is NOT a physical mathematical invariant**, because it combines a 24-hour rolling browser history count with simulated scenario metrics across disparate telemetry sources.
> * **Synthetic Signal Inheritance Warning (Critical for Unsupervised & Supervised Modeling)**: Because this heuristic floor incorporates `post_requests` and `large_uploads` (which are marked `SYNTHETIC_ONLY` scenario injections), candidate `http_count` **inherits the `SYNTHETIC_ONLY` exclusion constraint**. If fed into unsupervised anomaly detectors (Tier 1 Isolation Forests), it leaks attack signatures into normal baseline profiles. If fed into supervised classifiers (Tier 2 XGBoost), it introduces synthetic scenario spikes absent from live agents; any such run must be evaluated as a **deliberately contaminated upper-bound ablation**, not realistic production detection performance. **Do NOT sum `http_count` across rows in either dataset.**

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `browser_db_found` | `bool` | Host | Inventory | Instantaneous | Chrome/Edge history SQLite database detected on disk | `False` | Real-time | `LIVE_AGENT` | Max, Any |
| `cloud_storage_uploads` | `int` [uploads] | Host | Delta | ~5s | HTTP requests directed to Dropbox, Google Drive, OneDrive, Mega. Stubbed to `0` in live agent (`browser_history.rs:214`); positive values exist only in simulation. | `0` | Real-time | `LIVE_AGENT (Stubbed 0)` / `SYNTHETIC_ONLY` | Sum over disjoint intervals, Max |
| `daily_domain_access_entropy` | `float` [entropy] | Host | Entropy | 24 Hours | Shannon entropy over visited domain names in 24h browser history (`browser_history.rs:112-120`) | `0.0` | 24h rolling | `LIVE_AGENT` | Last, Mean |
| `daily_external_domain_ratio` | `float` [ratio] | Host | Ratio | 24 Hours | External domain requests divided by total HTTP requests ($0.0 - 1.0$). **Direct alias of `external_url_ratio`** (`browser_history.rs:210, 216`). | `0.0` | 24h rolling | `LIVE_AGENT` | Last, Mean |
| `daily_http_request_count` | `float` [count] | Host | Rolling Count | 24 Hours | Total HTTP visits in past 24h from browser SQLite query. **Alias of raw `http_count`** (`browser_history.rs:200, 201`). | `0.0` | 24h rolling | `LIVE_AGENT` | Last, Max (Do NOT sum) |
| `daily_unique_domain_count` | `float` [count] | Host | Rolling Count | 24 Hours | Distinct FQDNs visited in past 24h (`browser_history.rs:109`) | `0.0` | 24h rolling | `LIVE_AGENT` | Last, Max |
| `external_url_ratio` | `float` [ratio] | Host | Ratio | 24 Hours | External domain visits / total visits ($0.0 - 1.0$). **Emitted directly from same 24h query as `daily_external_domain_ratio`** (`browser_history.rs:140`). | `0.0` | 24h rolling | `LIVE_AGENT` | Last, Mean |
| `file_sharing_site_visits` | `float` [visits] | Host | Rolling Count | 24 Hours | Visits to file-sharing domains in 24h history (`browser_history.rs:126`). In simulation, elevated during exfiltration. | `0.0` | 24h rolling | `LIVE_AGENT` | Max, Last |
| `http_count` | `float` [count] | Host | **Candidate: Research Heuristic Floor**<br/>(Raw: Rolling Count) | 24 Hours / ~5s Mixed | **Raw Baseline**: 24h browser SQLite history count (`LIVE_AGENT`).<br/>**Candidate Harmonized**: **`HARMONIZATION_DERIVED` Research Heuristic Floor** ($\max(\text{browser history}, \dots, \text{post\_requests}, \text{large\_uploads})$). Mixes 24h rolling browser counts and simulated scenario metrics.<br/>**Synthetic Leakage Warning**: Inherits `SYNTHETIC_ONLY` constraint. Must be excluded from unsupervised baseline training (Tier 1); if included in supervised training (Tier 2), it is a contaminated upper-bound ablation rather than realistic detection. | `0.0` | 24h rolling / Heuristic floor | `HARMONIZATION_DERIVED` (Candidate)<br/>`LIVE_AGENT` (Raw) | **Max, Last, Percentiles (Do NOT sum across rows!)** |
| `job_search_site_visits` | `float` [visits] | Host | Rolling Count | 24 Hours | Hits on job recruitment/career portals in 24h history (`browser_history.rs:129`) | `0.0` | 24h rolling | `LIVE_AGENT` | Max, Last |
| `large_uploads` | `float` [uploads] | Host | Delta | ~5s | Outbound HTTP POST/PUT payloads exceeding 5 MB. **Not collected by live agent; populated only during synthetic scenario injection.** | `0.0` | Real-time | `SYNTHETIC_ONLY` | Sum over disjoint intervals, Max |
| `post_requests` | `float` [requests] | Host | Delta | ~5s | HTTP requests using POST method. **Not collected by live agent; populated only during synthetic scenario injection.** | `0.0` | Real-time | `SYNTHETIC_ONLY` | Sum over disjoint intervals, Max |
| `status_4xx_count` | `int` [errors] | Host | Delta | ~5s | HTTP client error response codes. **Not collected by live agent; populated only in simulation.** | `0` | Real-time | `SYNTHETIC_ONLY` | Sum over disjoint intervals |
| `status_5xx_count` | `int` [errors] | Host | Delta | ~5s | HTTP server error response codes. **Not collected by live agent; populated only in simulation.** | `0` | Real-time | `SYNTHETIC_ONLY` | Sum over disjoint intervals |
| `suspicious_url_count` | `float` [urls] | Host | Rolling Count | 24 Hours | URLs matching suspicious TLDs/watchlists in 24h history (`browser_history.rs:132`). In simulation, elevated during exfiltration. | `0.0` | 24h rolling | `LIVE_AGENT` | Max, Last |
| `unique_url_count` | `float` [urls] | Host | Rolling Count | 24 Hours | Distinct URLs visited in 24h history (`browser_history.rs:110`) | `0.0` | 24h rolling | `LIVE_AGENT` | Last, Max |
| `unusual_user_agents` | `int` [requests] | Host | Delta | ~5s | Requests with script/automated User-Agents. **Not collected by live agent; populated only in simulation.** | `0` | Real-time | `SYNTHETIC_ONLY` | Sum over disjoint intervals |
| `url_access_count` | `int` [requests] | Host | Rolling Count | 24 Hours | Alias of `http_count` in Rust agent (`browser_history.rs:212`) | `0` | 24h rolling | `LIVE_AGENT` | Last, Max |
| `watchlisted_domain_hits` | `int` [hits] | Host | Rolling Count | 24 Hours | Alias of `suspicious_url_count` in Rust agent (`browser_history.rs:215`) | `0` | 24h rolling | `LIVE_AGENT` | Max, Last |

---

### 4.10 `keystroke-collector` (Keystroke Dynamics & Typing Velocity)
*File*: `keystroke-collector_dataset_*.csv` | *Scope*: Interactive User Session (Privacy-Preserving Timings Only; No Text Content)

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `backspace_rate` | `float` [keys/min] | User | Rate | ~5s | Backspaces pressed per minute | `0.0` | Real-time | `LIVE_AGENT` | Mean, Max |
| `backspace_ratio` | `float` [ratio] | User | Ratio | ~5s | `backspace_count / max(1, total_keys_sampled)` ($0.0 - 1.0$) | `0.0` | Real-time | `LIVE_AGENT` | Mean |
| `digraph_latency` | `float` [ms] | User | Gauge | ~5s | Inter-keystroke time between consecutive characters | `0.0` | Real-time | `LIVE_AGENT` | Mean |
| `dwell_sample_count` | `int` [samples] | User | Gauge | ~5s | Count of key press/release duration samples collected | `0` | Real-time | `LIVE_AGENT` | Sum, Last |
| `error_rate` | `float` [ratio] | User | Ratio | ~5s | Typing correction frequency | `0.0` | Real-time | `LIVE_AGENT` | Mean |
| `mean_dwell_time_ms` | `float` [ms] | User | Metric | ~5s | Mean duration between KeyDown and KeyUp events | `0.0` | Real-time | `LIVE_AGENT` | Mean |
| `mean_flight_time_ms` | `float` [ms] | User | Metric | ~5s | Mean duration between KeyUp(N) and KeyDown(N+1) events | `0.0` | Real-time | `LIVE_AGENT` | Mean |
| `std_dwell_time_ms` | `float` [ms] | User | Metric | ~5s | Standard deviation of key dwell times | `0.0` | Real-time | `LIVE_AGENT` | Mean |
| `std_flight_time_ms` | `float` [ms] | User | Metric | ~5s | Standard deviation of flight times | `0.0` | Real-time | `LIVE_AGENT` | Mean |
| `total_keys_sampled` | `int` [keys] | User | Delta | ~5s | Total key events recorded (timings only) | `0` | Real-time | `LIVE_AGENT` | Sum over disjoint intervals |
| `typing_speed_cpm` | `float` [cpm] | User | Rate | ~5s | Characters typed per minute | `0.0` | Real-time | `LIVE_AGENT` | Mean, Max |
| `typing_speed_wpm` | `float` [wpm] | User | Rate | ~5s | `typing_speed_cpm / 5.0` | `0.0` | Real-time | `LIVE_AGENT` | Mean, Max |
| `keystroke_timings_{0..9}` | `float` [ms] | User | Slot Metric | Sampled | Durations of the 10 most recent key transitions in FIFO buffer | `0.0` | 10 slots | `LIVE_AGENT` | Distribution stats |

---

### 4.11 `logon` (Authentication & Session Lifecycle)
*File*: `logon_dataset_*.csv` | *Scope*: Host Authentication Subsystem (EID 4624, 4625, 4634, 4647)

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `after_hours_logon` | `float` [events] | Host | Delta | ~5s | Logons outside 08:00–18:00 or weekends. **Bounded by `logon_count`** | `0.0` | Real-time | `LIVE_AGENT` | Sum over disjoint intervals |
| `concurrent_sessions` | `int` [sessions] | Host | Gauge | Instantaneous | Active logon sessions on host from `LsaEnumerateLogonSessions()` | `0` | Real-time gauge | `LIVE_AGENT` | Max, Last |
| `daily_after_hours_logon_ratio`| `float` [ratio]| Host | Ratio | 24 Hours | `daily_after_hours / max(1, daily_logons)` ($0.0 - 1.0$) | `0.0` | Resets daily | `SERVER_DERIVED` | Last, Mean |
| `daily_pc_access_entropy` | `float` [entropy] | Host | Entropy | 24 Hours | Shannon entropy over destination workstations accessed today | `0.0` | Resets daily | `SERVER_DERIVED` | Last |
| `daily_unique_pc_count` | `float` [pcs] | Host | Cumulative | 24 Hours | Distinct destination workstations logged into today | `0.0` | Resets daily | `SERVER_DERIVED` | Last, Max |
| `etw_lifecycle_events_started_count`| `int` [events]| Host | Delta | ~5s | Winlogon/Security audit service startup events | `0` | Real-time | `LIVE_AGENT` | Sum |
| `etw_lifecycle_events_stopped_count`| `int` [events]| Host | Delta | ~5s | Winlogon/Security audit service stop/tamper events | `0` | Real-time | `LIVE_AGENT` | Sum, Max |
| `event_count` | `int` [events] | Host | Delta | ~5s | Total authentication and session lifecycle records in cycle | `0` | Real-time | `LIVE_AGENT` | Sum |
| `failed_logons` | `int` [events] | Host | Delta | ~5s | Failed logon attempts (Event ID 4625) | `0` | Real-time | `LIVE_AGENT` | Sum over disjoint intervals |
| `first_logon_time` | `string` | User | Timestamp | 24 Hours | Timestamp of first successful logon today | `""` | Resets daily | `SERVER_DERIVED` | First |
| `interactive_duration_seconds`| `float` [s] | User | Cumulative | Session | Total elapsed active desktop session time | `0.0` | Active session | `LIVE_AGENT` | Max, Last |
| `last_logoff_time` | `string` | User | Timestamp | Instantaneous | Timestamp of most recent logoff event | `""` | Event-driven | `LIVE_AGENT` | Last |
| `logoff_count` | `int` [events] | Host | Delta | ~5s | User logoff events (Event ID 4634 / 4647) | `0` | Real-time | `LIVE_AGENT` | Sum |
| `logon_count` | `int` [events] | Host | Delta | ~5s | Total authentication attempts: `successful_logons + failed_logons` | `0` | Real-time | `LIVE_AGENT` | Sum over disjoint intervals |
| `logon_entropy` | `float` [entropy] | Host | Entropy | ~5s | Entropy of logon types observed in sampling window | `0.0` | Real-time | `SERVER_DERIVED` | Mean |
| `logon_type` | `float` [enum] | Session | Category | Instantaneous | Win32 Logon Type (2=Interactive, 3=Network, 10=RemoteInteractive) | `0.0` | Event-driven | `LIVE_AGENT` | Mode |
| `session_duration_avg` | `float` [s] | Host | Metric | ~5s | Mean duration of completed sessions | `0.0` | Real-time | `LIVE_AGENT` | Mean |
| `successful_logons` | `int` [events] | Host | Delta | ~5s | Successful authentication events (EID 4624). **Bounded by `logon_count`** | `0` | Real-time | `LIVE_AGENT` | Sum over disjoint intervals |
| `unique_pc_count` | `float` [pcs] | Host | Delta | ~5s | Number of distinct PCs involved in authentication events | `0.0` | Real-time | `LIVE_AGENT` | Max |
| `weekend_logon` | `float` [flag] | Host | Flag | ~5s | `1.0` if logon occurred on Saturday or Sunday; else `0.0` | `0.0` | Calendar | `LIVE_AGENT` | Any, Max |

---

### 4.12 `lsass-monitor` (Credential Access & LSASS Protection)
*File*: `lsass-monitor_dataset_*.csv` | *Scope*: LSASS Process Security (`lsass.exe`)

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `credential_dumping_suspected`| `bool` | Process | Alert | ~5s | Unauthorized process requested dumping access mask on LSASS | `False` | Real-time | `LIVE_AGENT` / `SYNTHETIC_ONLY` | Any, Max |
| `event_count` | `int` [events] | Process | Delta | ~5s | Handle opens, duplicate handles, or memory reads targeting LSASS | `0` | Real-time | `LIVE_AGENT` | Sum over disjoint intervals |
| `handle_requests` | `float` [events]| Process | Delta | ~5s | `OpenProcess` calls requesting access to LSASS PID | `0.0` | Real-time | `LIVE_AGENT` / `SYNTHETIC_ONLY` | Sum, Max |
| `memory_dump_attempts` | `float` [events]| Process | Delta | ~5s | Calls to `MiniDumpWriteDump` targeting LSASS | `0.0` | Real-time | `LIVE_AGENT` / `SYNTHETIC_ONLY` | Sum, Max |
| `mimikatz_signatures` | `float` [matches]| Process | Alert | ~5s | Known Mimikatz module hashes, strings, or command lines | `0.0` | Real-time | `LIVE_AGENT` / `SYNTHETIC_ONLY` | Any, Max |
| `suspicious_access_mask` | `string` [hex] | Process | Mask | Instantaneous | Requested access mask: `0x1010` (VM_READ/QUERY), `0x1FFFFF` (ALL_ACCESS) | `""` | Real-time | `LIVE_AGENT` | Identity, Filter |
| `target_process` | `string` | Process | Identifier | Static | Target process binary: `"lsass.exe"` | `"lsass.exe"` | Static | `LIVE_AGENT` | Identity |

---

### 4.13 `memory-scanner` (In-Memory Injection & Hollowed Modules)
*File*: `memory-scanner_dataset_*.csv` | *Scope*: User-Mode Process Virtual Address Spaces

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `phantom_hollowed_mappings` | `int` [threats]| Process | Gauge | Periodic | Discrepancies between memory PE header and disk image (Process Hollowing) | `0` | Sweep cycle | `LIVE_AGENT` | Max |
| `reflective_pe_injections` | `int` [threats]| Process | Gauge | Periodic | Unmapped executable PE headers injected in heap/stack regions | `0` | Sweep cycle | `LIVE_AGENT` | Max |
| `sample_threats` | `string` | Process | Inventory | Instantaneous | Semicolon-delimited threat strings and target PIDs | `""` | Sweep cycle | `LIVE_AGENT` | Set union |
| `target_processes_scanned` | `int` [procs] | Host | Metric | Periodic | Total candidate processes evaluated during memory scan sweep | `0` | Sweep cycle | `LIVE_AGENT` | Last |
| `threats_detected` | `bool` | Host | Alert | Periodic | `unbacked_executable_regions > 0` or injections found | `False` | Sweep cycle | `LIVE_AGENT` | Any, Max |
| `unbacked_executable_regions`| `int` [regions]| Process | Gauge | Periodic | Committed executable pages (`PAGE_EXECUTE_READWRITE`) not backed by file | `0` | Sweep cycle | `LIVE_AGENT` | Max |

---

### 4.14 `named-pipe-monitor` (Inter-Process Communication & RPC Pipes)
*File*: `named-pipe-monitor_dataset_*.csv` | *Scope*: Host IPC Subsystem

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `named_pipes_sample` | `string` | Host | Inventory | Instantaneous | Semicolon-delimited pipe names (e.g. `\pipe\psexec;\pipe\lsarpc`). **Represents local pipe entity, not remote machine identity.** | `""` | Current open pipes | `LIVE_AGENT` | Set union |
| `pipe_count` | `int` [pipes] | Host | Gauge | Instantaneous | Total active named pipes opened on the local endpoint | `0` | Real-time gauge | `LIVE_AGENT` | Mean, Last |

---

### 4.15 `network` (Socket Table & Connection Samples)
*File*: `network_dataset_*.csv` | *Scope*: Host Network Sockets

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `active_connections_count` | `int` [sockets] | Host | Gauge | Instantaneous | Total TCP/UDP connections returned by `GetExtendedTcpTable()` | `0` | Real-time gauge | `LIVE_AGENT` | Mean, Last |
| `bytes_received` | `float` [bytes] | Host | Counter | Cumulative | Total network bytes received across all adapters | `0.0` | Resets on reboot | `LIVE_AGENT` | Disjoint delta sum |
| `bytes_sent` | `float` [bytes] | Host | Counter | Cumulative | Total network bytes transmitted across all adapters | `0.0` | Resets on reboot | `LIVE_AGENT` | Disjoint delta sum |
| `connection_count` | `int` [sockets] | Host | Gauge | Instantaneous | Instantaneous active socket count | `0` | Real-time gauge | `LIVE_AGENT` | Mean, Last |
| `dns_queries` | `int` [queries] | Host | Delta | ~5s | Network socket requests directed to port 53 (DNS) | `0` | Real-time | `LIVE_AGENT` | Sum |
| `failed_connections` | `int` [sockets] | Host | Delta | ~5s | TCP SYN retransmissions or reset sockets | `0` | Real-time | `LIVE_AGENT` | Sum |
| `high_port_traffic` | `float` [conns] | Host | Delta | ~5s | Connections targeting unprivileged destination ports ($> 1024$) | `0.0` | Real-time | `LIVE_AGENT` / `SYNTHETIC_ONLY` | Sum, Max |
| `inbound_connections` | `int` [sockets] | Host | Gauge | Instantaneous | Inbound listening and established TCP sockets | `0` | Real-time gauge | `LIVE_AGENT` | Mean, Last |
| `outbound_connections` | `float` [sockets]| Host | Gauge | Instantaneous | Outbound established TCP sockets | `0.0` | Real-time gauge | `LIVE_AGENT` | Mean, Last |
| `unique_remote_ips` | `float` [ips] | Host | Delta | ~5s | Count of distinct remote destination IP addresses in window | `0.0` | Real-time | `LIVE_AGENT` | Max |
| `connections_sample_{0..99}_local_addr` | `string` | Socket | Slot Address | Sampled | Local binding (`IP:Port`) for connection slot $X \in [0, 99]$ | `""` | 100 FIFO slots | `LIVE_AGENT` | Connection analysis |
| `connections_sample_{0..99}_pid` | `int` | Socket | Slot PID | Sampled | Owning Process ID for connection slot $X$ | `0` | 100 FIFO slots | `LIVE_AGENT` | Connection analysis |
| `connections_sample_{0..99}_remote_addr` | `string` | Socket | Slot Address | Sampled | Destination endpoint (`IP:Port`) for connection slot $X$ | `""` | 100 FIFO slots | `LIVE_AGENT` | Asset enrichment |
| `connections_sample_{0..99}_state` | `string` | Socket | Slot State | Sampled | TCP state: `"ESTABLISHED"`, `"LISTENING"`, `"TIME_WAIT"`, `"CLOSE_WAIT"` | `""` | 100 FIFO slots | `LIVE_AGENT` | Connection analysis |

---

### 4.16 `persistence-monitor` (Registry Run Keys & Startup Persistence)
*File*: `persistence-monitor_dataset_*.csv` | *Scope*: Host Persistence Mechanisms

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `entry_count` | `int` [entries] | Host | Gauge | Instantaneous | Count of active persistence registry values, scheduled tasks, and startup entries | `0` | Current state | `LIVE_AGENT` | Mean, Last |
| `modifications_detected` | `bool` | Host | Alert | ~5s | `True` when registry value or startup file was created, modified, or deleted | `False` | Real-time | `LIVE_AGENT` / `SYNTHETIC_ONLY` | Any, Max |
| `total_monitored_keys` | `int` [keys] | Host | Config | Static | Total registry keys and filesystem folders monitored for persistence | `12` | Static config | `LIVE_AGENT` | Identity |
| `persistence_entries_{0..9}_command` | `string` | Entry | Slot Command | Sampled | Executable command-line string registered for persistence slot $X \in [0, 9]$ | `""` | 10 slots | `LIVE_AGENT` | Signature analysis |
| `persistence_entries_{0..9}_name` | `string` | Entry | Slot Name | Sampled | Value name or scheduled task name for slot $X$ | `""` | 10 slots | `LIVE_AGENT` | Identity |
| `persistence_entries_{0..9}_path` | `string` | Entry | Slot Path | Sampled | Registry path or startup directory for slot $X$ | `""` | 10 slots | `LIVE_AGENT` | Identity |

---

### 4.17 `process-watcher` (Process Lifecycle & Execution Telemetry)
*File*: `process-watcher_dataset_*.csv` | *Scope*: Host Process Table

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `admin_process_count` | `int` [procs] | Host | Gauge | Instantaneous | Count of running processes executing with administrative / elevated tokens | `0` | Real-time gauge | `LIVE_AGENT` | Mean, Max |
| `daily_unique_process_count` | `float` [procs]| Host | Cumulative | 24 Hours | Count of distinct process image binaries executed today | `0.0` | Resets daily | `SERVER_DERIVED` | Last, Max |
| `etw_realtime_active` | `bool` | Host | Health | Instantaneous | Process lifecycle ETW provider active status | `True` | N/A | `LIVE_AGENT` | Filter |
| `executables_from_temp_folder`| `int` [procs] | Host | Gauge | Instantaneous | Processes executing from `C:\Windows\Temp\` or `AppData\Local\Temp\` | `0` | Real-time gauge | `LIVE_AGENT` | Max, Any |
| `process_count` | `int` [procs] | Host | Gauge | Instantaneous | Total running processes returned by `CreateToolhelp32Snapshot()` | `0` | Real-time gauge | `LIVE_AGENT` | Mean, Last |
| `tunneling_process_count` | `int` [procs] | Host | Gauge | Instantaneous | Running processes matching tunneling tools (`plink.exe`, `ngrok.exe`, `chisel.exe`) | `0` | Real-time gauge | `LIVE_AGENT` | Max, Any |

---

### 4.18 `short-term_edr_feature` (Rolling Feature Aggregations & Baselines)
*File*: `short-term_edr_feature_dataset_*.csv` | *Scope*: Entity Rolling Authentication & Anomaly Features

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `auth_fail_rate_300s` | `float` [ev/min] | Entity | Rolling Rate | 300 Seconds | `edr_failed_auth_events_per_minute_window` | `0.0` | Rolling 300s window | `SERVER_DERIVED` | Mean, Max |
| `auth_rate_300s` | `float` [ev/min] | Entity | Rolling Rate | 300 Seconds | `edr_auth_event_count_window / 5.0`. **Strict invariant**: Must match event count / 5. | `0.0` | Rolling 300s window | `SERVER_DERIVED` | Mean, Max |
| `auth_rate_3600s` | `float` [ev/min] | Entity | Rolling Rate | 3600 Seconds | Rolling 1-hour authentication events divided by 60 minutes | `0.0` | Rolling 1-hour window | `SERVER_DERIVED` | Mean, Max |
| `edr_auth_event_count_window` | `int` [events] | Entity | Rolling Count | 300 Seconds | Total authentication events (successful + failed) in rolling 300s window | `0` | Rolling 300s window | `SERVER_DERIVED` | Max, Distribution |
| `edr_auth_events_per_minute_window`| `float` [ev/min]| Entity | Rolling Rate | 300 Seconds | Identical to `auth_rate_300s` (`event_count / 5.0`) | `0.0` | Rolling 300s window | `SERVER_DERIVED` | Mean, Max |
| `edr_failed_auth_events_per_minute_window`| `float` [ev/min]| Entity | Rolling Rate | 300 Seconds | Failed authentications in rolling 300s window divided by 5.0 | `0.0` | Rolling 300s window | `SERVER_DERIVED` | Mean, Max |
| `edr_failed_auth_ratio_window` | `float` [ratio]| Entity | Rolling Ratio | 300 Seconds | `failed_auths / max(1, total_auths)` ($0.0 - 1.0$) | `0.0` | Rolling 300s window | `SERVER_DERIVED` | Mean, Max |
| `edr_unique_logon_type_count_window`| `int` [types]| Entity | Rolling Count | 300 Seconds | Count of distinct Win32 logon types observed in 300s window | `0` | Rolling 300s window | `SERVER_DERIVED` | Max |
| `logon_velocity_zscore` | `float` [std dev] | Entity | Baseline Score | 300 Seconds | Standard deviations from baseline velocity. **Authoritative scoring uses `BaselineEngine.get_deviation_vector()`.** | `0.0` | Continuous baseline | `SERVER_DERIVED` | Mean, Max |
| `off_hours_auth_count` | `int` [events] | Entity | Rolling Count | 300 Seconds | Authentication events occurring outside 08:00–18:00 in 300s window | `0` | Rolling 300s window | `SERVER_DERIVED` | Max |
| `unique_workstations_300s` | `int` [pcs] | Entity | Rolling Count | 300 Seconds | Distinct workstations observed in authentication telemetry for this entity. **Represents breadth scalar; not target host array.** | `0` | Rolling 300s window | `SERVER_DERIVED` | Max |

---

### 4.19 `usn-monitor` (NTFS Change Journal Activity)
*File*: `usn-monitor_dataset_*.csv` | *Scope*: Host NTFS Volumes

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `note` | `string` | Host | Status | Instantaneous | Collector operational state message | `""` | N/A | `LIVE_AGENT` | Identity |
| `usn_records_captured` | `int` [records] | Host | Delta | ~5s | Count of NTFS USN change journal records read from volume | `0` | Real-time delta | `LIVE_AGENT` | Sum over disjoint intervals, Max |

---

### 4.20 `wmi-activity` (WMI Execution & Lateral Movement)
*File*: `wmi-activity_dataset_*.csv` | *Scope*: Windows Management Instrumentation Subsystem

| Field Name | Type & Unit | Scope | Kind | Lookback | Formula / Dependencies | Default & Missing | Reset & Cap | Status | Supported Aggregation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `channel` | `string` | Host | Config | Static | ETW provider: `"Microsoft-Windows-WMI-Activity"` | `"etw"` | Static | `LIVE_AGENT` | Identity |
| `lateral_movement_suspected` | `bool` | Host | Alert | ~5s | Remote WMI connection or remote process creation (`Win32_Process.Create`) | `False` | Real-time | `LIVE_AGENT` / `SYNTHETIC_ONLY` | Any, Max |
| `total_queries_captured` | `int` [queries] | Host | Delta | ~5s | Count of WMI WQL queries captured in sampling cycle | `0` | Real-time delta | `LIVE_AGENT` | Sum over disjoint intervals, Max |

---

## 5. Critical Aggregation & Modeling Rules for Data Scientists

### 5.1 Do Not Sum Rolling Windows
Features with lookbacks of 300 seconds (`auth_rate_300s`, `edr_auth_event_count_window`, `unique_workstations_300s`) or 24 hours (`daily_*`) are **overlapping rolling snapshots**. Summing them across rows within the same lookback interval results in massive artificial overcounting.
* **Valid Aggregations**: Use `max()`, `last()`, or distribution percentiles ($p_{50}, p_{95}$) over temporal evaluation intervals.
* **Disjoint Delta Summing**: Only fields classified as **Delta** (`usb_connect_count`, `file_create_count`, `usn_records_captured`) may be summed across non-overlapping snapshot intervals.

### 5.2 Array Buffer Slot Interpretation
Columns formatted as `connections_sample_{0..99}_*`, `integrity_events_{0..9}_*`, and `persistence_entries_{0..9}_*` represent **sampled buffer slots**:
* `file_delete_count = 13` indicates that 13 sampled DELETE operations were observed across the snapshot cycle, matching the active FIFO slots. It does not represent a complete audit log of every file on the disk.
* Sockets in `connections_sample` capture instantaneous active connections returned by the TCP table sweep.

### 5.3 Entity Resolution & Graph Construction Semantics
* `named_pipes_sample` (e.g. `\pipe\psexec`) represents an IPC **pipe entity** on the local host (`Workstation --OPENED_PIPE--> Named_Pipe`), not a confirmed remote workstation identity.
* `connections_sample_remote_addr` records destination IP addresses (`Workstation --NETWORK_OUTBOUND--> Remote_IP`). Resolving an IP to an internal workstation hostname requires enterprise asset inventory / DHCP enrichment.
