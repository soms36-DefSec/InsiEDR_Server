# Honeytoken Pilot: Feature Provenance & Measurement Metadata

This document provides complete, transparent provenance for all features in the Honeytoken Pilot (`SIM_HONEYTOKEN_TRIP`), fulfilling ML Team Audit Item 3.

## 1. Provenance Classification Summary

| Field | Collector | Class | Source / Origin | Units | Invariant Notes |
| :--- | :--- | :---: | :--- | :---: | :--- |
| `run_id` | Meta | **Metadata** | Execution index | String | Traceable to `run_manifest.csv` |
| `timestamp` | Meta | **Measured** | OS System Clock | ISO UTC | Exact `+00:00` UTC offset |
| `threat_triggered`| `decoy-monitor` | **Measured** | File stat mtime/size diff | Boolean | `True` when canary file read/modified |
| `events_recorded` | `decoy-monitor` | **Measured** | Decoy monitor state log | Boolean | `True` when canary event captured |
| `current_size` | `decoy-monitor` | **Measured** | `stat().st_size` on canary | Bytes | 2,239 pristine, 2,245 touched |
| `monitored_decoys`| `decoy-monitor` | **Measured** | Agent decoy config | Path | `C:\Users\Public\Admin_Passwords.xlsx` |
| `file_access_count`| `file-integrity`| **Measured** | File system open/read events | Count | Independent measurement of file reads |
| `event_count` | `file-integrity`| **Measured** | ReadDirectoryChangesW audits | Count | Independent measurement of FS changes |
| `integrity_events_0_sha256`| `file-integrity`| **Measured**| Static Windows SHA-256 | Hex | Authentic system `hosts` hash (`2d6b...`) |
| `daily_file_access_entropy`| `file-integrity`| **Derived** | Shannon entropy formula | Bits | Computed over extension frequencies |

## 2. Invariant Resolutions Verified in this Pilot
1. **0 Baseline Deletions**: Zero `DELETE` operations appear across all benign runs.
2. **Static Hosts Hash**: The System32 `hosts` hash is constant (`2d6bdfb341be3a6234b24742377f93aa7c7cfb0d9fd64efa9282c87852e57085`) across all rows.
3. **Canonical Field Distinction**: `file_access_count` (file reads) and `event_count` (directory audits) are distinct and independently measured.
4. **Held-Out Evaluation Cohort**: Runs `RUN_HT_013` to `RUN_HT_016` originate from held-out host `SANDY-WS02` for unbiased generalization testing.
