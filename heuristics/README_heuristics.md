# Deterministic Heuristics

The heuristics engine evaluates one flattened feature vector for the active root user and returns explainable detections. It is not an ML inference module. ML outputs are optional inputs to the risk aggregator and are maintained by the ML team.

## Scenario contract

| ID | Detection | Rule behavior |
| --- | --- | --- |
| `S1` | IT sabotage | Mass file deletion is only a precursor. Confirm `S1` when deletion co-occurs with after-hours access, an auth burst, or a verified system-change signal. |
| `S2` | Data hoarding | Broad/high-volume or sensitive-file access. Baseline deviation can support the signal; the rule does not infer that a file was copied. |
| `S3` | Removable-media exfiltration | Requires a file-to-removable transfer counter. USB insertion or an unapproved device without transfer evidence is a precursor. |
| `S4` | Cloud exfiltration | Requires upload activity correlated with sensitive-file access or unusual collection. A file-sharing visit is a precursor only. |
| `HONEYTOKEN` | Decoy interaction | `threat_triggered=true` forces heuristic risk to 100 and produces a critical scenario. |

Supporting tags such as `AUTH_BURST`, `AUTH_LATERAL`, `FILE_DELETE`, `S1_PRECURSOR`, `S3_PRECURSOR`, and `S4_PRECURSOR` are not confirmed CERT scenarios.

The detector accepts a flat feature dictionary. Common inputs include `successful_logons`, `failed_logons`, `after_hours_logon`, `daily_after_hours_logon_ratio`, `daily_unique_pc_count`, `file_access_count`, `daily_unique_filename_count`, `daily_new_filename_count`, `daily_file_delete_count`, `sensitive_file_access`, `file_sharing_site_visits`, `cloud_storage_uploads`, `large_uploads`, `usb_connect_count`, `unauthorized_usb_detected`, `usb_file_transfer_count`, and `threat_triggered`. Additional fields are ignored unless a rule consumes them.

## Input and identity behavior

- The root telemetry payload's `username` is the identity for user-scoped analysis. Host-wide collectors may omit usernames; their fields are still attached to the root user's risk event.
- User-keyed collector maps are unwrapped only when their key matches the root username (case-insensitive). If no user matches, those counters are omitted rather than attributed to another account.
- Missing or invalid values do not create synthetic zero-valued evidence. Aliases are applied only after collector payloads have been flattened.
- The server baseline uses only selected numeric features and samples an entity at most once per hour. It is scored before update and updated only when final risk is below 40.

## Authentication burst and z-score fields

The auth detector consumes these short-term fields when available:

```text
edr_auth_event_count_window
edr_failed_auth_ratio_window
edr_auth_events_per_minute_window
edr_failed_auth_events_per_minute_window
unique_workstations_300s
off_hours_auth_count
```

It emits a `[0,100]` detector score, confidence, and evidence. Strong failure ratios require multiple estimated failed events; a high rate or several workstations must also meet event-volume thresholds. The z-score detector combines per-user baseline deviations with `logon_velocity_zscore`; z-scores at or below 2 do not add risk, and the calibration endpoint is controlled by `INSIEDR_ZSCORE_CALIBRATION_THRESHOLD` (default 8).

## Threshold tuning

Current count thresholds are conservative starter values, not universal truths. Tune them against labeled incidents and representative benign windows, stratified by role and system profile. Do not tune from repeated snapshot row counts. Where telemetry lacks file sensitivity, copy/transfer counts, or upload bytes, retain precursor behavior instead of claiming confirmed exfiltration.
