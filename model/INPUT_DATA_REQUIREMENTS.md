# V3 input data requirements

**Yes: V3 requires exactly 40 numeric daily behavioral features, with the exact names and column order below. Each row represents one endpoint on one calendar day.** Having any arbitrary 40 columns is not sufficient: their definitions, units and daily aggregation must match the model contract.

## Required feature file: X.csv

Do not include IDs, dates, timestamps, labels or other extra columns in this file. Supply the original daily values; V3 applies its own log1p transformations and feature engineering internally.

| Column position | Exact feature name |
|---:|---|
| 1 | `successful_logons` |
| 2 | `failed_logons` |
| 3 | `after_hours_logon_ratio` |
| 4 | `unique_pc_count` |
| 5 | `pc_access_entropy` |
| 6 | `interactive_duration_seconds` |
| 7 | `mean_session_duration_seconds` |
| 8 | `weekend_activity` |
| 9 | `usb_connect_count` |
| 10 | `usb_disconnect_count` |
| 11 | `after_hours_usb_ratio` |
| 12 | `distinct_usb_devices` |
| 13 | `file_access_count` |
| 14 | `unique_filename_count` |
| 15 | `new_filename_count` |
| 16 | `file_delete_count` |
| 17 | `file_access_entropy` |
| 18 | `protected_file_touch_count` |
| 19 | `http_request_count` |
| 20 | `unique_domain_count` |
| 21 | `new_domain_count` |
| 22 | `external_domain_ratio` |
| 23 | `domain_access_entropy` |
| 24 | `file_sharing_visit_count` |
| 25 | `mean_process_count` |
| 26 | `peak_process_count` |
| 27 | `admin_process_count` |
| 28 | `temp_exec_count` |
| 29 | `bytes_sent` |
| 30 | `bytes_received` |
| 31 | `external_connection_count` |
| 32 | `unique_remote_ip_count` |
| 33 | `clipboard_copy_count` |
| 34 | `lsass_handle_request_count` |
| 35 | `memory_dump_attempt_count` |
| 36 | `decoy_access_count` |
| 37 | `wmi_query_count` |
| 38 | `named_pipe_event_count` |
| 39 | `dns_query_count` |
| 40 | `outbound_attachment_count` |

The canonical machine-readable order is `run/schema.json` -> `raw_features`. The saved model also checks this order at inference.

## Separate metadata file: metadata.csv

Metadata does not count toward the 40 numeric predictors. The feature and metadata files must have the same number of rows in the same row order.

| Metadata | Requirement |
|---|---|
| `hostname` | Required stable endpoint identifier. Keep each computer's history separate. |
| `date` | Required calendar day in `YYYY-MM-DD` format. One row per hostname/date; duplicates are rejected. |
| `observation_complete` | Use numeric `1` only when daily coverage has been verified. Missing completeness metadata prevents review-queue eligibility. |
| `source_kind` | Declare `synthetic`, `observed_unlabeled` or `observed_labeled` as applicable. Missing provenance is legacy compatibility, not approval for real deployment. |

For declared observed data, the current serving implementation additionally requires:

- `feature_contract_version` = `v3_daily40_observed_v1`.
- `feature_contract_verified` = `1`.
- `sensor_coverage_verified` = `1`.
- `timezone_verified` = `1`.
- `observation_complete` = `1`.

These are quality attestations, not model features. Set them only after actually verifying collector definitions, aggregation, timezone and coverage. Setting flags does not make incompatible data valid. Ground-truth labels are not required for prediction; keep them separate for evaluation.

## Values and preprocessing

- All 40 values must be numeric, finite and nonnegative. NaN, infinity and missing feature columns are rejected.
- The three ratios (`after_hours_logon_ratio`, `after_hours_usb_ratio`, `external_domain_ratio`) must be between 0 and 1. `weekend_activity` must be 0 or 1.
- Counts must reflect the intended daily events or distinct entities. Do not sum repeated snapshots of a cumulative counter or substitute an instantaneous gauge for an event count.
- Subsets must agree with totals: for example, new filenames <= unique filenames <= file accesses, and new domains <= unique domains <= HTTP requests. Daily interactive duration must not exceed 86,400 seconds.
- Do not replace unavailable sensor measurements with zero. Zero means measured zero activity; unavailable measurements need collector/contract remediation before admission.
- Keep raw timestamps for provenance and daily aggregation upstream. Pass only the calendar date as ordering metadata; raw timestamps and endpoint IDs are not numeric predictors.

An original Harmonized collector CSV is not automatically a valid V3 input. A verified preprocessing adapter must produce the daily40 feature cache. The supplied RealTime archive also cannot currently meet the full verified daily40/history requirements; the supporting observed-data audit remains in the original research workspace, outside this inference package.

## There are two different sets of 40 features

1. **What you provide:** the 40 raw daily features listed above.
2. **What XGBoost receives internally:** 32 transformed behavioral features + 4 domain Isolation Forest scores + 1 combined IF risk + 3 historical risk features = 40 engineered features.

Do not supply the engineered set in place of the raw set. V3 builds it itself. RedRVFL then receives seven preceding daily fused-risk values, rather than these 40 columns directly. TreeSHAP explains the engineered XGBoost row.

## History and final Top-K

Daily IF and classifier scores can be computed from a valid daily row, with limited historical context during startup. One row is not enough for the complete temporal/review pipeline.

- One RedRVFL forecast/error needs seven preceding consecutive complete daily observations plus the target day: **8 daily observations**.
- The operational review queue needs 15 consecutive valid target days plus the seven-day warmup: **22 consecutive complete daily observations per endpoint from a cold start**, ending at the common review date.
- Missing days must not be fabricated or joined across gaps. Rows must preserve the correct endpoint/date identity.
- The default review budget is **up to K = 20**, after the frozen evidence threshold and coverage checks. It does not force 20 results when fewer qualify.

## Run prediction

From the workspace parent, using the model's pinned Python dependencies:

```powershell
python model/predict.py --features path/to/X.csv --metadata path/to/metadata.csv --output path/to/predictions --max-reviews 20
```

For a live batch, also supply `--as-of YYYY-MM-DD` with the actual review date. Without it, the latest input date is used for historical replay; that does not prove the data is current.

Outputs include daily predictions, host rankings, the thresholded review queue and a summary. Matching the 40-column schema enables compatible inference; it does not guarantee a correct attack-class prediction or confirm that a person is an insider.
