# Daily40 source audit (Rust agent, 21 October 2026)

The default server collector table is `collector_results` (schema v1). The
operator's reported payload-key inventory is useful context but is not a raw
24-hour export. The local ClickHouse endpoint was unavailable during this
audit, so the points below come from the checked-in Rust collectors. They
block setting `feature_contract_verified=1` for the current payloads.

| Model V3 fields | Checked-in source finding | Required work |
|---|---|---|
| `interactive_duration_seconds`, `mean_session_duration_seconds`, `pc_access_entropy` | `logon.rs` emits no interactive duration; `session_duration_avg` is fixed at 3600 and PC entropy is `log2(unique_pc_count)`, not the entropy of observed destinations. | Collect actual session intervals and destination frequencies. |
| `usb_connect_count`, `usb_disconnect_count`, `after_hours_usb_ratio` | `usb_devices.rs` reports the current connected-device count as connects, and hardcodes disconnects and after-hours use to zero. | Emit deduplicated arrival/removal events and UTC event times. |
| `file_access_count`, `new_filename_count`, `file_access_entropy`, `protected_file_touch_count` | `file_integrity.rs` scans and hashes files, emits `AUDIT` records, and hardcodes new-file count and entropy to zero. | Provide event-based file access and creation telemetry with stable file identities. |
| `file_delete_count` | `usn.rs` emits `daily_file_deletes_utc` deltas by native record date. It does not emit `cumulative_file_deletes` or `file_delete_count_delta`. | Sum deduplicated, disjoint USN reads by record date, checking all volumes and gap reports. |
| `new_domain_count` | `browser_history.rs` currently hardcodes `daily_new_domain_count` to zero; its other `daily_*` metrics use a rolling 24-hour window. | Derive genuine first-seen domains and calendar-day windows from timestamped visits. |
| `bytes_sent`, `bytes_received`, `external_connection_count`, `unique_remote_ip_count` | `network.rs` emits only `active_connections_count` and a socket snapshot. It has no byte counters or complete connection lifecycle. | Add per-interface byte counter provenance and connection events; account for wraps/restarts. |
| `lsass_handle_request_count`, `memory_dump_attempt_count` | `lsass.rs` is a passive placeholder with `event_count=0`; it has neither required counter. | Implement verified handle and dump-attempt observations. |
| `wmi_query_count`, `outbound_attachment_count` | `wmi_activity.rs` reports a passive zero; `email.rs` hardcodes attachment count to zero. | Implement measured event sources or keep these fields unavailable. |
| `named_pipe_event_count` | `named_pipe.rs` reports a sampled `pipe_count` gauge. | Capture pipe events, with stable deduplication. |
| `dns_query_count` | `dns.rs` can emit a static zero when real-time ETW is inactive. | Reject the fallback as coverage and aggregate only real query events. |

`ClickHouseStorage._derive_source_quality` assigns broad collector-name labels.
Older rows did not preserve the agent's `QualityFlags`. A `status='success'` row or a
`source_quality='high'` label therefore cannot prove exact measurement or
continuous sensor coverage. One success per collector in a day is insufficient.
The proposed 23:50 latest-snapshot rule also cannot convert a rolling 24-hour
lookback into an exact UTC calendar-day feature.

Use `scripts/inventory_model_v3_sources.py` on the deployment host to collect
read-only first/last timestamps, failure and USN-gap counts, and the latest
actual payload keys. The full producer needs a versioned mapping and verified
coverage policy for every required field before any row can be marked complete.

## Python-agent capture supplied in the conversation

The `SOCL4-61` examples for 12 October 2026 were produced by an older Python
agent, not the Rust service audited above. The samples are three points in
time, beginning at 03:20 UTC. They are not a complete 24-hour export, and the
private RealTime archive is not included in this repository. The historical
sample therefore cannot establish `observation_complete=1` or a 22-day host
sequence. Its USN payload reports that an elevated handle was unavailable;
zero USN records in that case are **missing observation**, not measured zero
deletions. New Python `usn_monitor.py` emits `daily_file_deletes_utc` plus
volume gap state, but it cannot reconstruct records absent from the old run.

The checked-in Python `network_monitor.py` emits top-level
`network_bytes_sent` and `network_bytes_recv`. Its nested interface objects
have `bytes_sent` and `bytes_recv`; neither maps to a top-level
`bytes_sent` feature without a reset-safe interval calculation. The supplied
USB and file counts repeat across snapshots, so summing rows overcounts.
`named_pipe_monitor.py` emits a sampled pipe inventory, not creation events.
`email_monitor.py` emits `large_attachment_count`, which does not equal all
outbound attachments. These fields remain unavailable for the V3 feature
contract until the source definition is aligned with the model.

Newly ingested `collector_results` and `collector_events_v2` rows retain
the agent's `quality` and `feature_quality` as separate JSON columns. Existing
rows have blank defaults. The legacy derived `source_quality` remains for
other readers but must never be treated as an exactness attestation.
