# InsiEDR Detection Pipeline

This page documents the live deterministic, authentication, and user-baseline risk path. ML inference and training are owned by the ML team and plug into the same detector-result interface; this document does not define their implementation.

## Scenario IDs

| ID | Meaning | Evidence required |
| --- | --- | --- |
| `S1` | IT sabotage | At least 10 sampled delete operations plus a verified service, privilege, persistence, or driver change, or destructive activity with after-hours authentication/an authentication burst. Deletion alone is a precursor. |
| `S2` | Data hoarding / broad file collection | High file volume and breadth, sensitive-file access, or a user-baseline deviation. Ordinary audit events are not evidence of copying. |
| `S3` | Removable-media exfiltration | A file-to-removable transfer counter. Device insertion alone is `S3_PRECURSOR`. |
| `S4` | Cloud exfiltration | Upload activity correlated with sensitive-file access or unusual collection. A file-sharing site visit alone is `S4_PRECURSOR`. |
| `HONEYTOKEN` | Decoy interaction | The decoy collector reports `threat_triggered=true`; this is an immediate critical signal. |

Scenario IDs are shared by heuristic detections and CERT correlation output. `S1_CRED_DUMP` and `S1_INJECTION` are dedicated endpoint-security scenarios; `NETWORK_TUNNELING` is a separate network indicator and does not mean cloud exfiltration (`S4`). `AUTH_BURST`, `AUTH_LATERAL`, `FILE_DELETE`, and `S*_PRECURSOR` are supporting signal IDs, not confirmed CERT scenarios.

## Live analytical path

1. **Feature extraction:** root payload identity (`username`, `hostname`, and `agent_id`) is authoritative. User-keyed collector data is unwrapped only for the matching root username. Host-scoped collectors inherit root identity for the live risk event; an unmatched user-keyed collector is not merged into another user's features.
2. **Deterministic heuristics:** rules evaluate logon, file, HTTP, removable-media, endpoint-security, and honeytoken evidence. LSASS credential-dumping reports retain a critical score floor across workload profiles; credential, execution/memory, and deception findings are kept in separate domains from ordinary file activity. Unbacked executable memory and process/DNS tunneling indicators are high severity. File-sharing visits and device insertions are low-confidence precursors until transfer evidence exists.
3. **Authentication burst:** the five-minute short-term EDR fields detect high failure ratios, repeated failures, rapid authentication across workstations, and repeated off-hours logons. Because current collectors aggregate from the Windows Security event log without per-account attribution, these metrics are treated as host-scoped indicators (`HIGH_FAILURE_BURST`, `MULTI_WORKSTATION_BURST`, `VELOCITY_BURST`, `OFF_HOURS_BURST`) rather than asserting specific tactical attack labels (e.g. brute force against a specific account or password spray). They do not independently establish a multi-stage sequence.
4. **Baseline and z-score:** baseline rows are keyed by the root payload username, which represents the agent's active primary session. This is not kernel-enforced per-user SID attribution: host-wide activity observed while that session is active can still affect flattened file, HTTP, device, or egress counters. Known host-scoped authentication counters are excluded from personal and role baseline features, and the agent's host-wide `logon_velocity_zscore` is not passed into the per-user z-score path. The auth burst detector currently uses host-level thresholds; the auth priors in `DEFAULT_FEATURE_PRIORS` are not used by the live per-user baseline path. Adding adaptive auth baselines requires a separate host-scoped baseline keyed by agent identity, rather than mixing those metrics into a user's baseline. If a user has fewer than 5 observations, the engine falls back to their role peer baseline (`__role_{role_name}__`), and finally to organizational safe priors during cold start. Role cohort baselines track member updates independently and serialize writes using PostgreSQL transaction-level advisory locks (`pg_advisory_xact_lock`) so concurrent Uvicorn worker processes neither throttle nor overwrite one another. Inactive cohort member entries older than 48 hours are automatically pruned. Baselines sample at most once per user per hour and only accept observations whose final risk is below `MEDIUM` (score < 40), limiting duplicate-snapshot influence and anomaly poisoning. Older or out-of-order observations are skipped to keep baseline updates chronological; they return before missing-feature counters are changed. The default z-score **risk mapping** maps 2σ→0, 3σ→40, 5σ→70, 7σ→95, and 8σ→100 (with interpolation). These are calibrated risk scores, not probabilities or p-values. Multi-domain corroboration considers domains above 2σ and can raise the score above the strongest single-domain result.
5. **Stateful Multi-Stage Kill-Chain Tracking:** temporal sequence evaluation correlates host stages (`CREDENTIAL_ACCESS`, `LATERAL_MOVEMENT`, `EXECUTION_PERSISTENCE`, `COLLECTION_STAGING`, `EXFILTRATION_SABOTAGE`) across a rolling 4-hour window for the same agent. Progression requires a stage in a prior event and a different newly observed stage in the current event. Multiple stages reported by one snapshot do not establish a sequence. A qualifying progression across 2 stages applies an 85.0 (`HIGH`) floor; 3 or more stages apply a 95.0 (`CRITICAL`) floor and satisfy the corroboration guard.
6. **Aggregation:** active detector weights are renormalized over detectors that ran. The deterministic heuristic score is a floor, so absent model output cannot suppress it. Prior risk may raise the result through temporal smoothing, but cannot lower the current score.

The model team may add outputs as detector results with a name, score in `[0,100]`, confidence, and optional evidence. Missing model output is excluded from the ensemble rather than treated as a zero-risk model prediction.

## Risk levels

| Score | Level |
| ---: | --- |
| 0–39 | `LOW` |
| 40–69 | `MEDIUM` |
| 70–89 | `HIGH` |
| 90–100 | `CRITICAL` |

## Data and baseline constraints

- Monitor exports may be host-attributed even when the live root payload contains a resolved username. Use `payload_id` to join live storage records. For CSVs without `payload_id`, a `(hostname, timestamp rounded to the nearest second)` join is an export-time fallback and must be checked for collisions.
- Telemetry snapshots repeat rolling or daily counters. Do not treat rows as independent actions or baseline samples.
- Missing fields remain unavailable; they must not be interpreted as zero activity.
- The current collectors do not provide all evidence needed for high-confidence hoarding or exfiltration. In particular, file copy counts, sensitive-file classification, USB transfer volume, and cloud upload bytes may be unavailable. In those cases the system emits a precursor or does not claim a confirmed scenario.
- Baselines are keyed to the root username/active primary session, not guaranteed SID-attributed activity. Host-level authentication logs are evaluated as host indicators, not credited or debited to the individual user baseline. If the root username is missing, the risk event is marked `unknown` and no user baseline is read or updated.
- A kill-chain progression requires at least one stage from an earlier event and a different stage newly present in the current event; stages co-reported by one snapshot do not constitute progression.
