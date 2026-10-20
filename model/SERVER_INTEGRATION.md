# Server integration boundary

This commit publishes the frozen model under `model/`; it does not wire inference into request handlers, modify root dependencies, change server thresholds or enable endpoint actions. The live server's [detection contract](../docs/DETECTION_PIPELINE.md) and `server/risk/pipeline.py` currently treat ML as an external detector integration.

## Required integration work

1. Build a verified raw-collector-to-daily40 adapter. Confirm event/counter windows, resets, units, timezone and sensor completeness. Do not sum rolling snapshots or fill unavailable values with zeros.
2. Maintain histories by stable endpoint identity. V3 uses hostname as its endpoint key; the server uses registered agent identity and root payload attribution. Resolve identity changes and shared machines explicitly. Host-level evidence is not automatically an individual-user verdict.
3. Run scheduled batch inference with a common explicit review date. Daily scores and a multi-day queue have different availability; preserve existing real-time heuristic detection during cold start or model abstention.
4. Add a bounded model worker/service compatible with the server's deployment environment. The CLI is verified; importing `model.predict` directly as a FastAPI API is not a supported integration in this commit. Test startup, dependency isolation, concurrency, failures and artifact lifecycle before wiring it in.
5. Adapt outputs to a detector result with detector_name, a calibrated [0,100] score, confidence and optional evidence. V3 probabilities/IF risks/errors are [0,1], and its host ranking score is not automatically a probability. Validate the conversion and confidence semantics; do not invent confidence or retune the frozen model on final test outcomes.
6. Preserve timestamps, coverage, model version, probabilities and supporting dates in evidence. Missing or incomplete model results should be absent/abstaining, not healthy zero-risk predictions.

## Scenario semantics

The model vocabulary differs from server CERT IDs. The following mappings are candidate interface meanings, not permission to bypass the server's evidence requirements:

| V3 hypothesis | Server meaning to preserve |
|---|---|
| BENIGN | Model normal hypothesis; not verified benign ground truth |
| IT_SABOTAGE | S1 hypothesis; retain required destructive/system-change corroboration |
| DATA_HOARDING | S2 collection/hoarding hypothesis; do not equate an audit event with a copy |
| USB_EXFILTRATION_PRECURSOR | S3_PRECURSOR; never promote to S3 without transfer evidence |
| CLOUD_EXFILTRATION_PRECURSOR | S4_PRECURSOR; never promote to S4 without upload/correlation evidence |
| CREDENTIAL_DUMP | Credential-access hypothesis; distinct from IT sabotage and a confirmed collector finding |
| HONEYTOKEN_TRIP | Model hypothesis; preserve the independent deterministic threat_triggered signal |
| KILL_CHAIN_APT | Campaign hypothesis; does not satisfy the server's ordered same-agent stage progression by itself |

Domain scores also need an explicit adapter: V3 identity/device-file/web-network/execution domains do not map one-to-one to server logon/file/device/network displays. Avoid duplicating a combined-domain score as independently corroborating evidence.

## Evaluation before promotion

Replay representative server exports through a verified adapter, preserve coverage, investigate false reviews and missed attacks, and evaluate independently reviewed labels on untouched hosts/periods. Then run a monitored shadow pilot. Synthetic queue precision is not a deployment-confidence value. No automatic isolation, account accusation or model-driven response is enabled here.
