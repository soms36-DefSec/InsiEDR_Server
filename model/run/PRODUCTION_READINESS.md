# Model V3: production readiness

**Status: research candidate; not production ready.** A local implementation can add controls and improve measured synthetic performance, but cannot certify real endpoint accuracy.

## Fixed or reduced in this iteration

- Two previously absent scenario outputs added, with genuine supervised training examples from fresh fitting cohorts.
- Phase-derived independent behavior heads allow overlapping behaviors without falsely labeling every kill-chain day with every primitive.
- Clustered legitimate activity included in fitting and calibration after the first candidate failed that stress. The failure remains recorded; new final seeds are reserved.
- A classifier-independent multi-domain anomaly review route is calibrated separately and must add detections while satisfying false-review gates.
- Seven-day temporal fitting uses chronological out-of-fold scores and fully normal windows; no bridging over gaps or attacks.
- Saved label-free inference checks schema/order, invalid values, ratios/subsets, duplicate keys, model hashes, coverage and review budgets. Missing completeness metadata abstains.
- Full probabilities, forecast errors, evidence routes, all ranking outputs, SHAP margins, cutoffs, checksums and comparison results are exportable.
- Training-only feature-distribution references support descriptive shift monitoring. They are not validated automatic drift alarms.

## Synthetic result gates

```json
{
  "final_standard": {
    "queue_precision_80": true,
    "queue_recall_70": true,
    "normal_host_review_rate_2": false,
    "scenario_macro_f1_70": false,
    "kill_chain_naming_recall_50": false
  },
  "final_normal_stress": {
    "queue_precision_80": false,
    "queue_recall_70": true,
    "normal_host_review_rate_2": false,
    "scenario_macro_f1_70": false,
    "kill_chain_naming_recall_50": false
  }
}
```

## Still unresolved

- No independently observed endpoint evaluation or real prevalence estimate
- No validated ordered campaign detector; scalar risk forecasts lose phase detail
- Unseen attack mechanisms not established by changing random seeds
- Small attack sample counts and synthetic phase-label ambiguity
- Eight direct feature omissions remain an unverified redundancy assumption
- Real collector aggregation/availability and identity attribution require integration testing
- Operational alert delay, drift thresholds, recovery and throughput not field-validated

No failed test is erased or used for cutoff retuning. Additional work after these final outcomes requires new development evidence and another untouched final evaluation. No deployment or GitHub push occurs in this task.
