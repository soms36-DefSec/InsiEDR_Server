# Model V3: actual results

Separate local experiment named Model V3 by the user. Original V2 and the earlier precision-first review policy are preserved. Eight named outputs include BENIGN plus all seven synthetic attack families. No final-evaluation data are used to fit or select thresholds.

## Data and fitting

- Training seeds 66001/66002 plus clustered-normal seeds 66041/66042, 216 hosts × 60 days each: 51,840 daily rows. Hosts/campaign IDs are prefixed by role/seed. These are synthetic examples, not reclassified old test records.
- Calibration seeds 66611/66612 (standard) and 66613/66614 (clustered normal) are separate from fitting. Both the review cutoff and daily thresholds use calibration outcomes, so their calibration numbers are selected-sample results.
- Final standard seed 66621 and clustered-normal stress 66622 are generated only after freezing weights and thresholds. They share attack mechanisms and the same synthetic calendar; this is not real-world, future-season or genuinely unseen-family validation.
- The same four-domain IF and 40-input XGBoost schema are retained. Two depth-3, 240-tree boosters use the original regularization and row/column subsampling. Class weights are capped at 5.
- RedRVFL is refitted: upstream scores are chronological out-of-fold, training windows require eight normal consecutive days, and windows cannot cross fold boundaries. Seven fused-risk inputs, three frozen random-LSTM64 layers, Ridge alpha 1000, median forecast, upward error.
- The original error-based temporal rank is retained and exported separately. The optional precision-first queue is still an architectural extension: supervised two-day threat persistence first, then independent anomaly candidates, with no padding to K.

## Frozen policy

```json
{
  "supervised_cutoff": 0.41032636165618896,
  "novelty_cutoff": null
}
```

Independent novelty route enabled: **False**. It uses the maximum daily second-largest domain anomaly score over the latest 15 calendar target dates: at least two domains must supply anomaly evidence. It does not require a high XGBoost score. A candidate route is accepted only when calibration finds extra attack hosts while retaining the prespecified precision/recall/false-review gates. If disabled, it remains a tested structural capability, not a promoted detector.

## New classes: naming accuracy versus detecting an attack

Scenario recall below means correctly naming that exact scenario on its labeled days. It is not the same as binary attack detection or host-review recall. BENIGN is normal.

| Population | Scenario | Days | Scenario precision | Scenario recall | Scenario F1 | Original V2 exact-name recall |
|---|---|---|---|---|---|---|
| final_standard | HONEYTOKEN_TRIP | 27 | 85.7% | 88.9% | 87.3% | 0.0% |
| final_standard | KILL_CHAIN_APT | 22 | 0.0% | 0.0% | 0.0% | 0.0% |
| final_normal_stress | HONEYTOKEN_TRIP | 26 | 87.0% | 76.9% | 81.6% | 0.0% |
| final_normal_stress | KILL_CHAIN_APT | 25 | 6.5% | 8.0% | 7.1% | 0.0% |

Original V2 exact-name recall is zero by construction: those labels do not exist in its output vocabulary. This does not imply its binary attack recall was zero.

## Accepted host queues: original V2 at the same review count

| Population | Reviews each | V2 found | Eight-class found | V2 precision | Eight-class precision | V2 recall | Eight-class recall | Anomaly referrals |
|---|---|---|---|---|---|---|---|---|
| final_standard | 20 | 14 | 16 | 70.0% | 80.0% | 77.8% | 88.9% | 0 |
| final_normal_stress | 20 | 13 | 14 | 65.0% | 70.0% | 72.2% | 77.8% | 0 |

## Daily attack detection on identical populations

| Population | Version / stage | Precision | Recall | Balanced accuracy | Accuracy | Normal FPR | AP |
|---|---|---|---|---|---|---|---|
| final_standard | V2 threat | 40.7% | 68.6% | 83.7% | 98.4% | 1.2% | 0.6589 |
| final_standard | Eight-class threat | 57.5% | 79.2% | 89.3% | 99.0% | 0.7% | 0.7818 |
| final_standard | V2 temporal | 44.7% | 66.7% | 82.8% | 98.4% | 1.2% | 0.6484 |
| final_standard | Eight-class temporal | 56.2% | 79.2% | 89.2% | 98.9% | 0.9% | 0.7560 |
| final_normal_stress | V2 threat | 23.2% | 69.6% | 83.3% | 96.8% | 2.9% | 0.6294 |
| final_normal_stress | Eight-class threat | 35.2% | 80.1% | 89.1% | 97.9% | 1.9% | 0.7617 |
| final_normal_stress | V2 temporal | 26.3% | 67.7% | 82.5% | 96.9% | 2.7% | 0.6264 |
| final_normal_stress | Eight-class temporal | 32.9% | 79.5% | 88.6% | 97.4% | 2.3% | 0.7345 |

## All eight scenario outputs on final populations

| Population | Scenario | Days | Precision | Recall | F1 |
|---|---|---|---|---|---|
| final_standard | BENIGN | 12801 | 99.7% | 99.6% | 99.7% |
| final_standard | CLOUD_EXFILTRATION_PRECURSOR | 21 | 52.0% | 61.9% | 56.5% |
| final_standard | CREDENTIAL_DUMP | 22 | 52.9% | 81.8% | 64.3% |
| final_standard | DATA_HOARDING | 23 | 44.7% | 73.9% | 55.7% |
| final_standard | IT_SABOTAGE | 22 | 91.3% | 95.5% | 93.3% |
| final_standard | USB_EXFILTRATION_PRECURSOR | 22 | 80.0% | 72.7% | 76.2% |
| final_standard | HONEYTOKEN_TRIP | 27 | 85.7% | 88.9% | 87.3% |
| final_standard | KILL_CHAIN_APT | 22 | 0.0% | 0.0% | 0.0% |
| final_normal_stress | BENIGN | 12799 | 99.7% | 98.9% | 99.3% |
| final_normal_stress | CLOUD_EXFILTRATION_PRECURSOR | 18 | 41.9% | 72.2% | 53.1% |
| final_normal_stress | CREDENTIAL_DUMP | 22 | 28.8% | 68.2% | 40.5% |
| final_normal_stress | DATA_HOARDING | 26 | 23.7% | 69.2% | 35.3% |
| final_normal_stress | IT_SABOTAGE | 25 | 83.3% | 100.0% | 90.9% |
| final_normal_stress | USB_EXFILTRATION_PRECURSOR | 19 | 57.1% | 84.2% | 68.1% |
| final_normal_stress | HONEYTOKEN_TRIP | 26 | 87.0% | 76.9% | 81.6% |
| final_normal_stress | KILL_CHAIN_APT | 25 | 6.5% | 8.0% | 7.1% |

## Fixed review budgets

P/R below mean host precision / host recall. Eight-class temporal is the original architecture score using the new model; eight-class pair is forced threat-persistence ranking. Accepted applies frozen cutoffs before the budget.

| Population | K | V2 P/R | Eight-class temporal P/R | Eight-class pair P/R | Accepted N | Accepted P/R |
|---|---|---|---|---|---|---|
| final_standard | 5 | 80.0% / 22.2% | 80.0% / 22.2% | 100.0% / 27.8% | 5 | 100.0% / 27.8% |
| final_standard | 10 | 90.0% / 50.0% | 90.0% / 50.0% | 100.0% / 55.6% | 10 | 100.0% / 55.6% |
| final_standard | 15 | 80.0% / 66.7% | 86.7% / 72.2% | 93.3% / 77.8% | 15 | 93.3% / 77.8% |
| final_standard | 20 | 70.0% / 77.8% | 80.0% / 88.9% | 80.0% / 88.9% | 20 | 80.0% / 88.9% |
| final_standard | 30 | 46.7% / 77.8% | 53.3% / 88.9% | 53.3% / 88.9% | 22 | 72.7% / 88.9% |
| final_normal_stress | 5 | 100.0% / 27.8% | 100.0% / 27.8% | 100.0% / 27.8% | 5 | 100.0% / 27.8% |
| final_normal_stress | 10 | 100.0% / 55.6% | 100.0% / 55.6% | 100.0% / 55.6% | 10 | 100.0% / 55.6% |
| final_normal_stress | 15 | 80.0% / 66.7% | 86.7% / 72.2% | 93.3% / 77.8% | 15 | 93.3% / 77.8% |
| final_normal_stress | 20 | 65.0% / 72.2% | 70.0% / 77.8% | 70.0% / 77.8% | 20 | 70.0% / 77.8% |
| final_normal_stress | 30 | 46.7% / 77.8% | 50.0% / 83.3% | 46.7% / 77.8% | 27 | 51.9% / 77.8% |

## Generalization and unresolved limitations

| Population | Scenario macro-F1 | Threat AP | Temporal AP | Queue precision | Queue recall |
|---|---|---|---|---|---|
| training | 0.7020 | 0.8420 | 0.8197 | 100.0% | 27.8% |
| calibration_66611 | 0.6903 | 0.7968 | 0.7731 | 85.7% | 66.7% |
| calibration_66612 | 0.6086 | 0.6839 | 0.6742 | 91.7% | 61.1% |
| calibration_66613 | 0.5979 | 0.7952 | 0.7683 | 75.0% | 83.3% |
| calibration_66614 | 0.6783 | 0.7878 | 0.7396 | 75.0% | 83.3% |
| final_standard | 0.6662 | 0.7818 | 0.7560 | 80.0% | 88.9% |
| final_normal_stress | 0.5949 | 0.7617 | 0.7345 | 70.0% | 77.8% |

- Adding labels permits explicit classification; it does not guarantee identifying every campaign. Kill-chain phases can resemble several primitives, and aggregate daily measurements can obscure temporal composition.
- Both formerly held-out families are now known supervised scenarios. They cannot also serve as unseen-family evaluation for this model. Truly novel attacks have no named output among these eight; the anomaly route can only refer them for investigation.
- A working classifier-independent route eliminates the mathematical need for high supervised probability; it does not prove that an IF can detect every unfamiliar behavior. Calibration disabling the route is a failure to establish its utility, not a reason to silently lower the bar.
- Review candidates are not confirmed insiders. Class probabilities are class-weighted model outputs, not calibrated probabilities of a person being malicious.
- Fresh seeds, disjoint IDs and duplicate checks do not establish independent synthetic mechanisms. Training/calibration/final gaps must be retained; no overfitting-free or production-readiness claim follows.
- TreeSHAP explains each booster class margin on the actual engineered 40-feature rows; average contributions do not add to the averaged probability or explain the temporal score.
- Previously published V2 and the precision-first review policy were not overwritten or pushed. This experiment requires separate review before promotion.

## Reproduce inference

```powershell
python model_v3/predict.py --features model_v3/data/final_standard_66621/X.csv --metadata model_v3/data/final_standard_66621/metadata.csv --output model_v3/inference_check --max-reviews 20
```

The input metadata allowlist is hostname/date, plus an optional observation-completeness gate. Labels, campaign IDs and synthetic maintenance flags never enter predictors. Training decisions, frozen hashes, full confusion matrices, saved predictions, SHAP arrays and checks are retained in run/.

## Accepted-queue sampling uncertainty

| Population | Reviews | Precision point estimate | Exact-binomial 95% lower | Upper |
|---|---|---|---|---|
| final_standard | 20 | 80.0% | 56.3% | 94.3% |
| final_normal_stress | 20 | 70.0% | 45.7% | 88.1% |

Intervals are descriptive under an independent-host binomial approximation; synthetic dependencies can invalidate that approximation. Small queues cannot establish guaranteed 80% precision.

## Prevalence sensitivity (planning calculation only)

Holding calibration recall and normal-review rate fixed, expected precision at prevalence p is p×recall / (p×recall + (1−p)×normal_review_rate). This is not a measured real-world result; rates and budget effects can change with the population.

| Assumed attack-host prevalence | Projected precision with fixed calibration rates |
|---|---|
| 0.1% | 4.3% |
| 1.0% | 31.2% |
| 4.0% | 65.1% |
| 8.3% | 80.3% |

## Overlapping behavior outputs

Eight independent binary heads supplement the eight-class softmax. They use the same engineered 40 inputs and phase-level synthetic targets. Multiple behaviors can be active on one day. They do not change the frozen review queue or prove an ordered kill-chain campaign. Thresholds can abstain for a label that fails calibration. Fresh behavior evaluation seeds 66631/66632 were generated only after their own freeze.

| Population | Behavior | Support | Enabled | Precision | Recall | F1 | AP |
|---|---|---|---|---|---|---|---|
| behavior_final_standard | CREDENTIAL_DUMP | 32 | True | 90.3% | 87.5% | 88.9% | 0.9379 |
| behavior_final_standard | USB_EXFILTRATION_PRECURSOR | 21 | True | 76.5% | 61.9% | 68.4% | 0.7378 |
| behavior_final_standard | IT_SABOTAGE | 25 | True | 89.3% | 100.0% | 94.3% | 1.0000 |
| behavior_final_standard | CLOUD_EXFILTRATION_PRECURSOR | 31 | True | 100.0% | 71.0% | 83.0% | 0.8193 |
| behavior_final_standard | DATA_HOARDING | 21 | True | 75.0% | 71.4% | 73.2% | 0.7709 |
| behavior_final_standard | HONEYTOKEN_TRIP | 23 | True | 81.0% | 73.9% | 77.3% | 0.8243 |
| behavior_final_standard | RECON | 9 | True | 100.0% | 11.1% | 20.0% | 0.3501 |
| behavior_final_standard | STAGING | 9 | False | 0.0% | 0.0% | 0.0% | 0.3581 |
| behavior_final_stress | CREDENTIAL_DUMP | 36 | True | 76.9% | 83.3% | 80.0% | 0.8802 |
| behavior_final_stress | USB_EXFILTRATION_PRECURSOR | 20 | True | 68.8% | 55.0% | 61.1% | 0.6455 |
| behavior_final_stress | IT_SABOTAGE | 24 | True | 100.0% | 100.0% | 100.0% | 1.0000 |
| behavior_final_stress | CLOUD_EXFILTRATION_PRECURSOR | 34 | True | 70.6% | 70.6% | 70.6% | 0.7976 |
| behavior_final_stress | DATA_HOARDING | 25 | True | 42.9% | 36.0% | 39.1% | 0.3761 |
| behavior_final_stress | HONEYTOKEN_TRIP | 24 | True | 76.0% | 79.2% | 77.6% | 0.7596 |
| behavior_final_stress | RECON | 11 | True | 66.7% | 18.2% | 28.6% | 0.2295 |
| behavior_final_stress | STAGING | 11 | False | 0.0% | 0.0% | 0.0% | 0.2394 |

## Comparison with prior variants on the same final populations

Each variant uses its own frozen rule; operational queues can differ in size. The matched-budget V2 row uses exactly the Model V3 review count. No outcome in this table changes weights or cutoffs.

| Population | Variant | Rule | Reviewed | TP | FP | Precision | Recall |
|---|---|---|---|---|---|---|---|
| final_standard | Original V2 | operational_queue | 20 | 14 | 6 | 70.0% | 77.8% |
| final_standard | Original V2 | temporal_top20 | 20 | 14 | 6 | 70.0% | 77.8% |
| final_standard | Precision-first review policy | operational_queue | 11 | 10 | 1 | 90.9% | 55.6% |
| final_standard | First eight-class candidate | operational_queue | 14 | 13 | 1 | 92.9% | 72.2% |
| final_standard | First eight-class candidate | temporal_top20 | 20 | 14 | 6 | 70.0% | 77.8% |
| final_standard | Model V3 | operational_queue | 20 | 16 | 4 | 80.0% | 88.9% |
| final_standard | Model V3 | temporal_top20 | 20 | 16 | 4 | 80.0% | 88.9% |
| final_standard | Original V2 | matched_to_Model_V3_reviews | 20 | 14 | 6 | 70.0% | 77.8% |
| final_normal_stress | Original V2 | operational_queue | 20 | 13 | 7 | 65.0% | 72.2% |
| final_normal_stress | Original V2 | temporal_top20 | 20 | 13 | 7 | 65.0% | 72.2% |
| final_normal_stress | Precision-first review policy | operational_queue | 16 | 14 | 2 | 87.5% | 77.8% |
| final_normal_stress | First eight-class candidate | operational_queue | 20 | 13 | 7 | 65.0% | 72.2% |
| final_normal_stress | First eight-class candidate | temporal_top20 | 20 | 12 | 8 | 60.0% | 66.7% |
| final_normal_stress | Model V3 | operational_queue | 20 | 14 | 6 | 70.0% | 77.8% |
| final_normal_stress | Model V3 | temporal_top20 | 20 | 14 | 6 | 70.0% | 77.8% |
| final_normal_stress | Original V2 | matched_to_Model_V3_reviews | 20 | 13 | 7 | 65.0% | 72.2% |
