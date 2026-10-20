# Model V3 details

## Input and feature engineering

Each row describes one endpoint on one day. The exact ordered 40 raw measurements and separate metadata are in [INPUT_DATA_REQUIREMENTS.md](INPUT_DATA_REQUIREMENTS.md) and `run/schema.json`. Raw timestamps, identifiers, campaign IDs and labels are not predictors. Missing real sensor measurements must not become zeros.

Four domain forests model identity, device/file, web/network and execution. Each receives log1p values; anomaly scores are mapped to percentiles against reserved normal training hosts. Only scores above the 90th percentile contribute risk. Combined IF risk is the equal-weight mean of the four domain scores.

XGBoost receives 32 retained log-level behavioral measurements, four domain scores, their mean and three past-only context features: past-seven risk mean, past-seven risk standard deviation and current risk minus the past mean. Current-day information is excluded from the historical reference; history resets across missing dates.

## Class and behavior outputs

The scenario ensemble averages two eight-class softmax models with this order:

1. BENIGN (normal)
2. CLOUD_EXFILTRATION_PRECURSOR
3. CREDENTIAL_DUMP
4. DATA_HOARDING
5. IT_SABOTAGE
6. USB_EXFILTRATION_PRECURSOR
7. HONEYTOKEN_TRIP
8. KILL_CHAIN_APT

These are alternative primary class scores. Eight separate binary heads permit simultaneous credential dump, USB precursor, sabotage, cloud precursor, hoarding, honeytoken, reconnaissance and staging hypotheses. They use phase-derived synthetic targets. A null behavior threshold means the head abstains; it does not establish absence of the behavior. Predicting several phases does not validate a complete ordered campaign.

## Temporal model and ranking

```text
threat_probability = 1 - P(BENIGN)
fused_risk = 0.85 * threat_probability + 0.15 * mean_IF_risk
input_for_day_D = [fused_risk(D-7), ..., fused_risk(D-1)]
temporal_error(D) = max(actual_fused_risk(D) - forecast(D), 0)
```

RedRVFL uses three frozen random LSTM layers, 64 hidden units each, and Ridge readouts with alpha 1000. The three forecasts are combined by their median and clipped to [0,1]. The forecast error is available after observing the target day's data; it is not a prediction of insider intent before that behavior occurs.

The faithful historical temporal ranking is max(error) * mean(error) * sqrt(sequence_count). The operational V3 queue instead ranks the largest adjacent-day minimum threat probability across 15 consecutive valid target days. The supervised cutoff is **0.41032636165618896**. Novelty-only cutoff is null, so that route is disabled. Apply a review-budget cap after eligibility and thresholds; default is up to 20.

## Training and calibration

- Fitting: four synthetic cohorts, 216 endpoints x 60 days each, totaling 51,840 daily rows. Two cohorts include clustered legitimate activity. Seed lists and hyperparameters are in `run/protocol.json`.
- Isolation Forests fit generated normal training rows, with disjoint reserved training hosts used for percentile calibration.
- Two depth 3, 240-tree XGBoost models use learning rate .035, strong regularization and capped class weights. Exact code is in `core.py`.
- RedRVFL fits normal-only chronological out-of-fold upstream risk windows; attack windows, gaps and fold-boundary bridges are excluded.
- Separate calibration cohorts select daily thresholds, review cutoffs and behavior thresholds. Final standard/stress cohorts are generated after freezing these artifacts.
- All of this is synthetic research evidence. New seeds or IDs do not establish new attack mechanisms or real-world generalization.

## Explanations

The saved experiment used native exact TreeSHAP to reconstruct each booster class margin on selected real input rows from the synthetic evaluation. TreeSHAP does not directly explain final probabilities, temporal errors, host ranking or intent. This inference package exposes model inputs/outputs, but does not include a live TreeSHAP endpoint or a walkthrough dataset.

## Limitations and observed-data audit

The supplied observed archive spans about 6.70 days globally, with at most three consecutive calendar dates per endpoint. Some required counters are entirely blank or have unverified windows. It was used as collector-quality evidence, not relabeled benign or admitted as verified daily40 training. The full observed audit remains in the research workspace, not this repository.

Known limitations include weak exact kill-chain naming, disabled novelty referrals, STAGING-head abstention, small synthetic attack populations, unvalidated redundancy assumptions for the eight direct-feature omissions, missing observed labels and uncertain real collector semantics. Detailed failures remain in [run/PRODUCTION_READINESS.md](run/PRODUCTION_READINESS.md). V3 is a research candidate for analyst-assisted review, not an autonomous disciplinary or endpoint-response verdict.
