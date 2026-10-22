# Model V3 dataset replay

The isolated scenario stack has been retired. Use the main Docker deployment
workflow in [MAIN_DASHBOARD_DATASET_REPLAY.md](MAIN_DASHBOARD_DATASET_REPLAY.md).
The replay is source-tagged synthetic data, writes historical records to the
main telemetry stores, and uses computed frozen-model output. It does not set
preset threat scores or change live alert severity.

Run the unified entry point from the repository root:

```bash
python scripts/simulate_all_scenarios.py --mode run
```

The main deployment currently supports seven dataset-backed attack hosts. It
does not provide a separate scenario dashboard, a separate database stack, or a
main-database cleanup command.
