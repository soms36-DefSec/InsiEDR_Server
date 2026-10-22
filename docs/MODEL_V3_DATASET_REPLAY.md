# Model V3 dataset replay on an isolated mirror

This workflow uses a separate PostgreSQL, ClickHouse, and Redis stack. It never writes generated daily40 rows to the observed production tables. The 22-day history is synthetic and is admitted to the unchanged frozen model with `source_kind=synthetic`; scores and threshold-selected reviews live in the mirror's `scenario_replay` schema. The operator provenance endpoint identifies original timestamps, dataset, run ID, and source kind for each replayed log.

## Preconditions

- Windows host with Docker Desktop running Linux containers and the server repo's `.venv` and `model/.venv` installed. `model/.venv` must pass `scripts/check_model_v3_prerequisites.py`.
- The three source folders must be present under `D:\Projects\AISH`: `Dataset_RealTime`, `Dataset_Simulated`, and `Dataset_Simulated_Harmonized`.
- No production PostgreSQL or ClickHouse DSN should be supplied to the replay CLI. Its guard requires local connections and `_scenario` database names. The separate Compose file binds all published ports to loopback and uses dedicated volumes.
- Do not point a deployed agent at this mirror. The configured agent tokens are generated solely for the seven dataset host IDs.

## Prepare

From `D:\Projects\AISH\InsiEDR_Server`:

```powershell
.venv\Scripts\python.exe scripts\scenario_replay.py init-env
docker compose --env-file .env.scenario -f docker-compose.scenario.yml up -d --build
.venv\Scripts\python.exe scripts\scenario_replay.py verify
.venv\Scripts\python.exe scripts\scenario_replay.py prepare --run-id presentation-01
```

`init-env` creates a private, gitignored `.env.scenario` with fresh DB passwords, the AES key, operator key, and agent-bound tokens. The local mirror leaves operator reads open so the existing browser SSE stream can connect, while agent ingestion remains token-authenticated. Its published ports are loopback-only. `verify` runs sampled source frames through the existing live heuristic risk pipeline offline and prints actual scores. `prepare` date-shifts source-shaped background collector rows, writes 22 consecutive synthetic daily40 vectors ending yesterday, invokes `model/predict.py` unchanged, and stores its computed outputs in the mirror. Keep the printed run ID.

For a 60-day historical presentation on Linux, place all three dataset folders beneath one parent directory and use the last 60 completed UTC days:

```bash
cd /srv/InsiEDR_Server
if [ ! -f .env.scenario ]; then .venv/bin/python scripts/scenario_replay.py init-env; fi
docker compose --env-file .env.scenario -f docker-compose.scenario.yml up -d --build
.venv/bin/python scripts/check_model_v3_prerequisites.py
.venv/bin/python scripts/scenario_replay.py verify --dataset-root /srv/insiedr-datasets
.venv/bin/python scripts/scenario_replay.py prepare --dataset-root /srv/insiedr-datasets \
  --days 60 --run-id sixty-day-presentation
```

This produces 60 daily vectors for each of seven scenario hosts and two control hosts. Three background observations per available collector per day are written to the isolated ClickHouse database. Dataset scenario collector frames recur at roughly ten-day intervals and on the final three dates; exact dates are in the run manifest. Historical risk events are calculated by the existing heuristic risk pipeline from those frames; risk numbers are never chosen by the replay runner. The isolated PostgreSQL database registers the dataset host identities, and the Review Queue displays the frozen model's 60 daily outputs. In the SOC dashboard, choose **UTC dates** and enter the `start_date` and `end_date` printed in `data/scenario_replay/sixty-day-presentation/run.json` to view the full log histogram. The Review Queue host trajectory shows each date and score.

The seven scenario machines appear as `EMPLOYEE-01` through `EMPLOYEE-07`. Their dataset agent IDs remain `AGENT-SOCL2-64`, `AGENT-DSL-174`, `AGENT-DATASL-173`, `AGENT-MCALAB1-07`, `AGENT-SOCL8-53`, `AGENT-SOCL8-03`, and `AGENT-SOCL4-61`. Original hostnames and timestamps remain in collector provenance. Risk correlation uses agent ID or hostname; a shared username cannot transfer a critical score to another machine.

The date range must end before the current UTC date. As of 22 October 2026, the 60-day completed window is 23 August through 21 October 2026. The precise dates are computed when `prepare` runs. The originally requested 30 October endpoint is in the future as of 22 October and is not admitted as a completed observation.

Check `data/scenario_replay/sixty-day-presentation/model/summary.json`, `daily_predictions.csv`, `host_rankings.csv`, and `review_queue.csv`. Queue membership is selected by the frozen policy. A host below threshold still has a 60-day trajectory and its computed scores. No model result is inserted into the live risk cache or used to alter alert severity.

The retired `scripts/demo_simulate_model_v3.py` direct and pipeline modes are blocked because they wrote preset scores or attested generated features as observed. If a Docker run reports `No module named 'heuristics'`, rebuild the backend image from this repository and check `docker compose --env-file .env.scenario -f docker-compose.scenario.yml exec backend python -c 'import heuristics.detector'`. The Dockerfile copies `heuristics/` into `/app`; an import failure after rebuilding means the running image or Compose project differs from this checkout. Do not treat Redis cache invalidation failure as proof that Model V3 ran.

The model input contains generated defaults and scenario intensity floors. These are generated features, never observed sensor readings; the floor can override a lower CSV value. Every applied floor and a raw-versus-harmonized collector schema audit are recorded in the run manifest. Historical search rows retain the original source timestamp in `agent_quality_json` and the shifted timestamp in the collector row.

## Present

Open `http://127.0.0.1:5088` and select Model V3 Review Queue. In another terminal:

```powershell
.venv\Scripts\python.exe scripts\scenario_replay.py play --run-id presentation-01
```

The scenario site is bound to Linux localhost port `5088`. From a separate terminal on your laptop, use `ssh -L 5088:127.0.0.1:5088 USER@SERVER` and open `http://127.0.0.1:5088`. On the Linux server for the 60-day run:

```bash
.venv/bin/python scripts/scenario_replay.py play --dataset-root /srv/insiedr-datasets \
  --run-id sixty-day-presentation
```

The runner sends encrypted, authenticated envelopes through `/api/logs`; the normal replay-window security check stays enabled. It shifts the envelope timestamps to now and preserves each original timestamp in collector quality metadata. The website displays collector logs, current and peak live heuristic risk, completed-day Model V3 scores and hypothesis, and the actual frozen-threshold Review Queue. The four-stage kill chain uses 24 frames in source time order. Default pacing is five seconds between frames: about one minute per ordinary scenario and two minutes for the kill chain. Use `--scenario SIM_CREDENTIAL_DUMP` to present one host.

Run `play` with the host Python environment as shown above, not `docker-compose run backend python scripts/scenario_replay.py play`. The backend image contains the web service but does not mount the dataset folders, model environment, or prepared run artifacts. The replay CLI loads the Model V3 schema only for `preview` and `prepare`, so playback itself does not need the model bundle. A `FileNotFoundError` for `/app/model/run/schema.json` from a containerized `play` command indicates an older replay script/image; it does not indicate that existing database rows were removed.

```powershell
.venv\Scripts\python.exe scripts\scenario_replay.py status --run-id presentation-01
.venv\Scripts\python.exe scripts\scenario_replay.py stop --run-id presentation-01
```

`stop` is checked before the next envelope. A stopped run can be resumed with `play`, which starts the selected source window from the beginning with new payload IDs.

## Reset and limits

```powershell
.venv\Scripts\python.exe scripts\scenario_replay.py reset --run-id presentation-01
```

`reset` tears down **only** the `insiedr-scenario` Compose project and its dedicated PostgreSQL, ClickHouse, and Redis volumes. It retains local run artifacts for audit. Recreate the mirror and use a new run ID for another session.

The scenario source is a laboratory dataset, not newly captured customer endpoint telemetry. Customer-facing descriptions must identify it as a controlled replay if provenance is discussed. Current source rows naturally produce different live severities: USB and cloud precursor activity can be low risk without transfer or upload evidence, and the sabotage deletion rule can also receive a lower aggregate score. Model V3 may select fewer than seven hosts or assign a different hypothesis. Two additional dataset-backed controls check missing-day abstention and benign behavior; they are absent from the seven-host presentation selector but remain available by agent ID in trajectory lookup. Do not alter risk scores, the model threshold, or source evidence to force an outcome.
