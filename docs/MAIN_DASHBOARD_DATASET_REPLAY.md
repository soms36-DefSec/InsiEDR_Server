# Dataset replay into the normal InsiEDR dashboard

This procedure keeps `http://172.16.22.198/dashboard/` on the **main** backend and
adds seven distinct `SOC_Lab-32`, `SOC_Lab-47`, `SOC_Lab-58`, `SOC_Lab-63`,
`SOC_Lab-71`, `SOC_Lab-84`, and `SOC_Lab-96` attack hosts. Their
authenticated IDs are `AGENT-EMPLOYEE-01` through `AGENT-EMPLOYEE-07`; the seven
original dataset agent IDs are retained in provenance. Existing fleet rows and
volumes remain in place. Historical Model V3 scores come from
the unchanged frozen model's computed output, stored in `scenario_replay` tables
inside the main PostgreSQL database. Historical collector logs are written to
the main ClickHouse tables with synthetic source and original timestamp
provenance. Current attack frames go through the main `/api/logs` ingestion route
and the normal heuristic risk pipeline. The Model V3 scores stay in shadow mode.

The main database must be healthy before starting. Do not run `down -v`, reset,
or the older `demo_simulate_model_v3.py` direct mode; that script hardcodes
scores. No main database rows are deleted by the commands below.

## Prepare the checkout

Install the changed code in `~/InsiEDR_Server`. Ensure these local assets are
available under the same paths on the Linux host:

- `data/scenario_replay/portable_sources/` (three dataset folders)
- `data/scenario_replay/main-preview-20261022/` (the frozen model output for
  the dedicated `AGENT-EMPLOYEE-*` identities)

The local checkout includes `data/main-preview-model-20261022.zip` for that
small model-output folder. After copying it to the Linux host, unpack from
`~/InsiEDR_Server/data/scenario_replay/` so the folder path above exists.

The model output is for 60 completed UTC days ending **2026-10-21**. The replay
checks the SHA256 of its newly generated `X.csv` and `metadata.csv` against
that output before writing. If either differs, preparation stops; regenerate
the output with the frozen Python 3.12 model for the new inputs.

From `~/InsiEDR_Server`, check the main services:

```bash
docker-compose -f docker-compose.yml ps db backend
docker-compose -f docker-compose.yml exec -T db sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

Install seven additional agent-bound tokens while preserving existing agent
credentials. The command saves a private backup of `.env`, then updates only
the main replay opt-in and agent-token entries:

```bash
docker-compose -f docker-compose.yml run --rm --no-deps \
  --user "$(id -u):$(id -g)" -v "$PWD:/app" backend \
  python scripts/scenario_replay.py install-main-tokens --target main
```

Restart the main backend to load the new credentials and read-only Model V3
presentation API. Restore the normal main URL if presentation routing was
previously enabled:

```bash
docker-compose -f docker-compose.yml up -d --build backend
docker-compose -f docker-compose.yml up -d --no-deps --force-recreate nginx
curl -fsS http://127.0.0.1/api/health/ready
```

## Write the computed history into the main databases

Choose a fresh run ID. The following command backfills bounded historical
collector observations, writes computed historical heuristic events, and
stores the frozen model's actual scores. It does not alter the model weights,
threshold, production coverage attestations, or live alert severity.

```bash
docker-compose -f docker-compose.yml run --rm --no-deps \
  --user "$(id -u):$(id -g)" -v "$PWD:/app" backend \
  python scripts/scenario_replay.py prepare --target main \
  --run-id main-fleet-20261022 --days 60 --as-of 2026-10-21 \
  --dataset-root /app/data/scenario_replay/portable_sources \
  --precomputed-model /app/data/scenario_replay/main-preview-20261022/model
```

The main `/dashboard/` fleet remains the normal fleet; the seven dedicated
attack identities may increase its endpoint count by seven. The two benign
model controls are kept out of the main fleet table. Review Queue selection is
the frozen model's result, so
fewer than seven attack hosts may be selected.

## Play current attacks through normal ingestion

Open the normal `/dashboard/` and Telemetry Explorer, then run:

```bash
docker-compose -f docker-compose.yml run --rm --no-deps \
  --user "$(id -u):$(id -g)" -v "$PWD:/app" backend \
  python scripts/scenario_replay.py play --target main \
  --run-id main-fleet-20261022 \
  --dataset-root /app/data/scenario_replay/portable_sources --interval 5
```

The command checks each host for an accepted authenticated envelope, a
searchable collector event, and a live risk score calculated by the main
pipeline. Its source quality retains `source_kind=synthetic`, source dataset,
original timestamp, and replay run ID. The frontend presents normal host and
collector terminology; operator provenance remains available. Do not describe
the replay as newly captured customer endpoint telemetry.
