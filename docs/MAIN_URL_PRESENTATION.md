# Serve the isolated scenario website at the main dashboard URL

This switch makes `http://172.16.22.198/dashboard/` display the scenario backend that normally appears on port 5088. The normal PostgreSQL, ClickHouse and Redis volumes remain separate. Normal endpoint telemetry posted to `/api/logs` or `/api/v1/logs`, and endpoint control calls under `/api/agent/`, continue to reach the normal backend. The main browser UI, its API reads and SSE stream show the isolated scenario stack until the switch is removed.

The scenario data is controlled replay data. The seven attack hosts are `EMPLOYEE-01` through `EMPLOYEE-07`, with their original dataset agent IDs retained. Additional `EMPLOYEE-*` hosts are benign historical fleet context; they have no fabricated Model V3 scores or risk events. The original source agent and replay run ID remain in ClickHouse provenance.

## Deploy from `~/InsiEDR_Server`

Transfer the changed code files to this checkout first. A ready archive is at `data/presentation-code-20261022.zip` in the local Windows checkout. For example, copy it with `scp` and unpack it at the Linux repository root:

```bash
cd ~/InsiEDR_Server
unzip -o presentation-code-20261022.zip
```

Keep the existing `.env` and `.env.scenario` files and Docker volumes. Do not run `down -v`.

```bash
cd ~/InsiEDR_Server
docker compose -f docker-compose.yml up -d --build
docker compose --env-file .env.scenario \
  -f docker-compose.scenario.yml \
  -f docker-compose.scenario.presentation.yml up -d --build
```

The scenario backend must be healthy before switching the main URL:

```bash
curl -fsS http://127.0.0.1:5088/api/health/ready
```

To populate a 200-machine employee fleet around the already prepared seven scenarios, run once for the existing run ID:

```bash
docker run --rm --user "$(id -u):$(id -g)" --network host \
  --env-file .env.scenario -v "$PWD:/app" -w /app \
  insiedr-scenario-backend python scripts/scenario_replay.py expand-fleet \
  --run-id employee-60day-ready-20261022 --fleet-size 200
```

The command can be rerun without duplicating complete fleet rows. It copies the prepared benign control host's dated source-shaped collector observations to `EMPLOYEE-08` through `EMPLOYEE-200` in the **isolated** ClickHouse database, records lineage, registers those hosts in the isolated PostgreSQL database, and adds per-host agent tokens to the private `.env.scenario`. Only the original nine hosts have Model V3 daily output; the extra 193 remain unscored and Low risk. This step can take time because it writes a 60-day history for each added host.

Reload the scenario backend's new agent tokens, then restart its private gateway so it resolves the new container address:

```bash
docker compose --env-file .env.scenario \
  -f docker-compose.scenario.yml -f docker-compose.scenario.presentation.yml \
  up -d --no-deps --force-recreate backend
docker compose --env-file .env.scenario \
  -f docker-compose.scenario.yml -f docker-compose.scenario.presentation.yml \
  up -d --no-deps --force-recreate presentation-gateway
curl -fsS http://127.0.0.1:5088/api/health/ready
```

Switch the main URL after the scenario site is healthy:

```bash
docker compose -f docker-compose.yml -f docker-compose.presentation.yml up -d --no-deps --force-recreate nginx
curl -fsS http://127.0.0.1/dashboard/ >/dev/null
```

Open `http://172.16.22.198/dashboard/`. Select **Telemetry Explorer** for current collector events and **Model V3 Review Queue** for the frozen model's completed-day trajectories. The log API now emits explicit UTC offsets, so a browser in India shows the same current local time as the histogram. The explorer's Refresh action returns to the newest page. If the API is unavailable, the page shows a refresh error instead of replacing real rows with an empty successful response.

To give all added employee hosts a current, benign collector observation through authenticated ingestion, run this bounded background pass. It sends five dataset-shaped collectors per host and does not create risk events or model scores directly:

```bash
docker run --rm --user "$(id -u):$(id -g)" --network host \
  --env-file .env.scenario -v "$PWD:/app" -w /app \
  insiedr-scenario-backend python scripts/scenario_replay.py play-fleet \
  --dataset-root data/scenario_replay/portable_sources \
  --run-id employee-60day-ready-20261022 --interval 0.1
```

Start all seven attack scenarios from another terminal. This submits encrypted, agent-token-authenticated envelopes through the scenario backend's normal `/api/logs` ingestion route; it does not insert alert scores directly:

```bash
cd ~/InsiEDR_Server
docker run --rm --user "$(id -u):$(id -g)" --network host \
  --env-file .env.scenario -v "$PWD:/app" -w /app \
  insiedr-scenario-backend python scripts/scenario_replay.py play \
  --dataset-root data/scenario_replay/portable_sources \
  --run-id employee-60day-ready-20261022 --interval 5
```

The portable dataset folder and prepared run folder must already exist under `data/scenario_replay/`, as created by the prior preparation. Use a different run ID if your prepared run has a different name. `play` confirms a searchable collector event and a calculated live risk event for each of the seven hosts. The frozen Model V3 score stays in shadow mode and may rank fewer than seven hosts.

## Return the main URL to the normal fleet

```bash
cd ~/InsiEDR_Server
docker compose -f docker-compose.yml up -d --no-deps --force-recreate nginx
```

This changes only Nginx routing. The scenario stack and its dedicated volumes remain available on port 5088. Do not describe controlled replay events as newly captured from customer endpoints.
