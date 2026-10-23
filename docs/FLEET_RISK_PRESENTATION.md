# Fleet risk presentation and test endpoints

The risk aggregator stores every assessment with its original score. Fleet widgets
show an assessment as **active** for 30 minutes after its event creation time.
Expired assessments remain in history and in the endpoint drawer, labeled
**Historical**. An agent's next assessment supersedes its preceding assessment.

Severity follows the scoring engine: Low below 40, Medium from 40, High from 70,
and Critical from 90. The dashboard summary reads the latest persisted event for
each registered agent. It does not infer one host's risk from a shared username.
The threat stream and domain charts include active events only. The retained
risk-event counter counts stored rows, including historical assessments.

## Explicit test-agent marker

Set `INSIEDR_TEST_AGENT_IDS` to a comma-separated list of exact agent IDs before
sending test telemetry. For example:

```text
INSIEDR_TEST_AGENT_IDS=AGENT-SOCL4-21-SIM,AGENT-SOCL4-23-SIM
```

These agent IDs appear with a `TEST` badge in the fleet table and are hidden
from ordinary fleet counts, charts, streams, and CSV exports. Analysts can select
**Show test endpoints** in the table. New risk events from allowlisted IDs also
store `source_kind=synthetic_test` in their correlated signals for audit. Keep
the allowlist configured until the test records have been reviewed and cleaned
up; removing an ID from the list ends its fleet presentation marker. The marker
does not authorize ingestion or bypass agent authentication. Provision a
credential bound to each test agent ID on an isolated server before sending.

Do not delete DEMO, EMPLOYEE, SANDY, or other named records from their names
alone. First export their agent IDs, payload IDs, event times, and correlated
signals, confirm provenance with the deployment owner, and retain an audit copy.

## Model output

The endpoint drawer labels absent or stale Model V3 output **Not evaluated**.
Daily Model V3 review requires 22 consecutive complete UTC days. A short
synthetic ingestion run verifies the heuristic and dashboard path; it does not
establish the model's predicted class or temporal drift.
