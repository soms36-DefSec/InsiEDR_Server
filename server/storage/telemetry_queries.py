"""Bounded dashboard queries; filter the database before paginating results."""
import json
from contextlib import closing


def telemetry_page(storage, limit=100, offset=0, collector=None, username=None,
                   status=None, search=None, start_time=None, end_time=None,
                   include_enrichment=True):
    clauses, params = [], []

    def contains(column, value):
        # Keywords are literal strings, not user-controlled LIKE patterns.
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params.append(f"%{escaped}%")
        return f"LOWER({column}) LIKE LOWER(%s) ESCAPE '\\'"

    if collector:
        terms = {"device": ["device", "usb"], "http": ["http", "network", "browser"]}.get(collector, [collector])
        clauses.append("(" + " OR ".join(contains("cr.collector", term) for term in terms) + ")")
    if username:
        clauses.append(contains("rp.username", username))
    if status:
        statuses = ["error", "failed", "critical", "tampered"] if status == "error" else [status]
        clauses.append("LOWER(cr.status) IN (" + ",".join("%s" for _ in statuses) + ")")
        params.extend(statuses)
    if search:
        clauses.append("(" + " OR ".join(contains(column, search) for column in (
            "cr.hostname", "rp.username", "cr.collector", "CAST(cr.payload_json AS TEXT)",
        )) + ")")
    for bound, operator in ((start_time, ">="), (end_time, "<=")):
        if bound:
            clauses.append(f"(cr.collector_collected_at {operator} %s OR (cr.collector_collected_at IS NULL AND rp.received_at {operator} %s))")
            params.extend([bound, bound])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    source = "FROM collector_results cr LEFT JOIN raw_payloads rp ON cr.payload_id = rp.payload_id"
    with storage.connection() as conn, closing(conn.cursor()) as cur:
        cur.execute(
            "SELECT cr.id, cr.payload_id, cr.agent_id, cr.collector, "
            "COALESCE(cr.collector_collected_at, rp.received_at) AS collected_at, "
            "cr.hostname, rp.username, cr.status, cr.payload_json AS payload, rp.received_at "
            + source + where
            + " ORDER BY cr.collector_collected_at DESC NULLS LAST, cr.id DESC LIMIT %s OFFSET %s",
            tuple(params + [limit, offset]),
        )
        columns = [column[0] for column in cur.description]
        logs = [dict(zip(columns, row)) for row in cur.fetchall()]
        for row in logs:
            if isinstance(row["payload"], str):
                try:
                    row["payload"] = json.loads(row["payload"])
                except ValueError:
                    pass
        # Unfiltered counts don't need to visit payload JSON, risk events, or
        # normalized features. Enrichment must not multiply/paginate raw rows.
        count_source = source if username or search else "FROM collector_results cr"
        if start_time or end_time:
            count_source = source
        cur.execute("SELECT COUNT(*) " + count_source + where, tuple(params))
        total = cur.fetchone()[0]
        if include_enrichment and logs:
            # Preserve the legacy API's enrichment fields, but fetch only this
            # page and choose one latest risk event so joins cannot duplicate rows.
            ids = list(dict.fromkeys(row["payload_id"] for row in logs))
            placeholders = ",".join("%s" for _ in ids)
            cur.execute(
                "SELECT payload_id, risk_level, summary, correlated_signals_json, risk_score FROM ("
                "SELECT payload_id, risk_level, summary, correlated_signals_json, risk_score, "
                "ROW_NUMBER() OVER (PARTITION BY payload_id ORDER BY created_at DESC, id DESC) AS position "
                f"FROM risk_events WHERE payload_id IN ({placeholders})) ranked WHERE position = 1",
                tuple(ids),
            )
            risk = {row[0]: dict(zip(("risk_level", "summary", "correlated_signals_json", "risk_score"), row[1:]))
                    for row in cur.fetchall()}
            empty_ids = list(dict.fromkeys(row["payload_id"] for row in logs if not row["payload"]))
            features = {}
            if empty_ids:
                cur.execute(
                    "SELECT payload_id, feature_name, COALESCE(feature_value_text, CAST(feature_value_numeric AS TEXT)) "
                    "FROM normalized_features WHERE payload_id IN (" + ",".join("%s" for _ in empty_ids) + ")",
                    tuple(empty_ids),
                )
                for payload_id, name, value in cur.fetchall():
                    features.setdefault(payload_id, {})[name] = value
            for row in logs:
                row.update(risk.get(row["payload_id"], dict.fromkeys(
                    ("risk_level", "summary", "correlated_signals_json", "risk_score"))))
                if not row["payload"]:
                    row["payload"] = features.get(row["payload_id"], {})
    return {"logs": logs, "total": total, "offset": offset, "limit": limit}
