"""Bounded dashboard queries; filter the database before paginating results."""
import json
from contextlib import closing
from server.storage.telemetry_cursor import filter_key, encode_cursor, decode_cursor


def telemetry_page(storage, limit=100, offset=0, collector=None, username=None,
                   status=None, search=None, start_time=None, end_time=None,
                   include_enrichment=True, cursor=None, include_total=True,
                   search_scope='payload'):
    if search_scope not in ('metadata', 'payload'):
        raise ValueError('Invalid search scope')
    if cursor and offset:
        raise ValueError('cursor and offset cannot be combined')
    key = filter_key(collector=collector, username=username, status=status, search=search,
                     start_time=start_time, end_time=end_time, search_scope=search_scope)
    clauses, params = [], []

    def contains(column, value):
        # Keywords are literal strings, not user-controlled LIKE patterns.
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params.append(f"%{escaped}%")
        return f"LOWER({column}) LIKE LOWER(%s) ESCAPE '\\'"

    if collector:
        collector_clean = collector.strip().lower()
        alias_map = {
            "device": ["device", "usb"],
            "usb": ["usb", "device"],
            "http": ["http", "browser"],
            "network": ["network"],
            "process": ["process"],
            "file": ["file"],
            "logon": ["logon"],
            "keystroke": ["keystroke"],
            "clipboard": ["clipboard"],
            "dns": ["dns"],
            "driver": ["driver"],
            "lsass": ["lsass"],
            "persistence": ["persistence"],
            "registry": ["registry"],
            "usn": ["usn"],
            "wmi": ["wmi"],
            "decoy": ["decoy"],
            "memory": ["memory"],
        }
        base_key = collector_clean.replace("-monitor", "").replace("_monitor", "").replace("-collector", "").replace("_collector", "").replace("-watcher", "").replace("_watcher", "")
        terms = alias_map.get(collector_clean, alias_map.get(base_key, [
            collector_clean,
            collector_clean.replace("_", "-"),
            collector_clean.replace("-", "_")
        ]))
        clauses.append("(" + " OR ".join(contains("cr.collector", term) for term in terms) + ")")
    if username:
        clauses.append(contains("rp.username", username))
    if status:
        statuses = ["error", "failed", "critical", "tampered"] if status == "error" else [status]
        clauses.append("LOWER(cr.status) IN (" + ",".join("%s" for _ in statuses) + ")")
        params.extend(statuses)
    if search:
        search_columns = ['cr.hostname', 'rp.username', 'cr.collector']
        if search_scope == 'payload':
            search_columns.append('CAST(cr.payload_json AS TEXT)')
        clauses.append("(" + " OR ".join(contains(column, search) for column in search_columns) + ")")
    for bound, operator in ((start_time, ">="), (end_time, "<=")):
        if bound:
            clauses.append(f"(cr.collector_collected_at {operator} %s OR (cr.collector_collected_at IS NULL AND rp.received_at {operator} %s))")
            params.extend([bound, bound])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    count_where, count_params = where, list(params)
    if cursor:
        timestamp, row_id = decode_cursor(cursor, 'postgres', key)
        if timestamp is None:
            clauses.append('(cr.collector_collected_at IS NULL AND cr.id < %s)')
            params.append(row_id)
        else:
            clauses.append('((cr.collector_collected_at, cr.id) < (%s, %s) OR cr.collector_collected_at IS NULL)')
            params.extend([timestamp, row_id])
        where = ' WHERE ' + ' AND '.join(clauses)
    source = "FROM collector_results cr LEFT JOIN raw_payloads rp ON cr.payload_id = rp.payload_id"
    with storage.connection() as conn, closing(conn.cursor()) as cur:
        cur.execute(
            "SELECT cr.id, cr.payload_id, cr.agent_id, cr.collector, "
            "COALESCE(cr.collector_collected_at, rp.received_at) AS collected_at, "
            "cr.hostname, rp.username, cr.status, cr.payload_json AS payload, rp.received_at, "
            "cr.collector_collected_at AS cursor_time "
            + source + where
            + " ORDER BY cr.collector_collected_at DESC NULLS LAST, cr.id DESC LIMIT %s OFFSET %s",
            tuple(params + [limit + 1, offset]),
        )
        columns = [column[0] for column in cur.description]
        logs = [dict(zip(columns, row)) for row in cur.fetchall()]
        has_more = len(logs) > limit
        logs = logs[:limit]
        next_cursor = encode_cursor('postgres', key, logs[-1]['cursor_time'], logs[-1]['id']) if has_more else None
        for row in logs:
            row.pop('cursor_time')
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
        total = None
        if include_total:
            cur.execute("SELECT COUNT(*) " + count_source + count_where, tuple(count_params))
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
    return {"logs": logs, "total": total, "offset": offset, "limit": limit,
            "has_more": has_more, "next_cursor": next_cursor, 'source': 'postgres'}
