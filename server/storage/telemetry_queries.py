import json
from typing import Any
from datetime import datetime, timezone
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


def telemetry_explorer(storage, limit=50, cursor=None, collector=None, username=None,
                       status=None, search=None, start_time=None, end_time=None,
                       agent_id=None):
    """
    PostgreSQL/SQLite implementation of Split-View Telemetry Explorer.
    Projects ONLY lightweight scalar columns:
    event_id, timestamp, agent_id, collector_name, hostname, username, status, summary_preview.
    Deterministic seek/cursor pagination, response size < 20KB for 50 rows.
    """
    from server.storage.clickhouse_telemetry_queries import extract_summary_preview
    key = filter_key(collector=collector, username=username, status=status, search=search,
                     start_time=start_time, end_time=end_time, agent_id=agent_id, scope='explorer')
    clauses, params = [], []

    def contains(column, value):
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params.append(f"%{escaped}%")
        return f"LOWER({column}) LIKE LOWER(%s) ESCAPE '\\'"

    if agent_id:
        clauses.append("cr.agent_id = %s")
        params.append(str(agent_id))

    if collector:
        collector_clean = collector.strip().lower()
        alias_map = {
            "device": ["device", "usb"], "usb": ["usb", "device"], "http": ["http", "browser"],
            "network": ["network"], "process": ["process"], "file": ["file"], "logon": ["logon"],
            "keystroke": ["keystroke"], "clipboard": ["clipboard"], "dns": ["dns"],
            "driver": ["driver"], "lsass": ["lsass"], "persistence": ["persistence"],
            "registry": ["registry"], "usn": ["usn"], "wmi": ["wmi"], "decoy": ["decoy"], "memory": ["memory"],
        }
        base_key = collector_clean.replace("-monitor", "").replace("_monitor", "").replace("-collector", "").replace("_collector", "").replace("-watcher", "").replace("_watcher", "")
        terms = alias_map.get(collector_clean, alias_map.get(base_key, [collector_clean, collector_clean.replace("_", "-"), collector_clean.replace("-", "_")]))
        clauses.append("(" + " OR ".join(contains("cr.collector", term) for term in terms) + ")")

    if username:
        clauses.append(contains("rp.username", username))

    if status:
        statuses = ["error", "failed", "critical", "tampered"] if status == "error" else [status]
        clauses.append("LOWER(cr.status) IN (" + ",".join("%s" for _ in statuses) + ")")
        params.extend(statuses)

    if search:
        search_cols = ['cr.hostname', 'rp.username', 'cr.collector']
        clauses.append("(" + " OR ".join(contains(col, search) for col in search_cols) + ")")

    for bound, operator in ((start_time, ">="), (end_time, "<=")):
        if bound:
            clauses.append(f"(cr.collector_collected_at {operator} %s OR (cr.collector_collected_at IS NULL AND rp.received_at {operator} %s))")
            params.extend([bound, bound])

    if cursor:
        timestamp, row_id = decode_cursor(cursor, 'postgres', key)
        if timestamp is None:
            clauses.append('(cr.collector_collected_at IS NULL AND cr.id < %s)')
            params.append(row_id)
        else:
            clauses.append('((cr.collector_collected_at, cr.id) < (%s, %s) OR cr.collector_collected_at IS NULL)')
            params.extend([timestamp, row_id])

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    source = "FROM collector_results cr LEFT JOIN raw_payloads rp ON cr.payload_id = rp.payload_id"

    events = []
    with storage.connection() as conn, closing(conn.cursor()) as cur:
        sql = (
            "SELECT cr.id AS event_id, cr.agent_id, cr.collector AS collector_name, "
            "COALESCE(cr.collector_collected_at, rp.received_at) AS collected_at, "
            "cr.hostname, rp.username, cr.status, cr.payload_json AS payload, "
            "cr.collector_collected_at AS cursor_time "
            + source + where
            + " ORDER BY cr.collector_collected_at DESC NULLS LAST, cr.id DESC LIMIT %s"
        )
        cur.execute(sql, tuple(params + [limit + 1]))
        columns = [column[0] for column in cur.description]
        rows = [dict(zip(columns, r)) for r in cur.fetchall()]
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = encode_cursor('postgres', key, rows[-1]['cursor_time'], rows[-1]['event_id']) if has_more and rows else None

        for row in rows:
            eid = str(row['event_id'])
            ts = row.get('collected_at')
            ts_str = ts.isoformat() if hasattr(ts, 'isoformat') else str(ts or '')
            cname = str(row.get('collector_name') or '')
            raw_payload = row.get('payload')
            preview = extract_summary_preview(cname, raw_payload)
            events.append({
                'event_id': eid,
                'id': eid,
                'timestamp': ts_str,
                'collected_at': ts_str,
                'agent_id': str(row.get('agent_id') or ''),
                'collector_name': cname,
                'collector': cname,
                'hostname': str(row.get('hostname') or ''),
                'username': str(row.get('username') or ''),
                'status': str(row.get('status') or 'success'),
                'summary_preview': preview,
            })

    return {
        'events': events,
        'logs': events,
        'next_cursor': next_cursor,
        'has_more': has_more,
        'limit': limit,
        'source': 'postgres',
    }


def telemetry_event_detail(storage, event_id: str) -> dict[str, Any] | None:
    """
    On-Demand Deep Forensic Detail lookup for PostgreSQL / SQLite.
    Fetches raw payload JSON, risk events, and normalized features for a single event ID.
    """
    from server.storage.clickhouse_telemetry_queries import extract_summary_preview
    if not event_id:
        return None

    with storage.connection() as conn, closing(conn.cursor()) as cur:
        cur.execute(
            "SELECT cr.id AS event_id, cr.payload_id, cr.agent_id, cr.collector AS collector_name, "
            "COALESCE(cr.collector_collected_at, rp.received_at) AS timestamp, "
            "cr.hostname, rp.username, cr.status, cr.payload_json "
            "FROM collector_results cr LEFT JOIN raw_payloads rp ON cr.payload_id = rp.payload_id "
            "WHERE CAST(cr.id AS TEXT) = %s LIMIT 1",
            (str(event_id),),
        )
        row = cur.fetchone()
        if not row:
            return None
        columns = [c[0] for c in cur.description]
        d = dict(zip(columns, row))

        raw_json = d.get('payload_json') or '{}'
        payload_obj = {}
        if isinstance(raw_json, str):
            try:
                payload_obj = json.loads(raw_json)
            except Exception:
                payload_obj = {'raw': raw_json}
        elif isinstance(raw_json, dict):
            payload_obj = raw_json

        ts = d.get('timestamp')
        ts_str = ts.isoformat() if hasattr(ts, 'isoformat') else str(ts or '')
        pid = d.get('payload_id')
        cname = str(d.get('collector_name') or '')

        features = {}
        risk = {}
        if pid:
            try:
                cur.execute(
                    "SELECT feature_name, COALESCE(feature_value_text, CAST(feature_value_numeric AS TEXT)) "
                    "FROM normalized_features WHERE payload_id = %s",
                    (pid,),
                )
                for fname, fval in cur.fetchall():
                    features[str(fname)] = fval
            except Exception:
                pass
            try:
                cur.execute(
                    "SELECT risk_level, summary, correlated_signals_json, risk_score "
                    "FROM risk_events WHERE payload_id = %s ORDER BY created_at DESC, id DESC LIMIT 1",
                    (pid,),
                )
                r_row = cur.fetchone()
                if r_row:
                    risk = dict(zip(("risk_level", "summary", "correlated_signals_json", "risk_score"), r_row))
            except Exception:
                pass

        return {
            'event_id': str(d['event_id']),
            'id': str(d['event_id']),
            'payload_id': pid,
            'agent_id': str(d.get('agent_id') or ''),
            'collector_name': cname,
            'collector': cname,
            'timestamp': ts_str,
            'collected_at': ts_str,
            'hostname': str(d.get('hostname') or ''),
            'username': str(d.get('username') or ''),
            'status': str(d.get('status') or 'success'),
            'summary_preview': extract_summary_preview(cname, payload_obj),
            'payload': payload_obj,
            'payload_json': raw_json if isinstance(raw_json, str) else json.dumps(raw_json),
            'features': features,
            'risk': risk,
        }


def telemetry_histogram(storage, time_range='1h', interval=None, collector=None, status=None, agent_id=None):
    """
    Event Frequency Histogram Aggregation for PostgreSQL / SQLite.
    Returns lightweight coordinates array for SVG/Canvas rendering.
    """
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    delta_map = {
        '15m': (timedelta(minutes=15), '1m', 16),
        '1h': (timedelta(hours=1), '1m', 16),
        '24h': (timedelta(hours=24), '15m', 13),
        '7d': (timedelta(days=7), '2h', 13),
        'all': (timedelta(days=30), '1d', 10),
    }
    time_delta, default_int, substr_len = delta_map.get(time_range, delta_map['1h'])
    actual_interval = interval or default_int
    start_time = (now - time_delta).strftime('%Y-%m-%d %H:%M:%S')

    clauses, params = [
        "(COALESCE(cr.collector_collected_at, rp.received_at) >= %s "
        "OR REPLACE(CAST(COALESCE(cr.collector_collected_at, rp.received_at) AS TEXT), ' ', 'T') >= %s)"
    ], [start_time, start_time]
    if collector:
        clauses.append("LOWER(cr.collector) = LOWER(%s)")
        params.append(collector.strip())
    if status:
        clauses.append("LOWER(cr.status) = LOWER(%s)")
        params.append(status.strip())
    if agent_id:
        clauses.append("cr.agent_id = %s")
        params.append(str(agent_id))

    where = " WHERE " + " AND ".join(clauses)
    histogram = []
    total_events = 0

    def _format_sqlite_pg_iso(t_val, slen):
        raw = str(t_val).replace(' ', 'T')
        if slen == 10 and len(raw) == 10:
            return f"{raw}T00:00:00Z"
        if slen == 13 and len(raw) == 13:
            return f"{raw}:00:00Z"
        if len(raw) == 16:
            return f"{raw}:00Z"
        if not raw.endswith('Z') and '+00:00' not in raw:
            return f"{raw}Z"
        return raw

    with storage.connection() as conn, closing(conn.cursor()) as cur:
        try:
            sql = (
                f"SELECT SUBSTR(CAST(COALESCE(cr.collector_collected_at, rp.received_at) AS TEXT), 1, {substr_len}) AS t, count(*) AS c "
                f"FROM collector_results cr LEFT JOIN raw_payloads rp ON cr.payload_id = rp.payload_id "
                f"{where} GROUP BY t ORDER BY t"
            )
            cur.execute(sql, tuple(params))
            for t_val, c_val in cur.fetchall():
                c_num = int(c_val)
                histogram.append({'timestamp': _format_sqlite_pg_iso(t_val, substr_len), 'count': c_num})
                total_events += c_num
        except Exception as exc:
            logger.warning("Telemetry histogram aggregation failed: %s", exc)

    return {
        'ok': True,
        'time_range': time_range,
        'interval': actual_interval,
        'total_events': total_events,
        'histogram': histogram,
    }
