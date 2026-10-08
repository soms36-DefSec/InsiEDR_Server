"""Opt-in analytics pages for the legacy ClickHouse schema.

Deduplicate replayed rows before LIMIT/count. This compatibility path still
needs a raw-payload join for username; see the audit's denormalized v2 design.
"""
import json

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
    params, clauses = {}, []

    def contains(column, value):
        name = f'p{len(params)}'
        params[name] = value
        return f'positionCaseInsensitiveUTF8({column}, %({name})s) > 0'

    if collector:
        clean = collector.strip().lower()
        base = clean
        for suffix in ('-monitor', '_monitor', '-collector', '_collector', '-watcher', '_watcher'):
            base = base.replace(suffix, '')
        aliases = {'device': ['device', 'usb'], 'usb': ['usb', 'device'], 'http': ['http', 'browser']}
        known = {'network', 'process', 'file', 'logon', 'keystroke', 'clipboard', 'dns',
                 'driver', 'lsass', 'persistence', 'registry', 'usn', 'wmi', 'decoy', 'memory'}
        terms = aliases.get(base, [base] if base in known else [clean, clean.replace('_', '-'), clean.replace('-', '_')])
        clauses.append('(' + ' OR '.join(contains('cr.collector', term) for term in terms) + ')')
    if username:
        clauses.append(contains('rp.username', username))
    if status:
        params['statuses'] = ['error', 'failed', 'critical', 'tampered'] if status == 'error' else [status]
        clauses.append('lower(cr.status) IN %(statuses)s')
    if search:
        columns = ['cr.hostname', 'rp.username', 'cr.collector']
        if search_scope == 'payload':
            columns.append('cr.payload_json')
        clauses.append('(' + ' OR '.join(contains(column, search) for column in columns) + ')')
    for name, value, operator in [('start', start_time, '>='), ('end', end_time, '<=')]:
        if value:
            params[name] = str(value)
            clauses.append(f"cr.collector_collected_at {operator} parseDateTime64BestEffort(%({name})s, 3, 'UTC')")
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    # The legacy writer emits deterministic IDs but MergeTree does not enforce
    # uniqueness. DISTINCT also prevents replay from changing page boundaries.
    source = ''' FROM (SELECT DISTINCT id, payload_id, agent_id, collector,
        collector_collected_at, hostname, status, payload_json FROM collector_results) cr
        LEFT JOIN (SELECT payload_id, argMin(username, received_at) AS username,
        min(received_at) AS received_at FROM raw_payloads GROUP BY payload_id) rp
        ON cr.payload_id = rp.payload_id'''
    count_where = where
    if cursor:
        timestamp, row_id = decode_cursor(cursor, 'clickhouse', key)
        if timestamp is None:
            raise ValueError('ClickHouse cursors require a timestamp')
        params.update(cursor_time=timestamp, cursor_id=row_id)
        clauses.append("(cr.collector_collected_at, cr.id) < (parseDateTime64BestEffort(%(cursor_time)s, 3, 'UTC'), toUUID(%(cursor_id)s))")
        where = ' WHERE ' + ' AND '.join(clauses)
    params.update(limit=limit + 1, offset=offset)
    result = storage._query('''SELECT cr.id, cr.payload_id, cr.agent_id, cr.collector,
        cr.collector_collected_at AS collected_at, cr.hostname, rp.username,
        cr.status, cr.payload_json AS payload, rp.received_at''' + source + where +
        ' ORDER BY cr.collector_collected_at DESC, cr.id DESC LIMIT %(limit)s OFFSET %(offset)s', params)
    logs = [dict(zip(result.column_names, row)) for row in result.result_rows]
    has_more = len(logs) > limit
    logs = logs[:limit]
    next_cursor = encode_cursor('clickhouse', key, logs[-1]['collected_at'], logs[-1]['id']) if has_more else None
    for row in logs:
        row['id'] = str(row['id'])
        if isinstance(row['payload'], str):
            try:
                row['payload'] = json.loads(row['payload'])
            except ValueError:
                pass
    total = None
    if include_total:
        total = storage._query('SELECT count()' + source + count_where, params).result_rows[0][0]
    if include_enrichment and logs:
        ids = list(dict.fromkeys(row['payload_id'] for row in logs))
        result = storage._query('''SELECT payload_id,
            argMax(tuple(risk_level, summary, correlated_signals_json, risk_score), (created_at, id))
            FROM risk_events WHERE payload_id IN %(ids)s GROUP BY payload_id''', {'ids': ids})
        fields = ('risk_level', 'summary', 'correlated_signals_json', 'risk_score')
        risks = {row[0]: dict(zip(fields, row[1])) for row in result.result_rows}
        empty_ids = list(dict.fromkeys(row['payload_id'] for row in logs if not row['payload']))
        features = {}
        if empty_ids:
            result = storage._query('''SELECT payload_id, feature_name,
                argMax(coalesce(feature_value_text, toString(feature_value_numeric)), (created_at, id))
                FROM normalized_features WHERE payload_id IN %(ids)s GROUP BY payload_id, feature_name''', {'ids': empty_ids})
            for payload_id, name, value in result.result_rows:
                features.setdefault(payload_id, {})[name] = value
        for row in logs:
            row.update(risks.get(row['payload_id'], dict.fromkeys(fields)))
            if not row['payload']:
                row['payload'] = features.get(row['payload_id'], {})
    return {'logs': logs, 'total': total, 'offset': offset, 'limit': limit,
            'has_more': has_more, 'next_cursor': next_cursor, 'source': 'clickhouse'}
