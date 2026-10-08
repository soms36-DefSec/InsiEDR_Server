"""Opaque, filter-bound positions, not authorization or snapshot tokens."""
import base64
import hashlib
import json
from datetime import datetime
from uuid import UUID


def filter_key(**filters):
    return hashlib.sha256(json.dumps(filters, sort_keys=True, default=str).encode()).hexdigest()[:24]


def encode_cursor(source, key, timestamp, row_id):
    value = [1, source, key, timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp, str(row_id)]
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode()


def decode_cursor(token, source, key):
    try:
        if len(token) > 1024:
            raise ValueError()
        version, backend, fingerprint, timestamp, row_id = json.loads(base64.b64decode(token, altchars=b'-_', validate=True))
        if version != 1 or backend != source or fingerprint != key:
            raise ValueError()
        if timestamp is not None:
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        if source == 'postgres':
            row_id = int(row_id)
            if not 0 <= row_id <= 9223372036854775807:
                raise ValueError()
        else:
            row_id = str(UUID(row_id))
        return timestamp, row_id
    except (ValueError, TypeError, AttributeError, OverflowError) as exc:
        raise ValueError('Invalid telemetry cursor; restart from the first page') from exc
