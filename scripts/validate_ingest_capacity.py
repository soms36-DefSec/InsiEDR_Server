"""Send encrypted synthetic telemetry to an explicitly selected TEST deployment.

Does not delete data, restart services, or infer production credentials. Use a
separate database and the same resource limits/storage class as the target host.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import json
import os
import random
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server.crypto.aesgcm_plugin import AES_GCM_AAD
from shared.protocol import encrypted_payload_headers


def build_envelope(agent_id, template, key):
    now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    payload = copy.deepcopy(template)
    payload.update(schema='insiedr.agent.telemetry.v1', protocol_version='2.0',
                   payload_id=str(uuid.uuid4()), agent_id=agent_id, hostname=agent_id,
                   collected_at=now, username='loadtest')
    for collector in payload['collectors']:
        collector.update(collected_at=now, hostname=agent_id)
    nonce = os.urandom(12)
    cipher = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), AES_GCM_AAD)
    envelope = {'protocol_version': '2.0', 'scheme': 'aes-256-gcm',
                'payload_id': payload['payload_id'], 'key_id': 'loadtest',
                'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(cipher).decode(), 'created_at': now}
    return envelope, encrypted_payload_headers(envelope, agent_id, payload['payload_id'])


async def run(args):
    key = base64.b64decode(os.environ['INSIEDR_LOADTEST_AES_KEY'], validate=True)
    if len(key) != 32:
        raise ValueError('INSIEDR_LOADTEST_AES_KEY must encode exactly 32 bytes')
    token = os.environ['INSIEDR_LOADTEST_AGENT_TOKEN']
    template = json.loads(Path(args.template).read_text()) if args.template else {
        'collectors': [{'collector': name, 'status': 'success', 'payload': {'count': 1}}
                       for name in ('process', 'network', 'dns', 'file', 'usb', 'logon',
                                    'registry', 'driver', 'lsass', 'wmi', 'usn', 'memory',
                                    'clipboard', 'http', 'persistence', 'decoy')]}
    if not isinstance(template.get('collectors'), list) or not template['collectors']:
        raise ValueError('Template must contain collector observations')
    counts, latency = Counter(), []
    deadline = time.monotonic() + args.duration
    prefix = 'loadtest-' + uuid.uuid4().hex[:8]
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    admission = asyncio.Semaphore(args.concurrency)

    async with httpx.AsyncClient(timeout=30, limits=limits) as client:
        async def agent(index):
            if not args.burst:
                await asyncio.sleep(random.uniform(0, min(args.interval, args.duration)))
            while time.monotonic() < deadline:
                envelope, headers = build_envelope(f'{prefix}-{index}', template, key)
                headers['Authorization'] = f'Bearer {token}'
                # Retries send identical bytes and identity, matching agent replay.
                for attempt in range(6):
                    started = time.monotonic()
                    try:
                        async with admission:
                            response = await client.post(args.url, json=envelope, headers=headers)
                        counts[str(response.status_code)] += 1
                        if response.status_code in (200, 202):
                            body = response.json()
                            if body.get('payload_id') == envelope['payload_id'] and body.get('ok'):
                                counts['acknowledged'] += 1
                            else:
                                counts['invalid_ack'] += 1
                            break
                        if response.status_code not in (429, 500, 502, 503, 504):
                            counts['rejected'] += 1
                            break
                    except (httpx.HTTPError, ValueError):
                        counts['request_error'] += 1
                    finally:
                        latency.append((time.monotonic() - started) * 1000)
                    if attempt == 5 or time.monotonic() >= deadline:
                        counts['unacknowledged'] += 1
                        break
                    await asyncio.sleep(min(10, 2 ** attempt) * random.uniform(.8, 1.2))
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    await asyncio.sleep(min(args.interval, remaining))
        started = time.monotonic()
        await asyncio.gather(*(agent(i) for i in range(args.agents)))
    elapsed = time.monotonic() - started
    latency.sort()
    def percentile(fraction):
        return round(latency[min(len(latency) - 1, int(len(latency) * fraction))], 2) if latency else None
    report = {'agent_prefix': prefix, 'agents': args.agents, 'elapsed_seconds': round(elapsed, 2),
              'attempts': len(latency), 'counts': dict(counts),
              'acknowledged_per_second': round(counts['acknowledged'] / elapsed, 2),
              'attempt_latency_ms': {'p50': percentile(.5), 'p95': percentile(.95), 'p99': percentile(.99)},
              'note': 'Synthetic client results; verify outbox drain, disk growth and database row counts separately.'}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 1 if any(counts[k] for k in ('unacknowledged', 'invalid_ack', 'rejected')) else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='Explicit test /api/logs URL')
    parser.add_argument('--agents', type=int, default=200)
    parser.add_argument('--duration', type=float, default=300)
    parser.add_argument('--interval', type=float, default=10)
    parser.add_argument('--concurrency', type=int, default=32)
    parser.add_argument('--burst', action='store_true', help='Start all agents together')
    parser.add_argument('--template', help='Sanitized representative telemetry JSON')
    parser.add_argument('--output', default='capacity-results.json')
    args = parser.parse_args()
    if min(args.agents, args.duration, args.interval, args.concurrency) <= 0:
        parser.error('Load parameters must be positive')
    sys.exit(asyncio.run(run(args)))
