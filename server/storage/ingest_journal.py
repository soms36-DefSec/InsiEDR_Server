"""Encrypted, bounded server acceptance journal with SQLite WAL group commit.

SQLite owns record framing, checksums/atomic recovery and durable identity updates;
we deliberately do not implement a new filesystem journal. One owner per directory.
Success means a FULL synchronous transaction committed, never queue admission.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import sqlite3
import threading
import time
import zlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime,timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      default=str,allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


@dataclass
class Submission:
    operation: str
    args: tuple
    done: threading.Event = field(default_factory=threading.Event)
    result: object = None
    error: Exception | None = None


class IngestJournal:
    def __init__(self, directory, key: bytes, *, max_bytes=20 * 1024**3,
                 reserve_bytes=50 * 1024**3, group_seconds=.02,
                 queue_size=32, max_record_bytes=16 * 1024**2):
        if len(key) != 32:
            raise ValueError('journal key must be exactly 32 bytes')
        if max_bytes <= 0 or reserve_bytes < 0 or group_seconds <= 0 or queue_size <= 0:
            raise ValueError('invalid journal limits')
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_bytes, self.reserve_bytes = max_bytes, reserve_bytes
        self.max_record_bytes = max_record_bytes
        self.group_seconds = group_seconds
        self._aes = AESGCM(key)
        self._owner = open(self.directory / 'owner.lock', 'a+b')
        try:
            if os.name == 'nt':
                import msvcrt
                self._owner.seek(0)
                self._owner.write(b'0')
                self._owner.flush()
                self._owner.seek(0)
                msvcrt.locking(self._owner.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._owner.close()
            raise RuntimeError('journal already owned: run one API worker per journal') from None
        self.path = self.directory / 'journal.sqlite3'
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('PRAGMA synchronous=FULL')
        self._db.execute('PRAGMA cache_size=-65536')
        self._db.execute('PRAGMA wal_autocheckpoint=256')
        self._group_reserved = 0
        self._db.executescript('''
            CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS receipts (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, payload_id TEXT UNIQUE NOT NULL,
              agent_id TEXT NOT NULL, envelope_hash TEXT NOT NULL, payload_hash TEXT NOT NULL,
              cipher_hash TEXT, received_at TEXT NOT NULL, accepted REAL NOT NULL,
              data BLOB, delivered INTEGER NOT NULL DEFAULT 0,
              analytics_done INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS pending ON receipts(delivered, seq);
        ''')
        if 'analytics_done' not in {r[1] for r in self._db.execute('PRAGMA table_info(receipts)')}:
            self._db.execute('ALTER TABLE receipts ADD COLUMN analytics_done INTEGER NOT NULL DEFAULT 0')
            self._db.commit()
        # Detect an incorrect encryption key even if every old record was reclaimed.
        sentinel = self._db.execute("SELECT value FROM settings WHERE name='key_check'").fetchone()
        try:
            if sentinel:
                self._decode(bytes.fromhex(sentinel[0]), 'key_check')
            else:
                self._db.execute('INSERT INTO settings VALUES (?,?)',
                                 ('key_check', self._encode({'ok': True}, 'key_check').hex()))
                self._db.commit()
        except Exception:
            self._db.close()
            self._owner.close()
            raise ValueError('journal encryption key does not match existing journal') from None
        self._db.execute('INSERT OR IGNORE INTO settings VALUES (?,?)',('cache_namespace',uuid.uuid4().hex))
        self._db.commit()
        self.cache_namespace=self._db.execute("SELECT value FROM settings WHERE name='cache_namespace'").fetchone()[0]
        row=self._db.execute("SELECT seq FROM sqlite_sequence WHERE name='receipts'").fetchone()
        self.revision=int(row[0]) if row else 0
        self._queue = queue.Queue(maxsize=queue_size)
        self._closed = False
        self._worker = threading.Thread(target=self._loop, name='JournalGroupCommit', daemon=True)
        self._worker.start()

    def _encode(self, value, payload_id):
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, zlib.compress(canonical(value), 1), payload_id.encode())

    def _decode(self, data, payload_id):
        return json.loads(zlib.decompress(self._aes.decrypt(data[:12], data[12:], payload_id.encode())))

    def _submit(self, operation, *args):
        item = Submission(operation, args)
        with self._lock:
            if self._closed:
                raise RuntimeError('journal is closed')
            try:
                self._queue.put_nowait(item)
            except queue.Full:
                raise RuntimeError('journal admission queue full; retry') from None
        # No timeout that could be mistaken for a negative durable outcome.
        item.done.wait()
        if item.error:
            raise item.error
        return item.result

    def append(self, envelope, payload, *, projection=None,stored_payload=None):
        if stored_payload is not None and any(stored_payload.get(k)!=payload.get(k) for k in ('payload_id','agent_id')):
            raise ValueError('journal projection changed authenticated identity')
        value=dict(envelope=envelope,payload=stored_payload if stored_payload is not None else payload)
        if projection is not None:
            value['projection']=projection
        if len(canonical(value)) > self.max_record_bytes:
            raise ValueError('journal record exceeds byte limit')
        return self._submit('append', envelope, payload, projection, stored_payload)

    def setting(self,name):
        with self._lock:
            row=self._db.execute('SELECT value FROM settings WHERE name=?',(name,)).fetchone()
            return row[0] if row else None

    def set_setting(self,name,value):
        return self._submit('setting',name,str(value))

    def seed_receipts(self,rows,*,hashed=False):
        if len(rows)>1000:
            raise ValueError('receipt seed batch exceeds 1000 rows')
        return self._submit('seed',rows,hashed)

    def lookup(self, payload_id):
        with self._lock:
            row = self._db.execute('''SELECT envelope_hash,payload_hash,cipher_hash,agent_id,seq,received_at
                                      FROM receipts WHERE payload_id=?''', (payload_id,)).fetchone()
        if row is None:
            return None
        return dict(zip(('envelope_hash', 'decrypted_payload_hash', 'ciphertext_hash', 'agent_id', 'seq', 'received_at'), row))

    def record(self,seq):
        with self._lock:
            row=self._db.execute('''SELECT payload_id,received_at,data,analytics_done FROM receipts
                                   WHERE seq=?''',(seq,)).fetchone()
            if row is None:
                return None
            value=self._decode(row[2],row[0]) if row[2] is not None else {}
            return dict(seq=seq,payload_id=row[0],received_at=row[1],analytics_done=bool(row[3]),**value)

    def pending(self, *, limit=1024, max_bytes=8 * 1024**2,before_seq=None):
        records, size = [], 0
        with self._lock:
            extra=' AND seq<=?' if before_seq is not None else ''
            params=(before_seq,limit) if before_seq is not None else (limit,)
            rows = self._db.execute('''SELECT seq,payload_id,received_at,data,analytics_done FROM receipts
                                      WHERE delivered=0'''+extra+' ORDER BY seq LIMIT ?', params)
            for seq, pid, received, data, analytics_done in rows:
                value = self._decode(data, pid)
                cost = len(canonical(value))
                if size + cost > max_bytes:
                    if not records:
                        raise ValueError('pending record exceeds replay byte limit')
                    break
                records.append(dict(seq=seq, payload_id=pid, received_at=received,
                                    analytics_done=bool(analytics_done), **value))
                size += cost
        return records

    def complete(self, sequences):
        return self._submit('complete', tuple(sequences))

    def mark_analytics(self,sequences):
        return self._submit('analytics',tuple(sequences))

    def compact(self, retention_hours,before_received):
        """Expire only completed identities older than both retained data and policy."""
        return self._submit('compact', time.time() - retention_hours * 3600,before_received)

    def stats(self,before_seq=None):
        with self._lock:
            count, oldest, size,received = self._db.execute('''SELECT count(*),min(accepted),
                COALESCE(sum(length(data)),0),min(received_at) FROM receipts WHERE delivered=0'''+
                (' AND seq<=?' if before_seq is not None else ''),
                (before_seq,) if before_seq is not None else ()).fetchone()
        return dict(pending=count, oldest_age=0 if oldest is None else time.time()-oldest,
                    pending_bytes=size, disk_bytes=self.disk_bytes(), revision=self.revision,
                    oldest_received=received)

    def disk_bytes(self):
        return sum(p.stat().st_size for p in self.directory.glob('journal.sqlite3*') if p.is_file())

    def _apply(self, item):
        if item.operation=='setting':
            self._db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)',item.args)
            return
        if item.operation=='seed':
            if self.disk_bytes()+len(item.args[0])*2048>self.max_bytes:
                raise RuntimeError('receipt seed exceeds journal capacity')
            for row in item.args[0]:
                pid,agent,envelope,payload_hash,cipher_hash,received=row
                if not item.args[1] and isinstance(envelope,str):
                    envelope=json.loads(envelope)
                accepted_at=datetime.fromisoformat(str(received).replace('Z','+00:00'))
                if accepted_at.tzinfo is None:
                    accepted_at=accepted_at.replace(tzinfo=timezone.utc)
                accepted_at=accepted_at.astimezone(timezone.utc)
                self._db.execute('''INSERT OR IGNORE INTO receipts
                    (payload_id,agent_id,envelope_hash,payload_hash,cipher_hash,received_at,accepted,delivered,analytics_done)
                    VALUES (?,?,?,?,?,?,?,?,?)''',
                    (pid,agent,envelope if item.args[1] else digest(envelope),payload_hash or '',cipher_hash,
                     accepted_at.isoformat(timespec='milliseconds'),accepted_at.timestamp(),1,1))
            return
        if item.operation == 'append':
            envelope, payload, projection, stored_payload = item.args
            pid = str(payload['payload_id'])
            existing = self.lookup(pid)
            if existing:
                if (existing['envelope_hash'] != digest(envelope)
                        or existing['agent_id'] != str(payload['agent_id'])):
                    raise ValueError('duplicate payload_id with different content or identity')
                return False
            value=dict(envelope=envelope,payload=stored_payload if stored_payload is not None else payload)
            if projection is not None:
                value['projection']=projection
            data = self._encode(value, pid)
            # Include record/index/WAL overhead and free-space reserve. Never evict pending data.
            if (self.disk_bytes() + self._group_reserved + 4 * len(data) + 65536 > self.max_bytes
                    or shutil.disk_usage(self.directory).free < self.reserve_bytes + 4 * len(data)):
                raise RuntimeError('journal disk reserve or capacity exhausted; retry')
            self._group_reserved += 4 * len(data) + 65536
            received = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
            cipher = envelope.get('ciphertext')
            cur = self._db.execute('''INSERT INTO receipts
                (payload_id,agent_id,envelope_hash,payload_hash,cipher_hash,received_at,accepted,data)
                VALUES (?,?,?,?,?,?,?,?)''',
                (pid, str(payload['agent_id']), digest(envelope), digest(payload),
                 hashlib.sha256(cipher.encode()).hexdigest() if cipher is not None else None,
                 received, time.time(), data))
            return cur.lastrowid
        if item.operation == 'complete':
            self._db.executemany('UPDATE receipts SET delivered=1,data=NULL WHERE seq=?',
                                 [(s,) for s in item.args[0]])
        elif item.operation == 'analytics':
            self._db.executemany('UPDATE receipts SET analytics_done=1 WHERE seq=?',
                                [(s,) for s in item.args[0]])
        elif item.operation == 'compact':
            self._db.execute('DELETE FROM receipts WHERE delivered=1 AND accepted<? AND received_at<?', item.args)
        else:
            raise ValueError('unsupported journal operation')

    def _loop(self):
        while True:
            first = self._queue.get()
            if first is None:
                return
            batch = [first]
            stopping = False
            deadline = time.monotonic() + self.group_seconds
            while len(batch) < 64 and time.monotonic() < deadline:
                try:
                    other = self._queue.get(timeout=max(.0001, deadline-time.monotonic()))
                    if other is None:
                        stopping = True
                        break
                    batch.append(other)
                except queue.Empty:
                    break
            with self._lock:
                try:
                    self._group_reserved = 0
                    self._db.execute('BEGIN IMMEDIATE')
                    for item in batch:
                        item.result = self._apply(item)
                    self._db.commit()  # FULL synchronous WAL commit is the ACK boundary.
                    row=self._db.execute("SELECT seq FROM sqlite_sequence WHERE name='receipts'").fetchone()
                    self.revision=max(self.revision,int(row[0]) if row else 0)
                except Exception as exc:
                    try:
                        self._db.rollback()
                    except Exception:
                        pass
                    try:
                        row=self._db.execute("SELECT seq FROM sqlite_sequence WHERE name='receipts'").fetchone()
                        self.revision=max(self.revision,int(row[0]) if row else 0)
                    except Exception:
                        pass
                    for item in batch:
                        item.error = exc
            for item in batch:
                item.done.set()
            batch.clear()
            first=other=item=None
            if stopping:
                return

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
        # Queue all accepted operations before the sentinel, then wait for durable outcomes.
        self._queue.put(None)
        self._worker.join()
        try:
            self._db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        finally:
            try:
                self._db.close()
            finally:
                self._owner.close()
