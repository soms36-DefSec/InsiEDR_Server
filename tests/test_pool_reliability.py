import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from psycopg2.pool import PoolError
from server.storage.postgres_storage import PostgresStorage


def storage_with_pool(capacity=2, wait=1):
    storage = PostgresStorage.__new__(PostgresStorage)
    storage.connection_factory = None
    storage._pool_slots = threading.BoundedSemaphore(capacity)
    storage._pool_wait_seconds = wait
    storage._pool_broken = False
    storage.pool = Mock()
    storage.pool.getconn.side_effect = lambda: Mock(closed=False)
    return storage


@pytest.mark.parametrize('failure', [None, RuntimeError('query failed'), KeyboardInterrupt()])
def test_pool_rolls_back_and_returns_connection_on_every_exit(failure):
    storage = storage_with_pool()
    connection = None
    try:
        with storage.connection() as connection:
            if failure:
                raise failure
    except BaseException as exc:
        assert exc is failure
    connection.rollback.assert_called_once()
    storage.pool.putconn.assert_called_once_with(connection, close=False)
    assert storage._pool_slots._value == 2


@pytest.mark.parametrize('closed,rollback_error', [(True, False), (False, True)])
def test_bad_connection_is_discarded_and_slot_released(closed, rollback_error):
    storage = storage_with_pool()
    connection = Mock(closed=closed)
    if rollback_error:
        connection.rollback.side_effect = OSError('disconnected')
    storage.pool.getconn.side_effect = None
    storage.pool.getconn.return_value = connection
    with storage.connection():
        pass
    storage.pool.putconn.assert_called_once_with(connection, close=True)
    assert storage._pool_slots._value == 2


def test_checkout_failure_does_not_leak_admission_slot():
    storage = storage_with_pool()
    storage.pool.getconn.side_effect = PoolError('database unavailable')
    with pytest.raises(PoolError):
        with storage.connection():
            pass
    assert storage._pool_slots._value == 2


def test_pool_capacity_has_a_bounded_wait():
    storage = storage_with_pool(1, .03)
    with storage.connection():
        start = time.monotonic()
        with pytest.raises(PoolError):
            with storage.connection():
                pass
        assert time.monotonic() - start < .5
    assert storage._pool_slots._value == 1


def test_contended_pool_never_exceeds_capacity_or_leaks():
    storage = storage_with_pool(3, 3)
    lock = threading.Lock()
    active = peak = 0

    def query(_):
        nonlocal active, peak
        with storage.connection():
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(.002)
            with lock:
                active -= 1

    with ThreadPoolExecutor(max_workers=24) as executor:
        list(executor.map(query, range(240)))
    assert peak <= 3
    assert active == 0
    assert storage.pool.putconn.call_count == 240
    assert storage._pool_slots._value == 3


def test_pool_return_failure_is_visible_and_future_checkout_fails_closed():
    storage = storage_with_pool()
    storage.pool.putconn.side_effect = OSError('broken pool')
    with storage.connection() as conn:
        pass
    conn.close.assert_called_once()
    with pytest.raises(PoolError):
        with storage.connection():
            pass
    assert storage._pool_slots._value == 2
