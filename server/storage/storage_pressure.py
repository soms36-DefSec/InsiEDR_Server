"""Pure pressure policy; hard admission checks remain independent of hysteresis."""
from dataclasses import dataclass
from enum import IntEnum


class Level(IntEnum):
    NORMAL = 0
    PRESSURED = 1
    CRITICAL = 2


@dataclass(frozen=True)
class Limits:
    rows: int
    batch_bytes: int
    flush_seconds: float
    analytical_queries: int
    admission: int
    archive: bool
    cache_entries: int


POLICY = {
    Level.NORMAL: Limits(8000, 8*1024**2, 2, 3, 16, True, 150000),
    Level.PRESSURED: Limits(12000, 12*1024**2, 4, 1, 8, False, 80000),
    Level.CRITICAL: Limits(16000, 16*1024**2, 6, 0, 2, False, 40000),
}


class PressureController:
    def __init__(self):
        self.level = Level.NORMAL
        self._candidate = self.level
        self._ticks = 0

    def sample(self, m):
        # Ratios are relative to configured caps, never arbitrary fleet-wide part counts.
        critical = (m.get('free_bytes', float('inf')) < m.get('reserve_bytes', 0)
                    or m.get('queue_ratio', 0) >= .95 or m.get('memory_ratio', 0) >= .92)
        pressured = (m.get('queue_ratio', 0) >= .7 or m.get('memory_ratio', 0) >= .8
                     or m.get('cache_ratio',0)>.9
                     or m.get('oldest_age', 0) > 180 or m.get('disk_latency_ms', 0) > 50
                     or m.get('insert_seconds', 0) > 3 or m.get('merge_ratio', 0) > .8
                     or m.get('live_seconds', 0) > .15 or m.get('query_seconds', 0) > 2
                     or m.get('arrival_bytes_sec', 0) > m.get('drain_bytes_sec', float('inf')))
        target = Level.CRITICAL if critical else Level.PRESSURED if pressured else Level.NORMAL
        if target != self._candidate:
            self._candidate, self._ticks = target, 0
        self._ticks += 1
        if critical or self._ticks >= (3 if target > self.level else 5):
            self.level = target
        return POLICY[self.level]
