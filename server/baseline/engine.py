from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
from typing import Any, Dict, Optional

from server.storage.base import BaseStorage


@dataclass
class UserBaseline:
    username: str
    feature_means: Dict[str, float] = field(default_factory=dict)
    feature_stds: Dict[str, float] = field(default_factory=dict)
    sample_count: int = 0
    hour_profiles: Dict[int, Dict[str, float]] = field(default_factory=dict)
    last_updated: str = ""
    decay_factor: float = 0.05
    
    # Independent Missingness Tracking
    feature_missing_counts: Dict[str, int] = field(default_factory=dict)
    feature_sample_counts: Dict[str, int] = field(default_factory=dict)
    
    # 1-Day Short Term Buffer
    short_term_sums: Dict[str, float] = field(default_factory=dict)
    short_term_counts: Dict[str, int] = field(default_factory=dict)
    last_merge_date: str = ""
    last_observation_at: str = ""
    cohort_member_last_seen: Dict[str, str] = field(default_factory=dict)

    @property
    def confidence_score(self) -> float:
        return min(self.sample_count / 14.0, 1.0) if self.sample_count > 0 else 0.1


# Organizational priors for cold-start accounts before user or role baseline matures (>= 5 samples).
# Normal activities produce z <= 0; extreme anomalous spikes produce immediate calibrated deviations.
DEFAULT_FEATURE_PRIORS: Dict[str, tuple[float, float]] = {
    "auth_rate_300s": (0.2, 0.5),
    "auth_rate_3600s": (0.2, 0.5),
    "auth_fail_rate_300s": (0.0, 0.2),
    "edr_auth_events_per_minute_window": (1.0, 2.0),
    "edr_failed_auth_events_per_minute_window": (0.0, 0.5),
    "edr_failed_auth_ratio_window": (0.0, 0.15),
    "unique_workstations_300s": (1.0, 0.5),
    "off_hours_auth_count": (0.0, 0.5),
    "daily_after_hours_logon_ratio": (0.0, 0.15),
    "daily_unique_pc_count": (1.0, 0.5),
    "daily_unique_filename_count": (25.0, 35.0),
    "daily_new_filename_count": (10.0, 25.0),
    "file_access_count": (30.0, 50.0),
    "file_sharing_site_visits": (0.0, 0.5),
    "daily_http_request_count": (60.0, 80.0),
    "daily_external_domain_ratio": (0.25, 0.25),
    "daily_device_connect_count": (0.0, 0.5),
    "bytes_sent": (5_000_000.0, 15_000_000.0),
}


class BaselineEngine:
    def __init__(self, storage: BaseStorage, window_days: int = 30) -> None:
        self.storage = storage
        self.window_days = window_days
        # EMA Equivalent for N days: 2 / (N + 1)
        self.decay = 2.0 / (window_days + 1.0)
        self._meta_lock = threading.Lock()
        self._entity_locks: dict[str, threading.Lock] = {}

    def _get_entity_lock(self, entity_id: str) -> threading.Lock:
        with self._meta_lock:
            if entity_id not in self._entity_locks:
                self._entity_locks[entity_id] = threading.Lock()
            return self._entity_locks[entity_id]

    def _get_role_for_user(self, user: str, role: str | None = None) -> str:
        explicit_role = str(role or "").strip()
        if explicit_role:
            return explicit_role.lower().replace(" ", "_")
        lower = user.lower()
        if "admin" in lower or "sys" in lower or "root" in lower:
            return "administrator"
        return "standard_user"

    @staticmethod
    def _std_floor(feature: str, mean_value: float) -> float:
        normalized = feature.lower()
        if "ratio" in normalized or "rate" in normalized or "entropy" in normalized:
            return max(abs(mean_value) * 0.1, 0.05)
        return max(abs(mean_value) * 0.1, 1.0)

    def get_baseline(self, user: str) -> Optional[UserBaseline]:
        row = self.storage.load_baseline(user)
        if not row:
            return None
        metadata = row.get("metadata_json") or {}
        return UserBaseline(
            username=row.get("username") or user,
            feature_means=dict(metadata.get("feature_means") or {}),
            feature_stds=dict(metadata.get("feature_stds") or {}),
            sample_count=int(row.get("sample_count") or 0),
            hour_profiles=dict(metadata.get("hour_profiles") or {}),
            last_updated=row.get("created_at") or "",
            decay_factor=float(metadata.get("decay_factor") or self.decay),
            feature_missing_counts=dict(metadata.get("feature_missing_counts") or {}),
            feature_sample_counts=dict(metadata.get("feature_sample_counts") or {}),
            short_term_sums=dict(metadata.get("short_term_sums") or {}),
            short_term_counts=dict(metadata.get("short_term_counts") or {}),
            last_merge_date=metadata.get("last_merge_date") or "",
            last_observation_at=metadata.get("last_observation_at") or "",
            cohort_member_last_seen=dict(metadata.get("cohort_member_last_seen") or {}),
        )

    @staticmethod
    def _parse_observed_at(value: str | datetime | None) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                parsed = datetime.now(timezone.utc)
        else:
            parsed = datetime.now(timezone.utc)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)

    def _update_single_baseline(
        self,
        entity_id: str,
        features: Dict[str, float],
        observed_at: str | datetime | None = None,
        contributing_user: str | None = None,
    ) -> dict[str, Any]:
        storage_lock = getattr(self.storage, "acquire_entity_lock", None)
        in_process_lock = self._get_entity_lock(entity_id)

        with in_process_lock:
            if callable(storage_lock):
                with storage_lock(entity_id):
                    return self._do_update_single_baseline(entity_id, features, observed_at, contributing_user)
            return self._do_update_single_baseline(entity_id, features, observed_at, contributing_user)

    def _do_update_single_baseline(
        self,
        entity_id: str,
        features: Dict[str, float],
        observed_at: str | datetime | None = None,
        contributing_user: str | None = None,
    ) -> dict[str, Any]:
        current = self.get_baseline(entity_id) or UserBaseline(username=entity_id, decay_factor=self.decay)
        observed = self._parse_observed_at(observed_at)
        today_date = observed.strftime("%Y-%m-%d")

        is_cohort = entity_id.startswith("__role_") or entity_id.startswith("__org_")

        # High-frequency snapshots are correlated; retain at most one baseline
        # observation per entity (or per contributing member for cohorts) per hour
        # and ignore stale/replayed observations.
        if is_cohort:
            contrib_key = str(contributing_user or "unknown").strip().lower()
            if contrib_key in current.cohort_member_last_seen:
                previous = self._parse_observed_at(current.cohort_member_last_seen[contrib_key])
                if observed <= previous or (observed - previous).total_seconds() < 3600:
                    return {"username": entity_id, "sample_count": current.sample_count, "skipped": True, "reason": "cohort member throttled"}
        else:
            if current.last_observation_at:
                previous = self._parse_observed_at(current.last_observation_at)
                if observed <= previous or (observed - previous).total_seconds() < 3600:
                    return {"username": entity_id, "sample_count": current.sample_count, "skipped": True, "reason": "entity throttled"}

        # Merge short term buffer into long term EMA if a day has passed
        if current.last_merge_date and current.last_merge_date != today_date:
            for feature, count in current.short_term_counts.items():
                if count > 0:
                    daily_avg = current.short_term_sums.get(feature, 0.0) / count

                    prev_mean = current.feature_means.get(feature, daily_avg)
                    updated_mean = (1 - self.decay) * prev_mean + self.decay * daily_avg
                    current.feature_means[feature] = updated_mean

                    prev_std = current.feature_stds.get(feature, self._std_floor(feature, prev_mean))
                    updated_std = (1 - self.decay) * prev_std + self.decay * abs(daily_avg - prev_mean)
                    current.feature_stds[feature] = max(updated_std, self._std_floor(feature, updated_mean))
                    current.feature_sample_counts[feature] = current.feature_sample_counts.get(feature, 0) + 1

            # Reset buffer
            current.short_term_sums = {}
            current.short_term_counts = {}

        current.last_merge_date = today_date
        current.sample_count += 1
        current.last_observation_at = observed.isoformat().replace("+00:00", "Z")
        if is_cohort:
            if contributing_user:
                contrib_key = str(contributing_user or "unknown").strip().lower()
                current.cohort_member_last_seen[contrib_key] = observed.isoformat().replace("+00:00", "Z")
            # Prune cohort member recency records older than 48 hours to bound dictionary size
            cutoff_seconds = 48 * 3600
            current.cohort_member_last_seen = {
                u: ts for u, ts in current.cohort_member_last_seen.items()
                if (observed - self._parse_observed_at(ts)).total_seconds() < cutoff_seconds
            }

        # Add current features to short term buffer
        all_known_features = set(current.feature_means.keys()).union(features.keys())
        for feature_name in all_known_features:
            if feature_name in features:
                value = features[feature_name]
                current.short_term_sums[feature_name] = current.short_term_sums.get(feature_name, 0.0) + value
                current.short_term_counts[feature_name] = current.short_term_counts.get(feature_name, 0) + 1
            else:
                current.feature_missing_counts[feature_name] = current.feature_missing_counts.get(feature_name, 0) + 1

        payload = {
            "agent_id": None,
            "username": entity_id,
            "feature_name": "__aggregate__",
            "baseline_scope": "user",
            "window_start": observed.isoformat().replace("+00:00", "Z"),
            "window_end": observed.isoformat().replace("+00:00", "Z"),
            "mean_value": 0.0,
            "std_value": 0.0,
            "sample_count": current.sample_count,
            "logic_version": "2.0",
            "metadata_json": {
                "feature_means": current.feature_means,
                "feature_stds": current.feature_stds,
                "feature_missing_counts": current.feature_missing_counts,
                "feature_sample_counts": current.feature_sample_counts,
                "short_term_sums": current.short_term_sums,
                "short_term_counts": current.short_term_counts,
                "last_merge_date": current.last_merge_date,
                "last_observation_at": current.last_observation_at,
                "cohort_member_last_seen": current.cohort_member_last_seen,
                "hour_profiles": current.hour_profiles,
                "decay_factor": self.decay,
            },
            "created_at": observed.isoformat().replace("+00:00", "Z"),
        }
        self.storage.save_baseline(payload)
        return payload

    def update_baseline(
        self,
        user: str,
        features: Dict[str, float],
        hour: int | None = None,
        observed_at: str | datetime | None = None,
        role: str | None = None,
    ):
        if not features:
            return {"username": user, "skipped": True, "reason": "no baseline features"}
        user_payload = self._update_single_baseline(user, features, observed_at)
        role_name = self._get_role_for_user(user, role)
        self._update_single_baseline(f"__role_{role_name}__", features, observed_at, contributing_user=user)
        return user_payload

    def get_deviation_vector(
        self,
        user: str,
        features: Dict[str, float],
        role: str | None = None,
    ) -> Dict[str, float]:
        baseline = self.get_baseline(user)
        role_name = self._get_role_for_user(user, role)
        role_baseline = self.get_baseline(f"__role_{role_name}__")

        deviations: Dict[str, float] = {}
        for name, value in features.items():
            if baseline and baseline.feature_sample_counts.get(name, 0) >= 5:
                mean_value = baseline.feature_means.get(name, value)
                std_value = max(baseline.feature_stds.get(name, 0.0), self._std_floor(name, mean_value))
            elif role_baseline and role_baseline.feature_sample_counts.get(name, 0) >= 5:
                mean_value = role_baseline.feature_means.get(name, value)
                std_value = max(role_baseline.feature_stds.get(name, 0.0), self._std_floor(name, mean_value))
            elif name in DEFAULT_FEATURE_PRIORS:
                prior_mean, prior_std = DEFAULT_FEATURE_PRIORS[name]
                mean_value = prior_mean
                std_value = max(prior_std, self._std_floor(name, prior_mean))
            else:
                mean_value = value
                std_value = 1.0

            deviations[name] = (value - mean_value) / std_value
        return deviations

    def get_rolling_window(self, user: str, days: int = 7) -> Dict[str, Any]:
        baseline = self.get_baseline(user)
        if baseline is None:
            return {"user": user, "days": days, "samples": []}
        return {
            "user": user,
            "days": days,
            "samples": [
                {
                    "feature": feature,
                    "mean": baseline.feature_means.get(feature, 0.0),
                    "std": baseline.feature_stds.get(feature, 0.0),
                    "samples": baseline.feature_sample_counts.get(feature, 0),
                    "missing": baseline.feature_missing_counts.get(feature, 0),
                }
                for feature in sorted(baseline.feature_means)
            ],
        }


@dataclass
class HostBaseline:
    agent_id: str
    feature_means: Dict[str, float] = field(default_factory=dict)
    feature_stds: Dict[str, float] = field(default_factory=dict)
    sample_count: int = 0
    last_updated: str = ""
    decay_factor: float = 0.05
    feature_missing_counts: Dict[str, int] = field(default_factory=dict)
    feature_sample_counts: Dict[str, int] = field(default_factory=dict)
    short_term_sums: Dict[str, float] = field(default_factory=dict)
    short_term_counts: Dict[str, int] = field(default_factory=dict)
    last_merge_date: str = ""
    last_observation_at: str = ""

    @property
    def confidence_score(self) -> float:
        return min(self.sample_count / 14.0, 1.0) if self.sample_count > 0 else 0.1


# Organizational priors for cold-start host baselines before an agent accumulates >= 5 samples.
DEFAULT_HOST_FEATURE_PRIORS: Dict[str, tuple[float, float]] = {
    "unique_workstations_300s": (1.0, 0.5),
    "auth_rate_300s": (0.2, 0.5),
    "edr_auth_events_per_minute_window": (1.0, 2.0),
    "edr_auth_event_count_window": (1.0, 2.0),
    "off_hours_auth_count": (0.0, 0.5),
    "daily_unique_pc_count": (1.0, 0.5),
    "daily_device_connect_count": (0.0, 0.5),
}


class HostBaselineEngine:
    """
    Agent-Scoped Host Baseline Engine.
    Tracks machine-wide authentication and host traversal metrics separately
    from per-user interactive session UEBA baselines.
    Applies bounded contribution updating (Winsorization) and hourly snapshot throttling.
    """

    def __init__(self, storage: BaseStorage, window_days: int = 30) -> None:
        self.storage = storage
        self.window_days = window_days
        self.decay = 2.0 / (window_days + 1.0)
        self._meta_lock = threading.Lock()
        self._entity_locks: dict[str, threading.Lock] = {}

    def _get_entity_lock(self, entity_id: str) -> threading.Lock:
        with self._meta_lock:
            if entity_id not in self._entity_locks:
                self._entity_locks[entity_id] = threading.Lock()
            return self._entity_locks[entity_id]

    @staticmethod
    def _std_floor(feature: str, mean_value: float) -> float:
        normalized = feature.lower()
        if "ratio" in normalized or "rate" in normalized or "entropy" in normalized:
            return max(abs(mean_value) * 0.1, 0.05)
        return max(abs(mean_value) * 0.1, 0.5)

    @staticmethod
    def _parse_observed_at(value: str | datetime | None) -> datetime:
        return BaselineEngine._parse_observed_at(value)

    def get_baseline(self, agent_id: str) -> Optional[HostBaseline]:
        load_fn = getattr(self.storage, "load_host_baseline", None)
        if not callable(load_fn):
            return None
        row = load_fn(agent_id)
        if not row:
            return None
        metadata = row.get("metadata_json") or {}
        if isinstance(metadata, str):
            try:
                import json
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        return HostBaseline(
            agent_id=row.get("agent_id") or agent_id,
            feature_means=dict(metadata.get("feature_means") or {}),
            feature_stds=dict(metadata.get("feature_stds") or {}),
            sample_count=int(row.get("sample_count") or 0),
            last_updated=row.get("created_at") or "",
            decay_factor=float(metadata.get("decay_factor") or self.decay),
            feature_missing_counts=dict(metadata.get("feature_missing_counts") or {}),
            feature_sample_counts=dict(metadata.get("feature_sample_counts") or {}),
            short_term_sums=dict(metadata.get("short_term_sums") or {}),
            short_term_counts=dict(metadata.get("short_term_counts") or {}),
            last_merge_date=metadata.get("last_merge_date") or "",
            last_observation_at=metadata.get("last_observation_at") or "",
        )

    def get_deviation_vector(
        self,
        agent_id: str,
        features: Dict[str, float],
    ) -> Dict[str, float]:
        baseline = self.get_baseline(agent_id)
        deviations: Dict[str, float] = {}
        for name, value in features.items():
            if baseline and baseline.feature_sample_counts.get(name, 0) >= 5:
                mean_value = baseline.feature_means.get(name, value)
                std_value = max(baseline.feature_stds.get(name, 0.0), self._std_floor(name, mean_value))
            elif name in DEFAULT_HOST_FEATURE_PRIORS:
                prior_mean, prior_std = DEFAULT_HOST_FEATURE_PRIORS[name]
                mean_value = prior_mean
                std_value = max(prior_std, self._std_floor(name, prior_mean))
            else:
                mean_value = value
                std_value = 1.0

            deviations[name] = (value - mean_value) / std_value
        return deviations

    def update_baseline(
        self,
        agent_id: str,
        features: Dict[str, float],
        observed_at: str | datetime | None = None,
    ) -> dict[str, Any]:
        if not features or not agent_id:
            return {"agent_id": agent_id, "skipped": True, "reason": "no features or agent_id"}

        storage_lock = getattr(self.storage, "acquire_entity_lock", None)
        in_process_lock = self._get_entity_lock(agent_id)

        with in_process_lock:
            if callable(storage_lock):
                with storage_lock(f"host:{agent_id}"):
                    return self._do_update_host_baseline(agent_id, features, observed_at)
            return self._do_update_host_baseline(agent_id, features, observed_at)

    def _do_update_host_baseline(
        self,
        agent_id: str,
        features: Dict[str, float],
        observed_at: str | datetime | None = None,
    ) -> dict[str, Any]:
        current = self.get_baseline(agent_id) or HostBaseline(agent_id=agent_id, decay_factor=self.decay)
        observed = self._parse_observed_at(observed_at)
        today_date = observed.strftime("%Y-%m-%d")

        # High-frequency snapshots are correlated; retain at most one baseline
        # observation per host per hour and reject stale/replayed observations.
        if current.last_observation_at:
            previous = self._parse_observed_at(current.last_observation_at)
            if observed <= previous or (observed - previous).total_seconds() < 3600:
                return {
                    "agent_id": agent_id,
                    "sample_count": current.sample_count,
                    "skipped": True,
                    "reason": "host throttled",
                }

        # Merge short term buffer into long term EMA if a day has passed
        if current.last_merge_date and current.last_merge_date != today_date:
            for feature, count in current.short_term_counts.items():
                if count > 0:
                    daily_avg = current.short_term_sums.get(feature, 0.0) / count
                    prev_mean = current.feature_means.get(feature, daily_avg)
                    updated_mean = (1 - self.decay) * prev_mean + self.decay * daily_avg
                    current.feature_means[feature] = updated_mean

                    prev_std = current.feature_stds.get(feature, self._std_floor(feature, prev_mean))
                    updated_std = (1 - self.decay) * prev_std + self.decay * abs(daily_avg - prev_mean)
                    current.feature_stds[feature] = max(updated_std, self._std_floor(feature, updated_mean))
                    current.feature_sample_counts[feature] = current.feature_sample_counts.get(feature, 0) + 1

            current.short_term_sums = {}
            current.short_term_counts = {}

        current.last_merge_date = today_date
        current.sample_count += 1
        current.last_observation_at = observed.isoformat().replace("+00:00", "Z")

        # Bounded contribution (Winsorization):
        # Clip observation to [0, mu + 3.0 * sigma] when baseline has >= 5 samples
        # to prevent sudden behavioral surges or gradual poison escalation from distorting running state.
        all_known_features = set(current.feature_means.keys()).union(features.keys())
        for feature_name in all_known_features:
            if feature_name in features:
                raw_val = float(features[feature_name])
                if current.sample_count >= 5 and feature_name in current.feature_means:
                    mu = current.feature_means[feature_name]
                    sigma = max(current.feature_stds.get(feature_name, 0.0), self._std_floor(feature_name, mu))
                    bounded_val = max(0.0, min(raw_val, mu + (3.0 * sigma)))
                else:
                    bounded_val = max(0.0, raw_val)

                current.short_term_sums[feature_name] = current.short_term_sums.get(feature_name, 0.0) + bounded_val
                current.short_term_counts[feature_name] = current.short_term_counts.get(feature_name, 0) + 1
            else:
                current.feature_missing_counts[feature_name] = current.feature_missing_counts.get(feature_name, 0) + 1

        payload = {
            "agent_id": agent_id,
            "username": None,
            "feature_name": "__host_aggregate__",
            "baseline_scope": "host",
            "window_start": observed.isoformat().replace("+00:00", "Z"),
            "window_end": observed.isoformat().replace("+00:00", "Z"),
            "mean_value": 0.0,
            "std_value": 0.0,
            "sample_count": current.sample_count,
            "logic_version": "2.0",
            "metadata_json": {
                "feature_means": current.feature_means,
                "feature_stds": current.feature_stds,
                "feature_missing_counts": current.feature_missing_counts,
                "feature_sample_counts": current.feature_sample_counts,
                "short_term_sums": current.short_term_sums,
                "short_term_counts": current.short_term_counts,
                "last_merge_date": current.last_merge_date,
                "last_observation_at": current.last_observation_at,
                "decay_factor": self.decay,
            },
            "created_at": observed.isoformat().replace("+00:00", "Z"),
        }
        save_fn = getattr(self.storage, "save_host_baseline", None)
        if callable(save_fn):
            save_fn(payload)
        return payload
