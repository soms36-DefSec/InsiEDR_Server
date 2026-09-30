from __future__ import annotations

from typing import Any


class StorageError(RuntimeError):
    pass


class BaseStorage:
    def store_raw_payload(self, envelope: dict[str, Any], decrypted_payload: dict[str, Any]) -> None:
        raise NotImplementedError()

    def get_payload(self, payload_id: str) -> dict[str, Any] | None:
        raise NotImplementedError()

    def ensure_migrations(self) -> None:
        raise NotImplementedError()

    def list_agents(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def list_logs(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def list_anomalies(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def list_risk_events(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def list_baselines(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def get_stats(self) -> dict[str, Any]:
        raise NotImplementedError()

    def save_baseline(self, baseline: dict[str, Any]) -> None:
        raise NotImplementedError()

    def load_baseline(self, username: str) -> dict[str, Any] | None:
        raise NotImplementedError()

    def get_feature_vector(self, payload_id: str) -> dict[str, Any]:
        raise NotImplementedError()

    def list_daily_feature_vectors(self, username: str | None, hostname: str | None, limit: int = 16) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def list_normalized_features(
        self,
        limit: int = 1000,
        offset: int = 0,
        agent_id: str | None = None,
        username: str | None = None,
        collector: str | None = None,
        feature_name: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[dict[str, Any]]:
        """Returns rows from normalized_features matching the specified filters."""
        raise NotImplementedError()


    def save_model_output(self, output: dict[str, Any]) -> None:
        raise NotImplementedError()

    def save_risk_event(self, event: dict[str, Any]) -> None:
        raise NotImplementedError()

    def list_recent_risk_scores(self, username: str | None, hostname: str | None, limit: int = 7) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def get_pc_status(self, seconds_since_online: int = 15) -> dict[str, Any]:
        """Returns unique PC count, online count, offline count based on last_seen_at"""
        raise NotImplementedError()

    def get_user_collectors(self, username: str) -> list[dict[str, Any]]:
        """Returns collector results for a specific user with latest data"""
        raise NotImplementedError()

    def get_user_risk_scores(self, username: str, limit: int = 30) -> list[dict[str, Any]]:
        """Returns historical risk scores for a user"""
        raise NotImplementedError()

    def get_user_predictions(self, username: str) -> dict[str, Any] | None:
        """Returns model predictions (short-term and long-term) for a user"""
        raise NotImplementedError()

    def upsert_agent_heartbeat(
        self,
        agent_id: str,
        hostname: str,
        ip_address: str | None = None,
        agent_version: str | None = None,
        status: str = "active",
        metrics: dict[str, Any] | None = None,
        config_version: str | None = None,
    ) -> None:
        """Upsert agent presence, status, and health metrics on heartbeat."""
        raise NotImplementedError()

    def queue_agent_task(
        self,
        agent_id: str,
        command: str,
        params: dict[str, Any] | None = None,
        signature: str | None = None,
        task_id: str | None = None,
    ) -> str:
        """Enqueue a remote command for the agent to execute on next heartbeat."""
        raise NotImplementedError()

    def get_pending_agent_tasks(self, agent_id: str) -> list[dict[str, Any]]:
        """Fetch pending tasks queued for the specified agent."""
        raise NotImplementedError()

    def mark_tasks_dispatched(self, task_ids: list[str]) -> None:
        """Mark tasks as dispatched to the agent."""
        raise NotImplementedError()

    def update_agent_task_result(
        self,
        agent_id: str,
        task_id: str,
        status: str,
        exit_code: int,
        message: str,
        completed_at: str | None = None,
    ) -> bool:
        """Record the execution result returned by the agent."""
        raise NotImplementedError()

    def list_agent_tasks(self, agent_id: str, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """List tasks for an agent with execution status and timestamps."""
        raise NotImplementedError()

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Get agent details by ID."""
        raise NotImplementedError()

