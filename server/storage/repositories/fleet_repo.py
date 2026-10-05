"""
server/storage/repositories/fleet_repo.py
-----------------------------------------
Fleet Management & Agent Health Repository.
Operates primarily against PostgreSQL 16 for ACID state consistency.
"""
from __future__ import annotations

import json
import logging
from contextlib import closing
from typing import Any, Dict, List, Optional

try:
    from psycopg2.extras import Json
except ImportError:
    class Json:  # type: ignore
        def __init__(self, adapted: Any) -> None:
            self.adapted = adapted

logger = logging.getLogger("insiedr.storage.fleet_repo")



class FleetRepository:
    """Encapsulates fleet discovery, agent lifecycle, and PC online/offline status."""

    def __init__(self, postgres_storage: Any) -> None:
        self.pg = postgres_storage

    def upsert_agent(self, decrypted_payload: Dict[str, Any]) -> None:
        """Register or update an agent's heartbeat and host hardware profile."""
        agent_id = decrypted_payload.get("agent_id")
        if not agent_id:
            return

        hostname = decrypted_payload.get("hostname")
        username = decrypted_payload.get("username")
        os_info = decrypted_payload.get("os") or {}

        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                cur.execute(
                    """
                    INSERT INTO agents (
                        agent_id, hostname, username_last_seen, os_system, os_release, 
                        os_version, os_machine, first_seen_at, last_seen_at, last_payload_id, status
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %s, %s)
                    ON CONFLICT (agent_id) DO UPDATE SET
                        hostname = COALESCE(EXCLUDED.hostname, agents.hostname),
                        username_last_seen = COALESCE(EXCLUDED.username_last_seen, agents.username_last_seen),
                        os_system = COALESCE(EXCLUDED.os_system, agents.os_system),
                        os_release = COALESCE(EXCLUDED.os_release, agents.os_release),
                        os_version = COALESCE(EXCLUDED.os_version, agents.os_version),
                        os_machine = COALESCE(EXCLUDED.os_machine, agents.os_machine),
                        last_seen_at = EXCLUDED.last_seen_at,
                        last_payload_id = EXCLUDED.last_payload_id,
                        status = EXCLUDED.status
                    """,
                    (
                        agent_id,
                        hostname,
                        username,
                        os_info.get("system"),
                        os_info.get("release"),
                        os_info.get("version"),
                        os_info.get("machine"),
                        decrypted_payload.get("payload_id"),
                        "active",
                    ),
                )
                conn.commit()

    def list_agents(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List registered fleet endpoints with dynamic active/offline status."""
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                cur.execute(
                    """
                    SELECT agent_id, hostname, username_last_seen, os_system, os_release, os_version, os_machine,
                           first_seen_at, last_seen_at, last_payload_id,
                           CASE WHEN last_seen_at > CURRENT_TIMESTAMP - INTERVAL '5 minutes' THEN 'active' ELSE 'offline' END as status
                    FROM agents
                    ORDER BY last_seen_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (limit, offset),
                )
                cols = [col[0] for col in cur.description or []]
                return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_pc_status(self, seconds_since_online: int = 300) -> Dict[str, Any]:
        """Compute unique total, online, and offline PC counts."""
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                try:
                    cur.execute("SELECT COUNT(DISTINCT hostname) FROM agents WHERE hostname IS NOT NULL")
                    total_pcs = cur.fetchone()[0] or 0

                    cur.execute(
                        """
                        SELECT COUNT(DISTINCT hostname) FROM agents 
                        WHERE hostname IS NOT NULL 
                        AND last_seen_at > CURRENT_TIMESTAMP - INTERVAL '1 second' * %s
                        """,
                        (seconds_since_online,)
                    )
                    online_pcs = cur.fetchone()[0] or 0
                    offline_pcs = max(0, total_pcs - online_pcs)

                    return {
                        "total_pcs": total_pcs,
                        "online_pcs": online_pcs,
                        "offline_pcs": offline_pcs,
                    }
                except Exception as exc:
                    logger.warning("Error fetching pc status: %s", exc)
                    return {"total_pcs": 0, "online_pcs": 0, "offline_pcs": 0}

    def upsert_agent_heartbeat(
        self,
        agent_id: str,
        hostname: str,
        ip_address: str | None = None,
        agent_version: str | None = None,
        status: str = "active",
        metrics: Dict[str, Any] | None = None,
        config_version: str | None = None,
    ) -> None:
        """Register or update an agent's heartbeat, status, and health metrics."""
        if not agent_id:
            return
        metrics = metrics or {}
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                cur.execute(
                    """
                    INSERT INTO agents (
                        agent_id, hostname, first_seen_at, last_seen_at, status
                    )
                    VALUES (%s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %s)
                    ON CONFLICT (agent_id) DO UPDATE SET
                        hostname = COALESCE(EXCLUDED.hostname, agents.hostname),
                        last_seen_at = CURRENT_TIMESTAMP,
                        status = EXCLUDED.status
                    """,
                    (agent_id, hostname, status),
                )
                try:
                    cur.execute(
                        """
                        INSERT INTO agent_heartbeats (
                            agent_id, hostname, ip_address, agent_version, status, metrics_json, config_version, received_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        """,
                        (
                            agent_id,
                            hostname,
                            ip_address,
                            agent_version,
                            status,
                            Json(metrics),
                            config_version,
                        ),
                    )
                except Exception as hb_err:
                    logger.debug("Non-fatal: could not log to agent_heartbeats: %s", hb_err)
                conn.commit()

    VALID_TASK_STATUSES = {
        "pending", "dispatched", "acknowledged", "running",
        "success", "completed", "failed", "rejected", "timeout", "cancelled"
    }
    TERMINAL_STATES = {
        "success", "completed", "failed", "rejected", "timeout", "cancelled"
    }

    def queue_task(
        self,
        agent_id: str,
        command: str,
        params: Dict[str, Any] | None = None,
        signature: str | None = None,
        task_id: str | None = None,
        actor_id: str | None = None,
        actor_role: str | None = None,
        ip_address: str | None = None,
    ) -> str:
        """Enqueue a remote containment/investigation command for the agent."""
        if not task_id:
            import uuid
            task_id = str(uuid.uuid4())
        params = params or {}
        actor = actor_id or "system"
        role = actor_role or "operator"
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                cur.execute(
                    """
                    INSERT INTO agents (agent_id, status, first_seen_at, last_seen_at)
                    VALUES (%s, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ON CONFLICT (agent_id) DO NOTHING
                    """,
                    (agent_id,),
                )
                cur.execute(
                    """
                    INSERT INTO agent_tasks (
                        task_id, agent_id, command, params_json, signature, status, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, 'pending', CURRENT_TIMESTAMP)
                    """,
                    (task_id, agent_id, command, Json(params), signature),
                )
                # Atomically record operator command audit log
                try:
                    cur.execute(
                        """
                        INSERT INTO command_audit_log (
                            task_id, agent_id, command, params_json, actor_id, actor_role, ip_address, status, created_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued', CURRENT_TIMESTAMP)
                        """,
                        (task_id, agent_id, command, Json(params), actor, role, ip_address),
                    )
                except Exception as audit_err:
                    err_msg = str(audit_err).lower()
                    if "command_audit_log" in err_msg and ("does not exist" in err_msg or "no such table" in err_msg):
                        pass
                    else:
                        raise
                conn.commit()
        return task_id

    def get_pending_tasks(self, agent_id: str) -> List[Dict[str, Any]]:
        """Fetch pending tasks or expired unacknowledged leases for the given agent."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                try:
                    cur.execute(
                        """
                        SELECT task_id, command, params_json, signature
                        FROM agent_tasks
                        WHERE agent_id = %s
                          AND (
                            status = 'pending'
                            OR (status = 'dispatched' AND acknowledged_at IS NULL AND lease_expires_at IS NOT NULL AND lease_expires_at < %s)
                          )
                        ORDER BY created_at ASC
                        """,
                        (agent_id, now),
                    )
                except Exception:
                    # Fallback if lease columns are not present in legacy schema
                    cur.execute(
                        """
                        SELECT task_id, command, params_json, signature
                        FROM agent_tasks
                        WHERE agent_id = %s AND status = 'pending'
                        ORDER BY created_at ASC
                        """,
                        (agent_id,),
                    )
                cols = [col[0] for col in cur.description or []]
                rows = cur.fetchall()
                tasks = []
                for row in rows:
                    item = dict(zip(cols, row))
                    if isinstance(item.get("params_json"), str):
                        try:
                            item["params"] = json.loads(item["params_json"])
                        except Exception:
                            item["params"] = {}
                    else:
                        item["params"] = item.get("params_json") or {}
                    tasks.append({
                        "task_id": item["task_id"],
                        "command": item["command"],
                        "params": item["params"],
                        "signature": item.get("signature"),
                    })
                return tasks

    def mark_tasks_dispatched(self, task_ids: List[str], lease_seconds: int = 120) -> None:
        """Mark tasks as dispatched to the agent with a recoverable delivery lease."""
        if not task_ids:
            return
        from datetime import datetime, timezone, timedelta
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                for tid in task_ids:
                    try:
                        cur.execute(
                            """
                            UPDATE agent_tasks
                            SET status = 'dispatched',
                                dispatched_at = CURRENT_TIMESTAMP,
                                dispatch_count = COALESCE(dispatch_count, 0) + 1,
                                lease_expires_at = %s
                            WHERE task_id = %s AND (status = 'pending' OR (status = 'dispatched' AND acknowledged_at IS NULL))
                            """,
                            (expires_at, tid),
                        )
                    except Exception:
                        # Fallback for schema without lease columns
                        cur.execute(
                            """
                            UPDATE agent_tasks
                            SET status = 'dispatched', dispatched_at = CURRENT_TIMESTAMP
                            WHERE task_id = %s AND status = 'pending'
                            """,
                            (tid,),
                        )
                conn.commit()

    def acknowledge_task(self, agent_id: str, task_id: str) -> bool:
        """Explicitly acknowledge receipt of a task by the executing agent."""
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                try:
                    cur.execute(
                        """
                        UPDATE agent_tasks
                        SET status = 'acknowledged', acknowledged_at = CURRENT_TIMESTAMP
                        WHERE task_id = %s AND agent_id = %s AND status IN ('pending', 'dispatched')
                        """,
                        (task_id, agent_id),
                    )
                except Exception:
                    cur.execute(
                        """
                        UPDATE agent_tasks
                        SET status = 'acknowledged'
                        WHERE task_id = %s AND agent_id = %s AND status IN ('pending', 'dispatched')
                        """,
                        (task_id, agent_id),
                    )
                conn.commit()
                return cur.rowcount > 0

    def update_task_result(
        self,
        agent_id: str,
        task_id: str,
        status: str,
        exit_code: int,
        message: str,
        completed_at: str | None = None,
    ) -> bool:
        """Update task execution result reported by agent.
        Enforces:
        1. Task ownership in SQL by BOTH task_id AND agent_id.
        2. Legal state transitions (terminal states cannot be overwritten with different states).
        3. Allowed status validation.
        """
        normalized_status = status.lower().strip()
        if normalized_status not in self.VALID_TASK_STATUSES:
            logger.warning("Rejected invalid task status '%s' for task %s", status, task_id)
            return False

        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                cur.execute(
                    """
                    UPDATE agent_tasks
                    SET status = %s, exit_code = %s, message = %s, completed_at = CURRENT_TIMESTAMP
                    WHERE task_id = %s AND agent_id = %s
                      AND (status NOT IN ('success', 'completed', 'failed', 'rejected', 'timeout', 'cancelled') OR status = %s)
                    """,
                    (normalized_status, exit_code, message, task_id, agent_id, normalized_status),
                )
                updated = cur.rowcount > 0
                if updated:
                    try:
                        cur.execute(
                            """
                            UPDATE command_audit_log
                            SET status = %s
                            WHERE task_id = %s AND agent_id = %s
                            """,
                            (normalized_status, task_id, agent_id),
                        )
                    except Exception:
                        pass
                conn.commit()
                return updated

    def list_agent_tasks(self, agent_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List historical tasks executed or queued for the agent."""
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                cur.execute(
                    """
                    SELECT task_id, agent_id, command, params_json, signature, status, exit_code, message,
                           created_at, dispatched_at, completed_at
                    FROM agent_tasks
                    WHERE agent_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (agent_id, limit, offset),
                )
                cols = [col[0] for col in cur.description or []]
                rows = cur.fetchall()
                results = []
                for row in rows:
                    item = dict(zip(cols, row))
                    if isinstance(item.get("params_json"), str):
                        try:
                            item["params"] = json.loads(item["params_json"])
                        except Exception:
                            item["params"] = {}
                    else:
                        item["params"] = item.get("params_json") or {}
                    results.append(item)
                return results

    def get_agent(self, agent_id: str) -> Dict[str, Any] | None:
        """Get agent details by ID."""
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                cur.execute(
                    """
                    SELECT agent_id, hostname, username_last_seen, os_system, os_release, os_version, os_machine,
                           first_seen_at, last_seen_at, last_payload_id,
                           CASE WHEN last_seen_at > CURRENT_TIMESTAMP - INTERVAL '5 minutes' THEN 'active' ELSE 'offline' END as status
                    FROM agents
                    WHERE agent_id = %s
                    """,
                    (agent_id,),
                )
                cols = [col[0] for col in cur.description or []]
                row = cur.fetchone()
                if row:
                    return dict(zip(cols, row))
                return None

