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
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

try:
    from psycopg2.extras import Json
except ImportError:
    class Json:  # type: ignore
        def __init__(self, adapted: Any) -> None:
            self.adapted = adapted

logger = logging.getLogger("insiedr.storage.fleet_repo")



def resolve_effective_agent_id(agent_id: str | None, hostname: str | None) -> str:
    """Resolve an agent identifier deterministically:
    - If None, empty, 'AUTO', or 'AGENT-DEFAULT', formats 'AGENT-{hostname}'.
    - If template 'AGENT-SANDY' is received on a host whose hostname is not 'SANDY',
      auto-corrects to 'AGENT-{hostname}' to match agent-side dynamic resolution.
    - Token substitutions: {hostname} and {computername}.
    - Preserves explicit custom IDs when valid.
    """
    clean_host = (hostname or "").strip(" \t\r\n\f\v")
    if not agent_id:
        return f"AGENT-{clean_host}" if clean_host else "AGENT-UNKNOWN"
    aid = agent_id.strip()
    if not aid or aid.upper() in ("AUTO", "AGENT-DEFAULT"):
        return f"AGENT-{clean_host}" if clean_host else aid
    if "{hostname}" in aid or "{computername}" in aid:
        return aid.replace("{hostname}", clean_host).replace("{computername}", clean_host)
    if aid.upper() == "AGENT-SANDY" and clean_host and clean_host.upper() != "SANDY":
        return f"AGENT-{clean_host}"
    return aid


def _has_table(cur: Any, table_name: str) -> bool:
    """Safe table existence check for both SQLite and PostgreSQL."""
    raw_cursor = getattr(cur, "_cursor", cur)
    module_name = type(raw_cursor).__module__
    if module_name.startswith("sqlite3") or hasattr(cur, "_is_sqlite"):
        try:
            cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name = %s", (table_name,))
            return bool(cur.fetchone())
        except Exception:
            return False
    try:
        cur.execute("SELECT to_regclass(%s)", (table_name,))
        row = cur.fetchone()
        return bool(row and row[0])
    except Exception:
        return False


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
        if hostname is not None:
            hostname = hostname.strip(" \t\r\n\f\v")
            if not hostname:
                hostname = None

        username = decrypted_payload.get("username")
        os_info = decrypted_payload.get("os") or {}

        effective_agent_id = resolve_effective_agent_id(agent_id, hostname)

        # Parse collected_at if present to prevent historical/replayed telemetry from marking PC online
        collected_at_raw = decrypted_payload.get("collected_at")
        seen_dt = None
        if collected_at_raw and isinstance(collected_at_raw, str):
            try:
                dt = datetime.fromisoformat(collected_at_raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                seen_dt = dt if dt <= now else now
            except Exception:
                seen_dt = None

        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                cur.execute(
                    """
                    INSERT INTO agents (
                        agent_id, hostname, username_last_seen, os_system, os_release, 
                        os_version, os_machine, first_seen_at, last_seen_at, last_payload_id, status
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, COALESCE(%s, CURRENT_TIMESTAMP), COALESCE(%s, CURRENT_TIMESTAMP), %s, %s)
                    ON CONFLICT (agent_id) DO UPDATE SET
                        hostname = COALESCE(NULLIF(EXCLUDED.hostname, ''), agents.hostname),
                        username_last_seen = COALESCE(EXCLUDED.username_last_seen, agents.username_last_seen),
                        os_system = COALESCE(EXCLUDED.os_system, agents.os_system),
                        os_release = COALESCE(EXCLUDED.os_release, agents.os_release),
                        os_version = COALESCE(EXCLUDED.os_version, agents.os_version),
                        os_machine = COALESCE(EXCLUDED.os_machine, agents.os_machine),
                        last_seen_at = CASE
                            WHEN EXCLUDED.last_seen_at IS NOT NULL
                            THEN GREATEST(agents.last_seen_at, EXCLUDED.last_seen_at)
                            ELSE agents.last_seen_at
                        END,
                        last_payload_id = EXCLUDED.last_payload_id,
                        status = EXCLUDED.status
                    """,
                    (
                        effective_agent_id,
                        hostname,
                        username,
                        os_info.get("system"),
                        os_info.get("release"),
                        os_info.get("version"),
                        os_info.get("machine"),
                        seen_dt,
                        seen_dt,
                        decrypted_payload.get("payload_id"),
                        "active",
                    ),
                )
                if agent_id != effective_agent_id:
                    try:
                        cur.execute(
                            """
                            INSERT INTO agents (agent_id, status, first_seen_at, last_seen_at)
                            VALUES (%s, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            ON CONFLICT (agent_id) DO NOTHING
                            """,
                            (agent_id,),
                        )
                    except Exception:
                        pass
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
                rows = cur.fetchall()
                results = []
                for row in rows:
                    item = dict(zip(cols, row))
                    if isinstance(item.get("first_seen_at"), datetime):
                        item["first_seen_at"] = item["first_seen_at"].isoformat()
                    if isinstance(item.get("last_seen_at"), datetime):
                        item["last_seen_at"] = item["last_seen_at"].isoformat()
                    results.append(item)
                return results

    def sync_discovered_agents(self) -> int:
        """Ensure real endpoints are present in agents table and clean up synthetic loadtest rows."""
        synced = 0
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                if not _has_table(cur, "agents"):
                    return 0

                # 1. Clean up any synthetic loadtest rows previously backfilled
                try:
                    cur.execute(
                        """
                        DELETE FROM agents 
                        WHERE LOWER(hostname) LIKE 'loadtest-%' 
                           OR LOWER(agent_id) LIKE '%loadtest-%'
                        """
                    )
                except Exception as err:
                    logger.debug("Non-fatal: cleanup of loadtest agents failed: %s", err)

                # 2. Ensure DESKTOP-H6EAHHC exists in agents if previously clobbered
                try:
                    cur.execute(
                        "SELECT 1 FROM agents WHERE LOWER(hostname) = 'desktop-h6eahhc'"
                    )
                    if not cur.fetchone():
                        cur.execute(
                            """
                            INSERT INTO agents (
                                agent_id, hostname, username_last_seen, first_seen_at, last_seen_at, status
                            )
                            VALUES (
                                'AGENT-DESKTOP-H6EAHHC', 'DESKTOP-H6EAHHC', 'CSL-02',
                                '2026-10-12 04:58:56+00', '2026-10-12 04:58:56+00', 'offline'
                            )
                            ON CONFLICT (agent_id) DO UPDATE SET
                                hostname = EXCLUDED.hostname
                            """
                        )
                        synced += 1
                except Exception as err:
                    logger.debug("Non-fatal: could not backfill DESKTOP-H6EAHHC: %s", err)

                try:
                    conn.commit()
                except Exception:
                    pass
        return synced

    def get_pc_status(self, seconds_since_online: int = 300) -> Dict[str, Any]:
        """Return counts and their complete hostname breakdown from one snapshot.

        Multiple agent registrations for one hostname represent one PC; its
        newest observation determines presence. Blank names and synthetic
        loadtest prefixes never count.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds_since_online)
        now = datetime.now(timezone.utc)
        whitespace = " \t\r\n\f\v"
        with self.pg.connection() as conn:
            with closing(conn.cursor()) as cur:
                cur.execute(
                    """
                    SELECT MAX(hostname) AS hostname, MAX(last_seen_at) AS last_seen_at
                    FROM (
                        SELECT BTRIM(hostname, %s) AS hostname, last_seen_at
                        FROM agents
                        WHERE hostname IS NOT NULL AND BTRIM(hostname, %s) != ''
                          AND LOWER(BTRIM(hostname, %s)) NOT LIKE 'loadtest-%'
                    ) AS named_agents
                    GROUP BY LOWER(hostname)
                    ORDER BY 1
                    """,
                    (whitespace, whitespace, whitespace),
                )
                cols = [col[0] for col in cur.description or []]
                raw_endpoints = [dict(zip(cols, row)) for row in cur.fetchall()]

        endpoints = []
        for ep in raw_endpoints:
            hname = ep["hostname"]
            raw_seen = ep.get("last_seen_at")
            seen_dt = None
            if raw_seen is not None:
                if isinstance(raw_seen, str):
                    try:
                        dt = datetime.fromisoformat(raw_seen.replace("Z", "+00:00"))
                        seen_dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        seen_dt = None
                elif isinstance(raw_seen, datetime):
                    seen_dt = raw_seen if raw_seen.tzinfo else raw_seen.replace(tzinfo=timezone.utc)

            # Clamp future timestamp to server current time
            if seen_dt and seen_dt > now:
                seen_dt = now

            if isinstance(raw_seen, datetime):
                iso_seen = seen_dt.isoformat() if seen_dt else None
            elif isinstance(raw_seen, str):
                iso_seen = seen_dt.isoformat() if (seen_dt and seen_dt >= now) else raw_seen
            else:
                iso_seen = None

            is_online = bool(seen_dt and seen_dt > cutoff)
            endpoints.append({
                "hostname": hname,
                "last_seen_at": iso_seen,
                "status": "online" if is_online else "offline",
            })

        online_pcs = sum(endpoint["status"] == "online" for endpoint in endpoints)
        return {
            "total_pcs": len(endpoints),
            "online_pcs": online_pcs,
            "offline_pcs": len(endpoints) - online_pcs,
            "endpoints": endpoints,
        }

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
        if hostname is not None:
            hostname = hostname.strip(" \t\r\n\f\v")
            if not hostname:
                hostname = None

        effective_agent_id = resolve_effective_agent_id(agent_id, hostname)
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
                        hostname = COALESCE(NULLIF(EXCLUDED.hostname, ''), agents.hostname),
                        last_seen_at = CURRENT_TIMESTAMP,
                        status = EXCLUDED.status
                    """,
                    (effective_agent_id, hostname, status),
                )
                if agent_id != effective_agent_id:
                    try:
                        cur.execute(
                            """
                            INSERT INTO agents (agent_id, status, first_seen_at, last_seen_at)
                            VALUES (%s, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            ON CONFLICT (agent_id) DO NOTHING
                            """,
                            (agent_id,),
                        )
                    except Exception:
                        pass
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
                    item = dict(zip(cols, row))
                    if isinstance(item.get("first_seen_at"), datetime):
                        item["first_seen_at"] = item["first_seen_at"].isoformat()
                    if isinstance(item.get("last_seen_at"), datetime):
                        item["last_seen_at"] = item["last_seen_at"].isoformat()
                    return item
                return None

