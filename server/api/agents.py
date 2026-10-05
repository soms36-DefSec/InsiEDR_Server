from __future__ import annotations

import json
import logging
import anyio
from typing import Any
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from server.api.deps import (
    get_storage,
    require_operator,
    require_agent,
    verify_agent_identity,
    extract_client_ip,
    OperatorPrincipal,
    AgentPrincipal,
)
from server.config import config
from server.api.events import dispatch_agent_event

logger = logging.getLogger("insiedr.api.agents")

router = APIRouter(prefix="/api", tags=["Fleet & Endpoints"])
bp = router  # Backward compatibility alias


def _sync_queue_task(
    storage: Any,
    agent_id: str,
    command: str,
    params: dict[str, Any],
    actor_id: str,
    actor_role: str,
    ip_address: str | None,
) -> str:
    import uuid
    from shared.crypto_utils import sign_hmac_sha256

    task_id = str(uuid.uuid4())
    params_str = json.dumps(params or {}, separators=(",", ":"))
    payload = f"{task_id}:{command}:{params_str}".encode("utf-8")

    signature = None
    try:
        secret_key = config.load_aes_key()
        signature = sign_hmac_sha256(secret_key, payload)
    except Exception as sig_err:
        logger.debug("Could not compute task HMAC signature: %s", sig_err)

    kwargs: dict[str, Any] = {
        "task_id": task_id,
        "agent_id": agent_id,
        "command": command,
        "params": params,
        "signature": signature,
    }
    import inspect
    sig = inspect.signature(storage.queue_agent_task)
    if "actor_id" in sig.parameters or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
        kwargs.update({
            "actor_id": actor_id,
            "actor_role": actor_role,
            "ip_address": ip_address,
        })
    return storage.queue_agent_task(**kwargs)


async def _queue_task_with_audit(
    storage: Any,
    agent_id: str,
    command: str,
    params: dict[str, Any],
    operator: OperatorPrincipal,
    request: Request,
) -> str:
    actor_id = operator.actor
    actor_role = list(operator.roles)[0] if operator.roles else "operator"
    ip_address = extract_client_ip(request)
    return await anyio.to_thread.run_sync(
        _sync_queue_task,
        storage,
        agent_id,
        command,
        params,
        actor_id,
        actor_role,
        ip_address,
    )


@router.get("/agents")
@router.get("/v1/agents")
async def get_agents(
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    """List registered fleet endpoints."""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured", "agents": []}, status_code=503)
    agents = await anyio.to_thread.run_sync(
        lambda: storage.list_agents(limit=limit, offset=offset)
    )
    return {"ok": True, "agents": agents}


@router.get("/agents/{agent_id}")
@router.get("/v1/agents/{agent_id}")
async def get_agent_by_id(
    agent_id: str,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    """Retrieve detailed metadata and health for a single endpoint."""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    def _lookup_agent():
        agent = storage.get_agent(agent_id) if hasattr(storage, "get_agent") else None
        if not agent and hasattr(storage, "list_agents"):
            agents = storage.list_agents(limit=500, offset=0)
            agent = next((a for a in agents if a.get("agent_id") == agent_id), None)
        return agent

    agent = await anyio.to_thread.run_sync(_lookup_agent)
    if not agent:
        return JSONResponse({"ok": False, "error": f"Agent '{agent_id}' not found"}, status_code=404)
    return {"ok": True, "agent": agent}


@router.post("/agent/heartbeat")
@router.post("/v1/agent/heartbeat")
async def agent_heartbeat(
    request: Request,
    storage=Depends(get_storage),
    agent_principal: AgentPrincipal = Depends(require_agent),
):
    """
    Ingest agent periodic heartbeat with host metrics (CPU, RAM, Spool depth)
    and dispatch pending remote tasks for containment / mitigation.
    Matches InsiEDR-agent HeartbeatRequest / HeartbeatResponse protocol.
    """
    if storage is None:
        return JSONResponse({"status": "error", "error": "storage is not configured"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "error", "error": "Invalid JSON body"}, status_code=400)

    agent_id = body.get("agent_id")
    hostname = body.get("hostname")
    if not agent_id or not hostname:
        return JSONResponse({"status": "error", "error": "agent_id and hostname are required"}, status_code=400)

    verify_agent_identity(agent_id, agent_principal)

    ip_address = body.get("ip_address") or extract_client_ip(request) or "127.0.0.1"
    agent_version = body.get("agent_version", "2.0.0")
    status = body.get("status", "healthy")
    metrics = body.get("metrics") or {}
    config_version = body.get("config_version", "v1.0")

    # 1. Upsert agent health & presence in DB
    try:
        if hasattr(storage, "upsert_agent_heartbeat"):
            await anyio.to_thread.run_sync(
                lambda: storage.upsert_agent_heartbeat(
                    agent_id=agent_id,
                    hostname=hostname,
                    ip_address=ip_address,
                    agent_version=agent_version,
                    status=status,
                    metrics=metrics,
                    config_version=config_version,
                )
            )
    except Exception as exc:
        logger.warning("Failed upserting agent heartbeat: %s", exc)

    # 2. Fetch pending tasks queued for this agent
    pending_tasks: list[dict[str, Any]] = []
    if hasattr(storage, "get_pending_agent_tasks"):
        try:
            def _get_and_dispatch():
                tasks = storage.get_pending_agent_tasks(agent_id)
                if tasks and hasattr(storage, "mark_tasks_dispatched"):
                    task_ids = [t["task_id"] for t in tasks]
                    storage.mark_tasks_dispatched(task_ids)
                return tasks

            pending_tasks = await anyio.to_thread.run_sync(_get_and_dispatch)
        except Exception as exc:
            logger.warning("Failed querying pending tasks: %s", exc)

    # 3. Broadcast real-time agent presence update to SOC dashboard via SSE
    try:
        dispatch_agent_event({
            "event_type": "heartbeat",
            "agent_id": agent_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "status": status,
            "metrics": metrics,
        })
    except Exception:
        pass

    # 4. Return HeartbeatResponse conforming to native Rust agent contract
    formatted_tasks = [
        {
            "task_id": t["task_id"],
            "command": t["command"],
            "params": t.get("params") or {},
            "signature": t.get("signature"),
        }
        for t in pending_tasks
    ]

    return {
        "status": "acknowledged",
        "pending_tasks": formatted_tasks,
        "config_update": None,
    }


@router.post("/agent/task-result")
@router.post("/agent/task_result", include_in_schema=False)
@router.post("/v1/agent/task-result")
@router.post("/v1/agent/task_result", include_in_schema=False)
async def agent_task_result(
    request: Request,
    storage=Depends(get_storage),
    agent_principal: AgentPrincipal = Depends(require_agent),
):
    """
    Ingest remote command execution results uploaded by the agent.
    Matches InsiEDR-agent TaskResultPayload contract.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)

    agent_id = body.get("agent_id")
    task_id = body.get("task_id")
    status = body.get("status", "unknown")
    exit_code = int(body.get("exit_code", 0))
    message = str(body.get("message", ""))
    timestamp = body.get("timestamp")

    if not task_id:
        return JSONResponse({"ok": False, "error": "task_id is required"}, status_code=400)

    verify_agent_identity(agent_id or "", agent_principal)

    # 1. Update task result in DB
    updated = False
    if hasattr(storage, "update_agent_task_result"):
        try:
            updated = await anyio.to_thread.run_sync(
                lambda: storage.update_agent_task_result(
                    agent_id=agent_id or "",
                    task_id=task_id,
                    status=status,
                    exit_code=exit_code,
                    message=message,
                    completed_at=timestamp,
                )
            )
        except Exception as exc:
            logger.warning("Failed updating task result: %s", exc)

    # 2. Broadcast result via SSE
    try:
        dispatch_agent_event({
            "event_type": "task_result",
            "agent_id": agent_id,
            "task_id": task_id,
            "status": status,
            "exit_code": exit_code,
            "message": message,
        })
    except Exception:
        pass

    return {
        "ok": True,
        "task_id": task_id,
        "status": "recorded",
        "updated": updated,
    }


@router.post("/agent/task-ack")
@router.post("/v1/agent/task-ack")
async def agent_task_ack(
    request: Request,
    storage=Depends(get_storage),
    agent_principal: AgentPrincipal = Depends(require_agent),
):
    """
    Explicitly acknowledge receipt of a dispatched task by the executing agent.
    Prevents lease expiration and duplicate redelivery.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)

    agent_id = body.get("agent_id")
    task_id = body.get("task_id")
    if not agent_id or not task_id:
        return JSONResponse({"ok": False, "error": "agent_id and task_id are required"}, status_code=400)

    verify_agent_identity(agent_id, agent_principal)

    acknowledged = False
    if hasattr(storage, "acknowledge_agent_task"):
        try:
            acknowledged = await anyio.to_thread.run_sync(
                lambda: storage.acknowledge_agent_task(agent_id=agent_id, task_id=task_id)
            )
        except Exception as exc:
            logger.warning("Failed acknowledging task: %s", exc)

    return {
        "ok": True,
        "agent_id": agent_id,
        "task_id": task_id,
        "acknowledged": acknowledged,
    }


# --------------------------------------------------------------------------
# SOC Containment & Action Dispatch Endpoints
# --------------------------------------------------------------------------


@router.post("/agents/{agent_id}/isolate")
@router.post("/v1/agents/{agent_id}/isolate")
async def isolate_agent(
    agent_id: str,
    request: Request,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:containment")),
):
    """
    Queue an immediate host network isolation task.
    Agent will configure Windows Firewall to block all traffic except egress to server.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    params: dict[str, Any] = {}
    try:
        body = await request.json()
        if isinstance(body, dict):
            params = body
    except Exception:
        pass

    server_ip = params.get("server_ip")
    if not server_ip:
        server_ip = config.server_ip

    task_params = {"server_ip": server_ip or "127.0.0.1"}
    task_id = await _queue_task_with_audit(
        storage=storage,
        agent_id=agent_id,
        command="isolate_host",
        params=task_params,
        operator=operator,
        request=request,
    )

    try:
        dispatch_agent_event({
            "event_type": "task_queued",
            "agent_id": agent_id,
            "task_id": task_id,
            "command": "isolate_host",
        })
    except Exception:
        pass

    return {
        "ok": True,
        "agent_id": agent_id,
        "task_id": task_id,
        "command": "isolate_host",
        "status": "queued",
    }


@router.post("/agents/{agent_id}/unisolate")
@router.post("/v1/agents/{agent_id}/unisolate")
async def unisolate_agent(
    agent_id: str,
    request: Request,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:containment")),
):
    """
    Queue task to remove network containment firewall rules and restore normal connectivity.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    task_id = await _queue_task_with_audit(
        storage=storage,
        agent_id=agent_id,
        command="unisolate_host",
        params={},
        operator=operator,
        request=request,
    )

    try:
        dispatch_agent_event({
            "event_type": "task_queued",
            "agent_id": agent_id,
            "task_id": task_id,
            "command": "unisolate_host",
        })
    except Exception:
        pass

    return {
        "ok": True,
        "agent_id": agent_id,
        "task_id": task_id,
        "command": "unisolate_host",
        "status": "queued",
    }


@router.post("/agents/{agent_id}/terminate")
@router.post("/v1/agents/{agent_id}/terminate")
async def terminate_agent_process(
    agent_id: str,
    request: Request,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:remediation")),
):
    """
    Queue remote malicious process termination by PID.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)

    pid = body.get("pid")
    if pid is None or not isinstance(pid, int) or pid <= 0:
        return JSONResponse({"ok": False, "error": "A positive integer 'pid' is required"}, status_code=400)

    task_id = await _queue_task_with_audit(
        storage=storage,
        agent_id=agent_id,
        command="kill_process",
        params={"pid": pid},
        operator=operator,
        request=request,
    )

    try:
        dispatch_agent_event({
            "event_type": "task_queued",
            "agent_id": agent_id,
            "task_id": task_id,
            "command": "kill_process",
            "pid": pid,
        })
    except Exception:
        pass

    return {
        "ok": True,
        "agent_id": agent_id,
        "task_id": task_id,
        "command": "kill_process",
        "pid": pid,
        "status": "queued",
    }


@router.post("/agents/{agent_id}/lock")
@router.post("/v1/agents/{agent_id}/lock")
async def lock_agent_workstation(
    agent_id: str,
    request: Request,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:remediation")),
):
    """
    Queue immediate workstation console lock (Win32 LockWorkStation).
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    task_id = await _queue_task_with_audit(
        storage=storage,
        agent_id=agent_id,
        command="lock_workstation",
        params={},
        operator=operator,
        request=request,
    )

    try:
        dispatch_agent_event({
            "event_type": "task_queued",
            "agent_id": agent_id,
            "task_id": task_id,
            "command": "lock_workstation",
        })
    except Exception:
        pass

    return {
        "ok": True,
        "agent_id": agent_id,
        "task_id": task_id,
        "command": "lock_workstation",
        "status": "queued",
    }


@router.post("/agents/{agent_id}/rollback")
@router.post("/v1/agents/{agent_id}/rollback")
async def rollback_agent_files(
    agent_id: str,
    request: Request,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:remediation")),
):
    """
    Queue VSS snapshot creation or directory rollback against ransomware damage.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    params: dict[str, Any] = {}
    try:
        body = await request.json()
        if isinstance(body, dict):
            params = body
    except Exception:
        pass

    path = params.get("path")
    if path:
        command = "rollback_directory"
        task_params = {"path": path, "snapshot": params.get("snapshot")}
    else:
        command = "create_shadow"
        task_params = {"volume": params.get("volume", "C:")}

    task_id = await _queue_task_with_audit(
        storage=storage,
        agent_id=agent_id,
        command=command,
        params=task_params,
        operator=operator,
        request=request,
    )

    try:
        dispatch_agent_event({
            "event_type": "task_queued",
            "agent_id": agent_id,
            "task_id": task_id,
            "command": command,
            "params": task_params,
        })
    except Exception:
        pass

    return {
        "ok": True,
        "agent_id": agent_id,
        "task_id": task_id,
        "command": command,
        "params": task_params,
        "status": "queued",
    }


@router.get("/agents/{agent_id}/tasks")
@router.get("/v1/agents/{agent_id}/tasks")
async def get_agent_tasks(
    agent_id: str,
    limit: int = Query(50, ge=1),
    offset: int = Query(0, ge=0),
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    """
    List historical remote tasks queued or executed for the agent.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured", "tasks": []}, status_code=503)

    tasks = await anyio.to_thread.run_sync(
        lambda: storage.list_agent_tasks(agent_id=agent_id, limit=limit, offset=offset)
    ) if hasattr(storage, "list_agent_tasks") else []
    return {
        "ok": True,
        "agent_id": agent_id,
        "tasks": tasks,
    }


# --------------------------------------------------------------------------
# Tamper Alerts
# --------------------------------------------------------------------------


@router.get("/agents/tamper-alerts")
@router.get("/v1/agents/tamper-alerts")
async def get_tamper_alerts(
    limit: int = Query(50, ge=1),
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    """Returns recent risk events where tamper_detector fired."""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured", "alerts": []}, status_code=503)

    try:
        risk_events = await anyio.to_thread.run_sync(
            lambda: storage.list_risk_events(limit=500, offset=0)
        ) if hasattr(storage, "list_risk_events") else []

        tamper_alerts = []
        for ev in risk_events:
            try:
                signals = ev.get("correlated_signals_json")
                if isinstance(signals, str):
                    signals = json.loads(signals)
                elif signals is None:
                    signals = {}

                if signals.get("tamper_detector", {}).get("is_anomaly") is True:
                    level = (ev.get("risk_level") or "").upper()
                    if not level or level in ["NONE", "INFO"]:
                        score = float(ev.get("risk_score") or 0.0)
                        if score >= 85.0:
                            level = "CRITICAL"
                        elif score >= 60.0:
                            level = "HIGH"
                        elif score >= 35.0:
                            level = "MEDIUM"
                        else:
                            level = "LOW"
                    ev["risk_level"] = level
                    tamper_alerts.append(ev)
            except Exception:
                continue

            if len(tamper_alerts) >= limit:
                break

        return {"ok": True, "alerts": tamper_alerts}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e), "alerts": []}, status_code=500)
