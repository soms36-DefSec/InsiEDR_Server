from __future__ import annotations

import json
import logging
from typing import Any
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from server.api.deps import get_storage
from server.api.events import dispatch_agent_event

logger = logging.getLogger("insiedr.api.agents")

router = APIRouter(prefix="/api", tags=["Fleet & Endpoints"])
bp = router  # Backward compatibility alias


@router.get("/agents")
@router.get("/v1/agents")
async def get_agents(
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
    storage=Depends(get_storage),
):
    """List registered fleet endpoints."""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured", "agents": []}, status_code=503)
    return {"ok": True, "agents": storage.list_agents(limit=limit, offset=offset)}


@router.get("/agents/{agent_id}")
@router.get("/v1/agents/{agent_id}")
async def get_agent_by_id(
    agent_id: str,
    storage=Depends(get_storage),
):
    """Retrieve detailed metadata and health for a single endpoint."""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)
    
    agent = storage.get_agent(agent_id) if hasattr(storage, "get_agent") else None
    if not agent:
        # Fallback to search list_agents if get_agent returned None
        agents = storage.list_agents(limit=500, offset=0)
        agent = next((a for a in agents if a.get("agent_id") == agent_id), None)
    
    if not agent:
        return JSONResponse({"ok": False, "error": f"Agent '{agent_id}' not found"}, status_code=404)
    return {"ok": True, "agent": agent}


@router.post("/agent/heartbeat")
@router.post("/v1/agent/heartbeat")
async def agent_heartbeat(
    request: Request,
    storage=Depends(get_storage),
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

    ip_address = body.get("ip_address") or (request.client.host if request.client else "127.0.0.1")
    agent_version = body.get("agent_version", "2.0.0")
    status = body.get("status", "healthy")
    metrics = body.get("metrics") or {}
    config_version = body.get("config_version", "v1.0")

    # 1. Upsert agent health & presence in DB
    try:
        if hasattr(storage, "upsert_agent_heartbeat"):
            storage.upsert_agent_heartbeat(
                agent_id=agent_id,
                hostname=hostname,
                ip_address=ip_address,
                agent_version=agent_version,
                status=status,
                metrics=metrics,
                config_version=config_version,
            )
    except Exception as exc:
        logger.warning("Failed upserting agent heartbeat: %s", exc)

    # 2. Fetch pending tasks queued for this agent
    pending_tasks: list[dict[str, Any]] = []
    if hasattr(storage, "get_pending_agent_tasks"):
        try:
            pending_tasks = storage.get_pending_agent_tasks(agent_id)
            if pending_tasks and hasattr(storage, "mark_tasks_dispatched"):
                task_ids = [t["task_id"] for t in pending_tasks]
                storage.mark_tasks_dispatched(task_ids)
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

    # 1. Update task result in DB
    updated = False
    if hasattr(storage, "update_agent_task_result"):
        try:
            updated = storage.update_agent_task_result(
                agent_id=agent_id or "",
                task_id=task_id,
                status=status,
                exit_code=exit_code,
                message=message,
                completed_at=timestamp,
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


# --------------------------------------------------------------------------
# SOC Containment & Action Dispatch Endpoints
# --------------------------------------------------------------------------


@router.post("/agents/{agent_id}/isolate")
@router.post("/v1/agents/{agent_id}/isolate")
async def isolate_agent(
    agent_id: str,
    request: Request,
    storage=Depends(get_storage),
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
    if not server_ip and request.client:
        server_ip = request.client.host

    task_id = storage.queue_agent_task(
        agent_id=agent_id,
        command="isolate_host",
        params={"server_ip": server_ip or "127.0.0.1"},
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
    storage=Depends(get_storage),
):
    """
    Queue task to remove network containment firewall rules and restore normal connectivity.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    task_id = storage.queue_agent_task(
        agent_id=agent_id,
        command="unisolate_host",
        params={},
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

    task_id = storage.queue_agent_task(
        agent_id=agent_id,
        command="kill_process",
        params={"pid": pid},
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
    storage=Depends(get_storage),
):
    """
    Queue immediate workstation console lock (Win32 LockWorkStation).
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    task_id = storage.queue_agent_task(
        agent_id=agent_id,
        command="lock_workstation",
        params={},
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

    task_id = storage.queue_agent_task(
        agent_id=agent_id,
        command=command,
        params=task_params,
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
):
    """
    List historical remote tasks queued or executed for the agent.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured", "tasks": []}, status_code=503)

    tasks = storage.list_agent_tasks(agent_id=agent_id, limit=limit, offset=offset) if hasattr(storage, "list_agent_tasks") else []
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
):
    """Returns recent risk events where tamper_detector fired."""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured", "alerts": []}, status_code=503)

    try:
        risk_events = storage.list_risk_events(limit=500, offset=0)

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
