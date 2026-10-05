import os
import logging
import requests

log = logging.getLogger("webhook")


def _send_webhook(event: dict) -> None:
    """
    Pure HTTP dispatch function. Called by the TaskWorker inside its own thread.
    Safe to call directly for testing; no side-effects beyond the HTTP POST.
    """
    webhook_url = os.environ.get("INSIEDR_WEBHOOK_URL")
    if not webhook_url:
        return
    try:
        risk_score = float(event.get("risk_score") or 0.0)
        payload = {
            "text": (
                f"🚨 *CRITICAL INSIDER THREAT DETECTED* 🚨\n"
                f"**User**: {event.get('username')}\n"
                f"**Agent**: {event.get('agent_id')}\n"
                f"**Risk Score**: {risk_score:.2f}/100\n"
                f"**Summary**: {event.get('summary')}\n"
            ),
            "raw_event": event,
        }
        resp = requests.post(webhook_url, json=payload, timeout=5)
        resp.raise_for_status()
    except Exception as exc:
        log.warning("Failed to dispatch webhook alert: %s", exc)
        raise  # Re-raise so the TaskWorker can handle retry logic


_task_queue = None


def set_task_queue(queue) -> None:
    global _task_queue
    _task_queue = queue


def dispatch_alert(event: dict) -> None:
    """
    Enqueue a webhook alert as a durable task so it survives a server restart.
    Falls back to a direct synchronous send if the task queue is unavailable or enqueue fails.
    """
    global _task_queue
    if _task_queue is not None:
        try:
            task_id = _task_queue.enqueue("webhook_alert", event)
            if task_id is not None:
                return
            log.warning("Task queue enqueue returned None for webhook_alert; falling back to direct dispatch")
        except Exception as exc:
            log.warning("Task queue enqueue threw exception: %s; falling back to direct dispatch", exc)

    # Fallback: direct send (no durability guarantee)
    _send_webhook(event)


