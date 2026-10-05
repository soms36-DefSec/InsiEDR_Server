from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Callable, Optional, Set
from fastapi import Header, Request

from server.config import config
from server.api.errors import AuthenticationError, ForbiddenError


@dataclass(frozen=True)
class OperatorPrincipal:
    """Authenticated operator or SOC analyst identity with assigned RBAC roles."""
    actor: str
    roles: Set[str]

    def has_permission(self, permission: str | None) -> bool:
        if not permission:
            return True
        if "admin" in self.roles:
            return True
        return permission in self.roles


@dataclass(frozen=True)
class AgentPrincipal:
    """Authenticated endpoint agent identity bound to pre-shared or session credentials."""
    agent_id: str
    token_fingerprint: str
    is_authenticated: bool = True


def get_storage(request: Request) -> Any:
    """Extract storage instance from FastAPI app.state or legacy extensions."""
    if hasattr(request.app.state, "storage"):
        return request.app.state.storage
    if hasattr(request.app, "extensions"):
        return request.app.extensions.get("insiedr_storage")
    return None


def get_task_queue(request: Request) -> Any:
    """Extract task queue instance from FastAPI app.state or legacy extensions."""
    if hasattr(request.app.state, "task_queue"):
        return request.app.state.task_queue
    if hasattr(request.app, "extensions"):
        return request.app.extensions.get("task_queue")
    return None


def extract_client_ip(request: Request) -> str | None:
    """Extract client IP, inspecting X-Forwarded-For or X-Real-IP if present."""
    x_forwarded = request.headers.get("X-Forwarded-For")
    if x_forwarded:
        first = x_forwarded.split(",")[0].strip()
        if first:
            return first
    x_real = request.headers.get("X-Real-IP")
    if x_real and x_real.strip():
        return x_real.strip()
    return request.client.host if request.client else None


def _extract_token(request: Request, specific_header: str | None = None) -> str | None:
    """Extract credential from custom header or standard Authorization Bearer header."""
    if specific_header:
        val = request.headers.get(specific_header)
        if val:
            return val.strip()

    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        return auth[7:].strip()

    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()

    return None


def require_operator(required_permission: str | None = None) -> Callable[[Request], OperatorPrincipal]:
    """
    FastAPI dependency enforcing operator authentication and RBAC permissions.
    Fails closed when auth is enforced and credentials are absent or insufficient.
    """
    def _dependency(request: Request) -> OperatorPrincipal:
        token = _extract_token(request, specific_header="X-Operator-Key")

        if config.auth_enforced:
            if not token:
                raise AuthenticationError("Missing operator authentication credentials", status_code=401)

            roles_map = config.operator_roles
            roles: Set[str] = set()

            if token in roles_map:
                roles = set(roles_map[token])
            elif config.operator_api_key and hmac.compare_digest(token.encode("utf-8"), config.operator_api_key.encode("utf-8")):
                roles = {"admin"}
            else:
                raise AuthenticationError("Invalid operator credentials", status_code=401)

            principal = OperatorPrincipal(
                actor=f"operator:{hashlib.sha256(token.encode()).hexdigest()[:12]}",
                roles=roles,
            )
            if required_permission and not principal.has_permission(required_permission):
                raise ForbiddenError(f"Insufficient permissions: required '{required_permission}'", status_code=403)
            return principal

        # Unenforced / local test mode fallback:
        if token:
            roles_map = config.operator_roles
            if token in roles_map:
                roles = set(roles_map[token])
            elif config.operator_api_key and hmac.compare_digest(token.encode("utf-8"), config.operator_api_key.encode("utf-8")):
                roles = {"admin"}
            else:
                roles = {"admin"}
            principal = OperatorPrincipal(actor=f"operator:{hashlib.sha256(token.encode()).hexdigest()[:12]}", roles=roles)
            if required_permission and not principal.has_permission(required_permission):
                raise ForbiddenError(f"Insufficient permissions: required '{required_permission}'", status_code=403)
            return principal

        # Permissive dev fallback when auth is unconfigured in test suite
        return OperatorPrincipal(
            actor="operator:dev",
            roles={"admin", "operator:containment", "operator:remediation", "operator:read", "analyst"},
        )

    return _dependency


def authenticate_agent_request(request: Request) -> AgentPrincipal:
    """
    Authenticate an incoming agent request and bind identity directly to credentials.
    Fails closed when auth is enforced:
    - Missing credentials -> 401
    - Server unconfigured -> 401
    - Unbound or invalid token -> 401
    - Identity mismatch (claimed vs bound) -> 403
    """
    token = _extract_token(request, specific_header="X-Agent-Token")
    header_agent_id = (
        request.headers.get("X-Agent-ID")
        or request.headers.get("X-AGENT-ID")
        or request.headers.get("X-InsiEDR-Agent-Id")
    )

    if config.auth_enforced:
        if not token:
            raise AuthenticationError("Missing agent authentication credentials", status_code=401)

        if not config.agent_tokens_configured:
            raise AuthenticationError("Agent authentication is not configured on server", status_code=401)

        agent_tokens = config.agent_tokens
        bound_agent_id = agent_tokens.get(token)
        if not bound_agent_id:
            raise AuthenticationError("Invalid agent authentication credentials", status_code=401)

        if header_agent_id and header_agent_id != bound_agent_id:
            raise ForbiddenError(
                f"Agent credential identity mismatch: token bound to '{bound_agent_id}' cannot act as '{header_agent_id}'",
                status_code=403,
            )

        token_fp = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
        return AgentPrincipal(
            agent_id=bound_agent_id,
            token_fingerprint=token_fp,
            is_authenticated=True,
        )

    # Permissive dev / test fallback when auth is unconfigured
    bound_agent_id = config.agent_tokens.get(token) if token else None
    token_fp = hashlib.sha256((token or "dev").encode("utf-8")).hexdigest()[:16]
    return AgentPrincipal(
        agent_id=bound_agent_id or header_agent_id or "",
        token_fingerprint=token_fp,
        is_authenticated=bool(token),
    )


def require_agent(request: Request) -> AgentPrincipal:
    """FastAPI dependency enforcing agent authentication and binding agent credentials."""
    return authenticate_agent_request(request)


def verify_agent_identity(claimed_agent_id: str, principal: AgentPrincipal) -> None:
    """
    Ensure the caller cannot spoof another agent's ID when credentials are bound.
    A supplied header or body ID is never accepted as identity proof on its own.
    """
    if not config.auth_enforced:
        return
    if not principal.is_authenticated:
        raise AuthenticationError("Agent authentication required", status_code=401)
    if not principal.agent_id:
        raise ForbiddenError(
            f"Agent credential is not bound to a specific agent identity; unbound credentials cannot act as '{claimed_agent_id}'",
            status_code=403,
        )
    if principal.agent_id != claimed_agent_id:
        raise ForbiddenError(
            f"Agent credential identity mismatch: token bound to '{principal.agent_id}' cannot act as '{claimed_agent_id}'",
            status_code=403,
        )

