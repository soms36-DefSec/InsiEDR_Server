from __future__ import annotations

import inspect

import pytest
from fastapi import Request
from fastapi.routing import APIRoute

from server.api.analysis import router
from server.api.errors import AuthenticationError


def test_analysis_router_requires_operator_authentication(monkeypatch):
    monkeypatch.setenv("INSIEDR_AUTH_ENFORCED", "true")
    dependency = router.dependencies[0].dependency
    auth_routes = [route for route in router.routes if isinstance(route, APIRoute)]
    assert auth_routes
    assert all(
        any(item.call is dependency for item in route.dependant.dependencies)
        for route in auth_routes
    )
    request = Request({
        "type": "http", "method": "GET", "path": "/api/analysis",
        "headers": [], "query_string": b"",
    })
    with pytest.raises(AuthenticationError):
        dependency(request)


def _route_limit(route: APIRoute) -> int | None:
    parameter = next(p for p in inspect.signature(route.endpoint).parameters.values() if p.name == "limit")
    return next(item.le for item in parameter.default.metadata if hasattr(item, "le"))


def test_collection_routes_have_explicit_maximum_sizes():
    routes = {route.path: route for route in router.routes if isinstance(route, APIRoute)}
    assert _route_limit(routes["/api/user-risk-scores/{username}"]) == 500
    assert _route_limit(routes["/api/risk-events"]) == 500

    from server.api.agents import router as agents_router
    from server.api.logs import router as logs_router
    agent_routes = {route.path: route for route in agents_router.routes if isinstance(route, APIRoute)}
    log_routes = {route.path: route for route in logs_router.routes if isinstance(route, APIRoute)}
    assert _route_limit(log_routes["/api/logs"]) == 1000
    assert _route_limit(agent_routes["/api/agents"]) == 500
    assert _route_limit(agent_routes["/api/agents/{agent_id}/tasks"]) == 500
