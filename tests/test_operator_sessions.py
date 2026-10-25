from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from server.api.auth import router as auth_router
from server.api.deps import OperatorPrincipal, require_operator
from server.api.errors import register_error_handlers


def test_browser_session_authenticates_protected_routes_and_logout(monkeypatch):
    monkeypatch.setenv("INSIEDR_OPERATOR_API_KEY", "test-operator-secret")
    monkeypatch.setenv("INSIEDR_AUTH_ENFORCED", "true")
    monkeypatch.setenv("INSIEDR_ENVIRONMENT", "development")
    app = FastAPI()
    register_error_handlers(app)
    app.include_router(auth_router)

    @app.get("/protected")
    def protected(operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
        return {"actor": operator.actor}

    client = TestClient(app)
    assert client.get("/protected").status_code == 401

    invalid = client.post("/api/auth/session", json={"operator_key": "wrong"})
    assert invalid.status_code == 401

    login = client.post("/api/auth/session", json={"operator_key": "test-operator-secret"})
    assert login.status_code == 200
    assert "httponly" in login.headers["set-cookie"].lower()
    assert "samesite=strict" in login.headers["set-cookie"].lower()
    assert client.get("/protected").status_code == 200

    logout = client.delete("/api/auth/session")
    assert logout.status_code == 200
    assert client.get("/protected").status_code == 401
