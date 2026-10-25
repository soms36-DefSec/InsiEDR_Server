"""Browser session endpoints for the operator dashboard."""
from __future__ import annotations

import hmac
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from server.api.operator_sessions import COOKIE_NAME, SESSION_SECONDS, issue_session, resolve_session
from server.config import config

router = APIRouter(prefix="/api/auth", tags=["Operator Authentication"])


class OperatorLoginRequest(BaseModel):
    operator_key: str = Field(min_length=1, max_length=4096)


def _valid_operator_key(token: str) -> bool:
    roles = config.operator_roles
    if token in roles:
        return True
    return bool(config.operator_api_key and hmac.compare_digest(
        token.encode("utf-8"), config.operator_api_key.encode("utf-8")
    ))


@router.get("/session")
def get_operator_session(request: Request):
    if not config.auth_enforced:
        return {"authenticated": True, "auth_required": False}
    session = resolve_session(request.cookies.get(COOKIE_NAME))
    if not session:
        return {"authenticated": False, "auth_required": True}
    return {"authenticated": True, "auth_required": True, "expires_at": session[1]}


@router.post("/session")
def create_operator_session(body: OperatorLoginRequest, response: Response):
    if not _valid_operator_key(body.operator_key):
        raise HTTPException(status_code=401, detail="Invalid operator credentials")
    session, _expires_at = issue_session(body.operator_key)
    response.set_cookie(
        COOKIE_NAME,
        session,
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=config.is_production,
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "auth_required": config.auth_enforced}


@router.delete("/session")
def delete_operator_session(response: Response):
    response.delete_cookie(
        COOKIE_NAME,
        httponly=True,
        secure=config.is_production,
        samesite="strict",
        path="/",
    )
    return {"authenticated": not config.auth_enforced, "auth_required": config.auth_enforced}
