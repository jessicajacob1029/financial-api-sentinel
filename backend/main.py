"""Mock Open Banking backend (FastAPI).

The backend trusts that anything reaching it has passed the Sentinel proxy
once the proxy is in the path (Phase 2+), but still verifies the Bearer
token and DPoP proof itself so it is never "naked" (Build Spec SS2.6).

Phase 1 note: there is no proxy yet, so this is currently the only thing
standing between a request and the mock data -- full DPoP + token
verification happens here for every protected endpoint.
"""

import secrets
import time

from fastapi import FastAPI, Header, HTTPException, Request

from backend import auth, mock_data
from backend.models import Account, TokenRequest, TokenResponse, TransferRequest, TransferResponse
from proxy.dpop import validate_dpop

app = FastAPI(title="Financial API Sentinel - Mock Backend")


def _request_url(request: Request) -> str:
    return str(request.url)


@app.post("/oauth/token", response_model=TokenResponse)
def oauth_token(body: TokenRequest, request: Request, dpop: str = Header(...)):
    try:
        return auth.issue_token(body.client_id, dpop, _request_url(request))
    except auth.TokenIssuanceError:
        raise HTTPException(status_code=401, detail="unauthorized")


def _authenticate(request: Request, authorization: str, dpop: str) -> str:
    """Verify Bearer token + DPoP proof; return the token's subject (client_id)."""
    if not authorization.startswith("DPoP "):
        raise HTTPException(status_code=401, detail="unauthorized")
    access_token = authorization.removeprefix("DPoP ")

    try:
        claims = auth.verify_access_token(access_token)
    except auth.TokenValidationError:
        raise HTTPException(status_code=401, detail="unauthorized")

    dpop_result = validate_dpop(dpop, request.method, _request_url(request), int(time.time()))
    if not dpop_result.valid:
        raise HTTPException(status_code=401, detail="unauthorized")

    if dpop_result.jkt != claims.get("cnf", {}).get("jkt"):
        raise HTTPException(status_code=401, detail="unauthorized")

    return claims["sub"]


@app.get("/api/v1/accounts", response_model=list[Account])
def get_accounts(request: Request, authorization: str = Header(...), dpop: str = Header(...)):
    client_id = _authenticate(request, authorization, dpop)
    return [
        Account(id=acc_id, owner=data["owner"], balance=data["balance"])
        for acc_id, data in mock_data.ACCOUNTS.items()
        if data["owner"] == client_id
    ]


@app.post("/api/v1/transfer", response_model=TransferResponse)
def transfer(
    body: TransferRequest,
    request: Request,
    authorization: str = Header(...),
    dpop: str = Header(...),
):
    client_id = _authenticate(request, authorization, dpop)

    from_account = mock_data.get_account(body.from_account)
    if from_account is None or from_account["owner"] != client_id:
        raise HTTPException(status_code=403, detail="forbidden")

    to_account = mock_data.get_account(body.to_account)
    if to_account is None:
        raise HTTPException(status_code=400, detail="unknown destination account")

    if from_account["balance"] < body.amount:
        raise HTTPException(status_code=400, detail="insufficient funds")

    mock_data.apply_transfer(body.from_account, body.to_account, body.amount)

    return TransferResponse(status="ok", reference=f"txn-{secrets.token_hex(8)}")
