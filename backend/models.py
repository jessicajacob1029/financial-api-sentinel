"""Pydantic request/response schemas for the mock backend (doc 04 SS3)."""

from pydantic import BaseModel, ConfigDict, Field


class TokenRequest(BaseModel):
    client_id: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "DPoP"
    expires_in: int
    jti: str


class Account(BaseModel):
    id: str
    owner: str
    balance: float


class TransferRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_account: str = Field(alias="from")
    to_account: str = Field(alias="to")
    amount: float = Field(gt=0)


class TransferResponse(BaseModel):
    status: str
    reference: str
