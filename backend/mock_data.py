"""Fake accounts and balances for the mock Open Banking backend."""

DEMO_CLIENT_ID = "demo-client"

ACCOUNTS = {
    "acc-checking-001": {"owner": DEMO_CLIENT_ID, "balance": 5000.0},
    "acc-savings-001": {"owner": DEMO_CLIENT_ID, "balance": 12000.0},
    "acc-external-001": {"owner": "other-client", "balance": 800.0},
}


def get_account(account_id: str) -> dict | None:
    return ACCOUNTS.get(account_id)


def apply_transfer(from_id: str, to_id: str, amount: float) -> None:
    ACCOUNTS[from_id]["balance"] -= amount
    ACCOUNTS[to_id]["balance"] += amount
