import time

import pytest

from icp_agent.agent import Agent
from icp_agent.client import Client
from icp_candid.candid import Types, encode
from icp_identity.identity import Identity

CANISTER_ID_TEXT = "wcrzb-2qaaa-aaaap-qhpgq-cai"
# Ed25519 test vector (RFC 8032); used only for tests, not a real secret.
TEST_PRIVKEY_HEX = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"


@pytest.fixture(scope="session")
def ag() -> Agent:
    client = Client(url="https://ic0.app")
    iden = Identity(privkey=TEST_PRIVKEY_HEX)
    return Agent(iden, client)


def test_update_sync(ag):
    # Use verify_certificate=False to avoid requiring blst module (optional dependency)
    ret = ag.update(
        CANISTER_ID_TEXT,
        "set",
        [{"type": Types.Nat, "value": 2}],
        verify_certificate=False,
        return_type=[Types.Nat],
    )
    assert ret is not None


def test_query_sync(ag):
    ret = ag.query(CANISTER_ID_TEXT, "get", [])
    assert ret is not None