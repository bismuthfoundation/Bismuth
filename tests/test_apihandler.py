# apihandler tests on regnet
# Run with: python3 -m pytest -v or pytest -v
# The regnet server is started by conftest.py

import sys
from time import sleep
# from base64 import b64encode
sys.path.append('../')
from common import get_client
from bismuthcore.transaction import Transaction
from polysign.signerfactory import SignerFactory
import random


def random_address():
    return ''.join(random.choices("0123456789abcdef", k=56))


def test_api_ping(myserver, verbose=False):
    client = get_client(verbose=verbose)
    res = client.command(command="api_ping")
    if verbose:
        print(res)
    assert res == "api_pong"


def test_api_get_balance(myserver, verbose=False):
    # Random addresses so can be run several times, even with no regnet reset.
    recipient1 = random_address()
    recipient2 = random_address()
    client = get_client(verbose=False)
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.clear_cache()
    balance = client.command(command="api_getbalance", options=[[recipient1, recipient2], 1])
    if verbose:
        print(f"api_getbalance (before) returns {balance}")
    assert balance == 0
    client.send(recipient=recipient1, amount=1.0)
    client.send(recipient=recipient2, amount=2.0)
    sleep(1)
    client.command(command="regtest_generate", options=[2])  # Mine 2 blocks, so we have at 1 confirm after our insert
    client.clear_cache()
    balance = client.command(command="api_getbalance", options=[[recipient1, recipient2], 1])
    if verbose:
        print(f"api_getbalance (after) returns {balance}")
    assert balance == 3
    client.send(recipient=recipient1, amount=5.0)
    sleep(1)
    client.command(command="regtest_generate", options=[2])  # Mine 2 blocks, so we have at 1 confirm after our insert
    client.clear_cache()
    balance = client.command(command="api_getbalance", options=[[recipient1], 1])
    if verbose:
        print(f"api_getbalance (after2) returns {balance}")
    assert balance == 6
    balance = client.command(command="api_getbalance", options=[[recipient1], 2])
    if verbose:
        print(f"api_getbalance (after3) returns {balance}")
    assert balance == 1
    balance = client.command(command="api_listbalance", options=[[recipient1, recipient2], 1, True])
    if verbose:
        print(f"api_listbalance returns {balance}")
    assert len(balance.keys()) == 2
    assert balance[recipient1] == 6
    assert balance[recipient2] == 2


def test_api_get_received(myserver, verbose=False):
    # Random addresses so can be run several times, even with no regnet reset.
    recipient1 = random_address()
    recipient2 = random_address()
    client = get_client(verbose=False)
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.send(recipient=recipient1, amount=1.0)
    client.send(recipient=recipient2, amount=2.0)
    test = client.command(command="api_getreceived", options=[[recipient1, recipient2], 1])
    if verbose:
        print(f"api_getreceived (before) returns {test}")
    assert test == 0
    sleep(1)
    client.command(command="regtest_generate", options=[1])
    client.send(recipient=recipient1, amount=1.0)
    client.send(recipient=recipient2, amount=1.0)
    client.clear_cache()
    client.command(command="regtest_generate", options=[2])
    test = client.command(command="api_getreceived", options=[[recipient1, recipient2], 1])
    if verbose:
        print(f"api_getreceived (after) returns {test}")
    assert test == 5
    test = client.command(command="api_listreceived", options=[[recipient1, recipient2], 1, True])
    if verbose:
        print(f"api_listreceived (after) returns {test}")
    assert len(test.keys()) == 2
    assert test[recipient1] == 2
    assert test[recipient2] == 3


if __name__ == "__main__":
    test_api_ping(None, True)
    test_api_get_received(None, True)
    # test_amount_and_recipient(None, True)
    test_api_get_balance(None, True)
