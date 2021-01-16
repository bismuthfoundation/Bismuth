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


def test_api_balancelist(myserver, verbose=False):
    # Random addresses so can be run several times, even with no regnet reset.
    max = 100
    recipients = [random_address() for i in range(max)]
    client = get_client(verbose=False)
    client.command(command="regtest_generate", options=[max//10])  # Mine some blocks so we have funds
    for i in range(max):
        amount = (i+1)/100
        client.send(recipient=recipients[i], amount=amount)
        if i % 2 == 0:
            client.command(command="regtest_generate", options=[1])
    sleep(1)
    client.command(command="regtest_generate", options=[2])  # Mine 2 blocks, so we have 1 confirm after our insert
    client.clear_cache()
    client.verbose = verbose
    balance = client.command(command="api_balancelist", options=[1000])
    if verbose:
        print(f"api_balancelist returns {balance}")
        print(len(balance.keys()))
    hash = client.command(command="api_balancelisthash", options=[1000])
    if verbose:
        print(f"api_balancelisthash returns {hash}")


if __name__ == "__main__":
    test_api_balancelist(None, True)
