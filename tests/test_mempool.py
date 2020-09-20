# Basic mempool tests on regnet
# Run with: python3 -m pytest -v or pytest -v
# The regnet server is started by conftest.py

from base64 import b64decode
from time import sleep

from bismuthclient.bismuthclient import BismuthClient


def test_mempool(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    data = '123456789012345678901234567890'
    client.send(recipient=client.address, amount=1.0, data=data)
    tx = client.command(command="api_mempool")  # Fetch the mempool
    client.command(command="regtest_generate", options=[1])  # Mine next block
    sleep(1)
    assert float(tx[0][3]) == 1.0
    assert tx[0][7] == data


def test_mpget_json(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.send(recipient=client.address, amount=1.0)  # Tries to send 1.0 to self
    data1 = client.command(command="mpget")
    data2 = client.command(command="mpgetjson")
    client.command(command="regtest_generate", options=[1])  # Mine next block
    sleep(1)
    # print("data1", data1[0][5])
    pubkey = b64decode(data1[0][5]).decode('utf-8').replace("\n", "")
    # print("pubkey", pubkey)
    # TODO: double check that output with stable release regnet
    # (precise pubkey format from mpgetjson)
    """
    mpgetjson seemed to send pubkey without boundaries, while other json answers gave the full string. 
    Where is this used? can we harmonize with no risk?
    Did not change the behaviour to ensure compatibility if this is important.
    """
    # print("data2", data2[0]['public_key'])
    i = pubkey.find(data2[0]['public_key'])

    assert data1[0][0] == data2[0]['timestamp']
    assert type(data2[0]['timestamp']) == str
    assert data1[0][1] == data2[0]['address']
    assert data1[0][2] == data2[0]['recipient']
    assert data1[0][3] == data2[0]['amount']
    assert data1[0][4] == data2[0]['signature']
    assert i > 0


if __name__ == "__main__":
    test_mempool(None)
    test_mpget_json(None)
