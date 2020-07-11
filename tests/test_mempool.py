# Basic mempool tests on regnet
# Run with: python3 -m pytest -v or pytest -v
# The regnet server is started by conftest.py

from time import sleep
from bismuthclient.bismuthclient import BismuthClient


def test_mempool(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate",options=[1]) #Mine a block so we have some funds
    data = '123456789012345678901234567890'
    client.send(recipient=client.address, amount=1.0, data=data)
    tx = client.command(command="api_mempool") #Fetch the mempool
    client.command(command="regtest_generate",options=[1]) #Mine next block
    sleep(1)
    assert (float(tx[0][3]) == 1.0) and (tx[0][7] == data)

