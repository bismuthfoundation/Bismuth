# Basic ledger tests on regnet
# Run with: python3 -m pytest -v or pytest -v
# The regnet server is started by conftest.py

from time import sleep
from bismuthclient.bismuthclient import BismuthClient


def test_blocklast_json(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    data1 = client.command(command="blocklast")
    data2 = client.command(command="blocklastjson")
    assert (int(data1[0]) == data2['block_height']) and (data1[7] == data2['block_hash'])
