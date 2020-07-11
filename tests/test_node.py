# Basic node tests on regnet
# Run with: python3 -m pytest -v or pytest -v
# The regnet server is started by conftest.py

from time import sleep
from bismuthclient.bismuthclient import BismuthClient


def test_port_regnet(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    data = client.command(command="portget")
    assert int(data['port']) == 3030

def test_diff_json(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    data1 = client.command(command="difflast")
    data2 = client.command(command="difflastjson")
    block1 = data1[0]
    diff1 = data1[1]
    block2 = data2['block']
    diff2 = data2['difficulty']
    assert (block1 == block2) and (diff1 == diff2)

def test_keygen_json(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    data1 = client.command(command="keygen")
    data2 = client.command(command="keygenjson")
    assert len(data1[1]) == len(data2['public_key']) and \
           len(data1[2]) == len(data2['address'])
