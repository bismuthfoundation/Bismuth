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
    assert len(data1[1]) > 0 and len(data1[2]) > 0 and \
           len(data1[1]) == len(data2['public_key']) and \
           len(data1[2]) == len(data2['address'])

def test_api_config(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    data = client.command(command="api_getconfig")
    assert data['regnet'] == True and data['port'] == 3030

def test_api_getaddresssince(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so that we have some funds
    client.send(recipient=client.address, amount=1.0)  # Tries to send 1.0 to self
    client.command(command="regtest_generate", options=[10])  # Mine 10 more blocks
    sleep(1)
    data2 = client.command(command="blocklastjson")
    since = data2['block_height'] - 10
    conf = 8
    data = client.command(command="api_getaddresssince", options=[since,conf,client.address])
    N = len(data['transactions'])
    assert N == 3

def test_api_getblockssince(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so that we have some funds
    data='1234567890'
    amount = 1.5
    client.send(recipient=client.address, amount=amount, data=data)  # Tries to send amount to self
    client.command(command="regtest_generate", options=[10])  # Mine 10 more blocks
    sleep(1)
    data2 = client.command(command="blocklastjson")
    since = data2['block_height'] - 10
    blocks = client.command(command="api_getblocksince", options=[since])
    N = len(blocks)
    assert N == 11 and blocks[0][11] == data and float(blocks[0][4]) == amount

def test_add_validate(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    data = client.command(command="addvalidate", options=[client.address])
    assert data == "valid"
