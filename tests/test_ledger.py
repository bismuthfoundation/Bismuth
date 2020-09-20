# Basic ledger tests on regnet
# Run with: python3 -m pytest -v or pytest -v
# The regnet server is started by conftest.py

from time import sleep
from bismuthclient.bismuthclient import BismuthClient
from hashlib import sha224


def test_blocklast_json(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    data1 = client.command(command="blocklast")
    data2 = client.command(command="blocklastjson")
    # note: better split the asserts, one by line, so when it errors we have the why and value
    assert int(data1[0]) == data2['block_height']
    assert type(data2['block_height']) == int
    assert data1[7] == data2['block_hash']
    assert type(data2['block_hash']) == str


def test_balance_json(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    data1 = client.command(command="balanceget", options=[client.address])
    data2 = client.command(command="balancegetjson", options=[client.address])
    assert data1[0] == data2['balance']
    assert data1[1] == data2['credit']
    assert data1[2] == data2['debit']
    assert data1[3] == data2['fees']
    assert data1[4] == data2['rewards']
    assert data1[5] == data2['balance_no_mempool']


def test_addlistlim_json(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    op = '12345'
    data = '67890'
    client.send(recipient=client.address, amount=1.0, operation=op, data=data)
    client.command(command="regtest_generate", options=[1])  # Mine the next block
    sleep(1)
    data1 = client.command(command="addlistlim", options=[client.address, 1])
    data2 = client.command(command="addlistlimjson", options=[client.address, 1])
    assert data1[0][0] == data2[0]['block_height']
    assert data1[0][1] == data2[0]['timestamp']
    assert type(data2[0]['timestamp']) == str
    assert data1[0][2] == data2[0]['address']
    assert data1[0][3] == data2[0]['recipient']
    assert data1[0][4] == data2[0]['amount']
    assert data1[0][5] == data2[0]['signature']
    assert data1[0][6] == data2[0]['public_key']
    assert data1[0][7] == data2[0]['block_hash']
    assert data1[0][8] == data2[0]['fee']
    assert data1[0][9] == data2[0]['reward']
    assert data1[0][10] == data2[0]['operation']
    assert data1[0][11] == data2[0]['openfield']
    assert data1[0][10] == op
    assert data1[0][11] == data


def test_api_getblockfromhash(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.send(recipient=client.address, amount=1.0, operation='12345', data='67890')
    client.command(command="regtest_generate", options=[1])  # Mine the next block
    sleep(1)
    data1 = client.command(command="addlistlimjson", options=[client.address, 1])
    block_hash = data1[0]['block_hash']
    data2 = client.command(command="api_getblockfromhash", options=[block_hash])
    block_height = str(data1[0]['block_height'])
    n = len(data2[block_height]['transactions'])
    # note: better split the asserts, one by line, so when it errors we have the why and value
    assert type(block_hash) == str
    assert data2[block_height]['block_hash'] == block_hash
    assert n == 2


def test_db_blockhash(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[2])  # Mine two blocks
    sleep(1)
    data = client.command(command="blocklastjson")
    since = data['block_height'] - 2
    r = client.command(command="api_getblocksince", options=[since])
    db_block_hash_prev = r[0][7]
    db_block_hash = r[1][7]

    amount = '0.00000000'
    timestamp = f"{float(r[1][1]):.2f}"  # prefer to python2 style %
    tx_list = []
    tx_list.append((timestamp, r[1][2], r[1][3], amount, r[1][5], r[1][6], r[1][10], r[1][11]))
    block_hash = sha224((str(tx_list) + db_block_hash_prev).encode("utf-8")).hexdigest()
    assert db_block_hash == block_hash
    assert type(db_block_hash) == str


if __name__ == "__main__":
    test_blocklast_json(None)
    test_balance_json(None)
    test_addlistlim_json(None)
    test_api_getblockfromhash(None)
    test_db_blockhash(None)
