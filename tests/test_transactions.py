# Basic transaction tests on regnet
# Run with: python3 -m pytest -v or pytest -v
# The regnet server is started by conftest.py

from time import sleep
from bismuthclient.bismuthclient import BismuthClient


def test_amount_and_recipient(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.send(recipient=client.address, amount=1.0)  # Tries to send 1.0 to self
    client.command(command="regtest_generate", options=[1])  # Mine the next block
    sleep(1)
    tx = client.latest_transactions(num=1)
    assert (float(tx[0]["amount"]) == 1.0) and (tx[0]["recipient"] == client.address)


def test_sender_and_recipient_balances(myserver):
    recipient = "8342c1610de5d7aa026ca7ae6d21bd99b1b3a4654701751891f08742"
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.clear_cache()

    balance_sender_before = float(client.balance())
    balance = client.command(command="balanceget", options=[recipient])
    balance_recipient_before = float(balance[0])

    client.send(recipient=recipient, amount=1.0)
    sleep(1)
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.clear_cache()

    tx = client.latest_transactions(num=2)
    balance_sender_after = float(client.balance())
    balance = client.command(command="balanceget", options=[recipient])
    balance_recipient_after = float(balance[0])
    diff1 = balance_sender_after - balance_sender_before - float(tx[1]["reward"]) + float(tx[0]["fee"])
    diff2 = balance_recipient_after - balance_recipient_before
    assert abs(diff1 + 1.0) < 1e-6 and (diff2 == 1.0)


def test_tx_id(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    txid = client.send(recipient=client.address, amount=1.0)  # Tries to send 1.0 to self
    client.command(command="regtest_generate", options=[1])  # Mine the next block
    sleep(1)
    tx = client.latest_transactions(num=1)
    assert tx[0]["signature"][:56] == txid


def test_operation_and_openfield(myserver):
    operation = "test:1"
    data = "Bismuth"
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.send(recipient=client.address, amount=0.0, operation=operation, data=data)
    client.command(command="regtest_generate", options=[1])  # Mine the next block
    sleep(1)
    tx = client.latest_transactions(num=1)
    assert (tx[0]["operation"] == operation) and (tx[0]["openfield"] == data)


def test_spend_entire_balance(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.clear_cache()
    balance = float(client.balance())
    fee = 0.01
    recipient = "8342c1610de5d7aa026ca7ae6d21bd99b1b3a4654701751891f08742"
    client.send(recipient=recipient, amount=balance-fee)
    client.command(command="regtest_generate", options=[1])  # Mine the next block
    sleep(1)
    client.clear_cache()
    balance = float(client.balance())
    tx = client.latest_transactions(num=2)
    assert abs(balance - float(tx[1]["reward"])) < 1e-6


def test_send_more_than_owned(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.clear_cache()
    balance = float(client.balance())
    recipient = "8342c1610de5d7aa026ca7ae6d21bd99b1b3a4654701751891f08742"
    client.send(recipient=recipient, amount=balance)
    client.command(command="regtest_generate", options=[1])  # Mine the next block
    sleep(1)
    client.clear_cache()
    balance = float(client.balance())
    assert (balance > 1.0)


def test_send_more_than_owned_in_two_transactions(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    client.clear_cache()
    balance = float(client.balance())
    recipient = "8342c1610de5d7aa026ca7ae6d21bd99b1b3a4654701751891f08742"
    client.send(recipient=recipient, amount=1.0)
    client.send(recipient=recipient, amount=balance-1.0)
    client.command(command="regtest_generate", options=[1])  # Mine the next block
    sleep(1)
    client.clear_cache()
    balance = float(client.balance())
    assert (balance > 1.0)

def test_fee(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate",options=[1]) #Mine a block so we have some funds
    data = '12345678901234567890123456789012345678901234567890'
    client.send(recipient=client.address, amount=0, data=data)
    client.command(command="regtest_generate",options=[1]) #Mine the next block
    sleep(1)
    tx = client.latest_transactions(num=1)
    assert float(tx[0]["fee"]) == 0.01 + 1e-5*len(data)

def test_operation_length(myserver):
    client = BismuthClient(servers_list={'127.0.0.1:3030'},wallet_file='../datadir/wallet.der')
    client.command(command="regtest_generate",options=[1]) #Mine a block so we have some funds
    operation = '123456789012345678901234567890'
    client.send(recipient=client.address, amount=0, operation=operation)
    operation = '1234567890123456789012345678901'
    client.send(recipient=client.address, amount=0, operation=operation)
    client.command(command="regtest_generate",options=[1]) #Mine the next block
    sleep(1)
    tx = client.latest_transactions(num=2)
    assert (len(tx[0]["operation"]) == 30) and (len(tx[1]["operation"]) == 1)
