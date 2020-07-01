# Basic send test on regnet
import sys
sys.path.append("..") # Adds higher directory to python modules path.
import socks
import time
import json
from libs import connections
from bismuthclient.bismuthclient import BismuthClient


def generate_block(s):
    connections.send(s, "regtest_generate")
    connections.send(s, "1")
    print(connections.receive(s))
    time.sleep(1)  # Wait some time after block is generated


if __name__ == "__main__":
    # First mine a block so we get some funds
    s = socks.socksocket()
    s.settimeout(10)
    s.connect(("127.0.0.1", 3030))  # Port=3030 for regnet
    generate_block(s)

    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file='../datadir/wallet.der')
    print(f"My address is {client.address}")
    balance = client.balance(for_display=True)
    print(f"My Balance is {balance}")
    if True:
        test_address = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        txid = client.send(recipient=test_address, amount=1.0)  # Tries to send 1.0 to self
        print(f"Txid is {txid}")
        generate_block(s)
    client.clear_cache()
    balance = client.balance(for_display=True)
    print(f"My Balance is {balance}")
