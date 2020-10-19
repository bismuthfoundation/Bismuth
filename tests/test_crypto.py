# Basic crypto tests on regnet
# Run with: python3 -m pytest -v or pytest -v
# The regnet server is started by conftest.py

from common import get_client
from bismuthclient import bismuthcrypto

def test_ecdsa_dict(myserver, verbose=False):
    client = get_client(verbose=verbose)
    res = client.command(command="regtest_generate", options=[1])  # Mine a block so we have some funds
    ecdsa_priv_key = '82b6d896cbb1ac4d5af96cd43d4f391b1e6d73ce9b3ce29dd378730b22a952d2'
    signer = bismuthcrypto.ecdsa_pk_to_signer(ecdsa_priv_key)
    if verbose:
        print(f"signer contains {signer}")
    assert signer['type'] == 'ECDSA'
    assert 'test' in signer['address']
    assert signer['public_key'] == '035d3c145e518739f1e9b014ff00a5de2c8cd3478672f236ea13a07310d8a1a33a'


if __name__ == "__main__":
    test_ecdsa_dict(None, verbose=True)
