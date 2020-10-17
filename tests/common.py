# Common functions used in tests
# TODO: benchmark both, see use in polysign, signer_rsa (then take from there, class method)

from bismuthclient.bismuthclient import BismuthClient
from os.path import isfile

def normalize_key(a):
    b = "-----BEGIN PUBLIC KEY-----\n"
    i = 0
    n = 64
    while i * n < len(a):
        b = b + a[i * n:(i + 1) * n] + '\n'
        i = i + 1
    b = b + "-----END PUBLIC KEY-----"
    return b


def normalize_key_alt(s: str) -> str:
    chunks = [s[i:i+64] for i in range(0, len(s), 64)]
    chunks.insert(0, "-----BEGIN PUBLIC KEY-----")
    chunks.append("-----END PUBLIC KEY-----")
    return "\n".join(chunks)


def get_client(verbose: bool=False):
    # Helper to get a working and conencted BismuthClient no matter the test context
    file_first = "../datadir/wallet.der"
    file_second = "../wallet.der"
    wallet_file =  file_first if isfile(file_first) else file_second
    client = BismuthClient(servers_list={'127.0.0.1:3030'}, wallet_file=wallet_file, verbose=verbose)
    # Will raise and fail test if node is not connectible
    assert client is not None
    return client
