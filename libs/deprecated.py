"""Helpers that should not be used anymore"""

import hashlib
from Cryptodome.PublicKey import RSA


def rsa_key_generate():
    # generate key pair and an address
    key = RSA.generate(4096)
    private_key_readable = key.exportKey().decode("utf-8")
    public_key_readable = key.publickey().exportKey().decode("utf-8")
    address = hashlib.sha224(public_key_readable.encode("utf-8")).hexdigest()  # hashed public key
    return private_key_readable, public_key_readable, address
