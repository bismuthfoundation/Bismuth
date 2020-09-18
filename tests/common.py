# Common functions used in tests
# TODO: benchmark both, see use in polysign, signer_rsa (then take from there, class method)


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
