# Common functions used in tests

def normalize_key(a):
    b = "-----BEGIN PUBLIC KEY-----\n"
    i = 0
    n = 64
    while i * n < len(a):
        b = b + a[i * n:(i + 1) * n] + '\n'
        i = i + 1
    b = b + "-----END PUBLIC KEY-----"
    return b
