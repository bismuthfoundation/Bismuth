"""Generic helper functions"""

from random import shuffle
from hashlib import blake2b


def dict_shuffle(dictionary: dict) -> dict:
    my_list = list(dictionary.items())
    shuffle(my_list)
    return dict(my_list)


def blake2bhash_generate(data):
    blake2bhash = blake2b(str(data).encode(), digest_size=20).hexdigest()
    return blake2bhash
