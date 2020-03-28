"""Generic helper functions"""

from random import shuffle


def dict_shuffle(dictionary: dict) -> dict:
    my_list = list(dictionary.items())
    shuffle(my_list)
    return dict(my_list)
