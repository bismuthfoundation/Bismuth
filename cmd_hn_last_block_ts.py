"""

test cmd for the hn_last_block_ts command.


Usage:

python3 cmd_hn_last_block_ts

"""


import connections
import json
import socks
import sys


__version__ = "0.0.1"


ORIGIN_OF_TIME = 1534716000  # Real Origin: August 20
POS_SLOT_TIME_MIN = 3  # Real world setting?
POS_SLOT_TIME_SEC = POS_SLOT_TIME_MIN * 60
MAX_ROUND_SLOTS = 19  # Real world. 19+1 = 20 , 3x20 = 60 (round time)
END_ROUND_SLOTS = 1
# Round time in seconds
ROUND_TIME_SEC = POS_SLOT_TIME_SEC * (MAX_ROUND_SLOTS + END_ROUND_SLOTS)


def hn_last_block_ts():
    s = socks.socksocket()
    s.settimeout(10)
    s.connect(("127.0.0.1", 5658))
    # Last param is ip, to get feed of a specific ip, False for all.
    connections.send(s, "HN_last_block_ts")
    res = connections.receive(s)
    return res


if __name__ == "__main__":
    res_as_dict = hn_last_block_ts()
    print("Answer (<=0 means fail):")
    print(json.dumps(res_as_dict, indent=2))
