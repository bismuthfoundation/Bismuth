"""

cmd for the hn_reg_round command.


Usage:

python3 cmd_hn_reg_round.py round

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


def hn_reg_round(round: int, pow_height: int=0):
    s = socks.socksocket()
    s.settimeout(10)
    s.connect(("127.0.0.1", 5658))
    timestamp = ORIGIN_OF_TIME + round * ROUND_TIME_SEC
    # Last param is ip, to get feed of a specific ip, False for all.
    connections.send(s, "HN_reg_round {} {} {} False".format(round, timestamp, pow_height))
    res = connections.receive(s)
    return res


if __name__ == "__main__":
    _, round_string = sys.argv
    res_as_dict = hn_reg_round(int(round_string))
    print("Answer (<=0 means fail):")
    print(json.dumps(res_as_dict, indent=2))
