"""

cmd for the addpeers command.

Adds new peers to a running node

Usage:

python3 cmd_addpeers.py ip:port

python3 cmd_addpeers.py ip:port,ip:port,ip:port

if port is omitted, 5658 will be used.
"""


import connections
import json
import socks
import sys


__version__ = "0.0.1"


def add_peers(peers: dict):
    s = socks.socksocket()
    s.settimeout(10)
    s.connect(("127.0.0.1", 5658))
    # Command first
    connections.send(s, "addpeers")
    # addpeers expects a string, that is a json encoded dict.
    connections.send(s, json.dumps(peers))
    res = connections.receive(s)
    return res


if __name__ == "__main__":
    _, peers_string = sys.argv
    peers = peers_string.split(',')
    peers_dict = {}
    for peer in peers:
        if ':' in peer:
            ip, port = peer.split(':')
        else:
            ip = peer
            port = '5658'
        peers_dict[ip] = port
    res_as_dict = add_peers(peers_dict)
    print("Answer (-1 means busy testing peers):")
    print(json.dumps(res_as_dict, indent=2))
