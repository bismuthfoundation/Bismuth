import socks
from libs import connections
from libs.config import Config

config = Config()
version = config.version


# EGG_EVO: dup with `commands.py stop`, I would remove it.
# Less files at first level, less troubles.

s = socks.socksocket()

port = 5658
if "testnet" in version:
    port = 2829
    print("tesnet mode")
elif "regnet" in version:
    is_regnet = True
    print("Regtest mode")
    port = 3030


while True:
    try:
        s.connect(("127.0.0.1", port))

        print("Sending stop command...")
        connections.send(s, "stop")
        print("Stop command delivered.")
        break
    except:
        print("Cannot reach node, retrying...")

s.close()
