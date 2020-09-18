"""
Debug - recalc a block hash
To be used for test vectors as well
"""

from time import time as ttime
from sys import argv
import os
import sys
from hashlib import sha224

# Bis specific modules
sys.path.append('../')
from libs import log
from libs.logger import Logger
from libs.config import Config
from libs.solodbhandler import SoloDbHandler

VERSION = "0.0.1-recalc"

# Will delete this block as well
BLOCK = 1865630
BLOCK = 1865804
# 14ec4f6ff6cfcbf8c788b8e9d71fec48af5a0c7e77fa144b97f98fad

# Legacy (True) or V2 (False)
LEGACY = False


if __name__ == "__main__":
    datadir = "../datadir"  # Default datadir if empty
    if len(argv) > 1:
        _, datadir = argv
        if not os.path.isdir(datadir):
            print("No such '{}' dir. Using default".format(datadir))
            datadir = "../datadir"
    print("Using", datadir, "data dir")
    if LEGACY:
        config = Config(datadir=datadir, force_legacy=True)
    else:
        config = Config(datadir=datadir, force_v2=True, wait=0)
    logger = Logger()
    logger.set_app_log(log.log("recalc.log", config.debug_level, config.terminal_output))
    try:
        solo_db_handler = SoloDbHandler(config=config, logger=logger)
        previous_hash = solo_db_handler.get_block_hash(BLOCK - 1)
        block = solo_db_handler.get_block(BLOCK)
        buffer = block.tx_list_for_hash()
        print(buffer)
        print("Previous", previous_hash)
        block_hash_bin = sha224((str(buffer) + previous_hash).encode("utf-8")).digest()
        block_hash = block_hash_bin.hex()
        stored_hash = solo_db_handler.get_block_hash(BLOCK)
        print(BLOCK, block_hash)
        print(BLOCK, "Stored", stored_hash)
    except Exception as e:
        logger.app_log.info(e)
        raise
