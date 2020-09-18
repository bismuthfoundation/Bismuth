"""
Debug - rollback a DB in single user mode.
"""

from time import time as ttime
from sys import argv
import os
import sys
from decimal import Decimal

# Bis specific modules
sys.path.append('../')
from libs import log
from libs.logger import Logger
from libs.config import Config
from libs.solodbhandler import SoloDbHandler

VERSION = "0.0.1-rollback"

# Will delete this block as well
UPTO_BLOCK = 1865629

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
    logger.set_app_log(log.log("rollback.log", config.debug_level, config.terminal_output))
    try:
        solo_db_handler = SoloDbHandler(config=config, logger=logger)
        solo_db_handler.rollback(UPTO_BLOCK)
    except Exception as e:
        logger.app_log.info(e)
        raise
