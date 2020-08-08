"""
Convert tool
"""

from time import time as ttime
from sys import argv
import os
import sys

# Bis specific modules
sys.path.append('../')
from libs import log
from libs.logger import Logger
from libs.config import Config
from libs.solodbhandler import SoloDbHandler

VERSION = "0.0.2-convert"

if __name__ == "__main__":
    datadir = "../datadir"  # Default datadir if empty
    if len(argv) > 1:
        _, datadir = argv
        if not os.path.isdir(datadir):
            print("No such '{}' dir. Using default".format(datadir))
            datadir = "../datadir"  # Default datadir if empty
    print("Using", datadir, "data dir")
    config_legacy = Config(datadir=datadir, force_legacy=True)  # config.read() is now implicit at instanciation
    logger = Logger()  # is that class really useful?
    logger.set_app_log(log.log("convert.log", config_legacy.debug_level, config_legacy.terminal_output))
    logger.app_log.warning("Configuration settings loaded")
    # Pre-node tweaks
    # wallet_file_name = config_legacy.get_wallet_path()
    # Will start node init sequence
    # Node instanciation is now responsible for lots of things that were previously done here or below
    # node_legacy = Node(digest_block, config_legacy,  app_version=VERSION, logger=logger, keys=keys.Keys(), run_checks=False)
    # logger.app_log.warning(f"Python version: {node_legacy.py_version}")
    try:
        # EGG_EVO: Is this just used once for initial sync?
        # db_handler_initial = DbHandler.from_node(node)
        # node.node_block_init(db_handler_initial)  # Egg: to be called after single user mode only
        solo_db_handler = SoloDbHandler(config=config_legacy, logger=logger)
        if not solo_db_handler.tables_exist():
            logger.app_log.error("NO Legacy DB to convert from")
            sys.exit()
    except Exception as e:
        logger.app_log.info(e)
        raise

    config_v2 = Config(datadir=datadir, force_v2=True, wait=0)
    # EGG_EVO: SoloDbHandler expects a node, but only uses its .config and .logger properties.
    # As well have SoloDbHandler take config and logger, and avoid creating a node just for that.
    # node_v2 = Node(digest_block, config_v2,  app_version=VERSION, logger=logger, keys=keys.Keys(), run_checks=False)
    try:
        solo_db_handler2 = SoloDbHandler(config=config_v2, logger=logger)
        if solo_db_handler2.tables_exist():
            logger.app_log.error("V2 DB already exists")
            # sys.exit()
        else:
            logger.app_log.error("Creating V2 DB")
            solo_db_handler2.create_db()
        start = 0
        # Get latest tx from target (can be null)
        start = solo_db_handler2.block_height_max()
        print("Ledger last block is ", start)
        # sys.exit()
        step = 1000
        while True:
            print(start)
            # EGG: This is not optimized for speed, but only needed once (and users can bootstrap instead).
            test = solo_db_handler.get_blocks(start, step - 1 )
            if len(test.transactions) == 0:
                break
            # insert is way longer if indices are there. so better add indices in a second step
            solo_db_handler2.blocks_to_ledger(test)
            start += step
        # TODO: fill up misc
        # Get latest height from target (can be null)
        start = solo_db_handler2.block_height_max_diff()
        if start < 231551:
            start = 231551
        print("Misc last block is ", start)
        # sys.exit()
        step = 1000
        end = solo_db_handler2.block_height_max()

        while True:
            print(start)
            # EGG: This is not optimized for speed, but only needed once (and users can bootstrap instead).
            test = solo_db_handler.get_miscs(start, step - 1)
            #print(test)
            if len(test) != 0:
                solo_db_handler2.miscs_to_ledger(test)
            if start > end:
                break
            # insert is way longer if indices are there. so better add indices in a second step
            start += step
    except Exception as e:
        logger.app_log.info(e)
        raise

    logger.status_log.info("Clean Stop")
    logger.status_log.warning("Please copy clean index.db from legacy to v2")
