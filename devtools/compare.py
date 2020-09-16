"""
Convert tool
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

VERSION = "0.0.1-compare"

FROM_BLOCK = 1800000
FROM_BLOCK = 1865700

BALANCE_OF = "3e08b5538a4509d9daa99e01ca5912cda3e98a7f79ca01248c2bde16"
BALANCE_AT = 1865804

if __name__ == "__main__":
    datadir = "../datadir"  # Default datadir if empty
    if len(argv) > 1:
        _, datadir = argv
        if not os.path.isdir(datadir):
            print("No such '{}' dir. Using default".format(datadir))
            datadir = "../datadir"  # Default datadir if empty
    print("Using", datadir, "data dir")
    config_legacy = Config(datadir=datadir, force_legacy=True)
    logger = Logger()  # is that class really useful?
    logger.set_app_log(log.log("compare.log", config_legacy.debug_level, config_legacy.terminal_output))
    logger.app_log.warning("Legacy Configuration settings loaded")
    try:
        # EGG_EVO: Is this just used once for initial sync?
        # db_handler_initial = DbHandler.from_node(node)
        # node.node_block_init(db_handler_initial)  # Egg: to be called after single user mode only
        solo_db_handler = SoloDbHandler(config=config_legacy, logger=logger)
        if not solo_db_handler.tables_exist():
            logger.app_log.error("NO Legacy DB to compare")
            sys.exit()
    except Exception as e:
        logger.app_log.info(e)
        raise
    config_v2 = Config(datadir=datadir, force_v2=True, wait=0)
    logger.app_log.warning("V2 Configuration settings loaded")
    # EGG_EVO: SoloDbHandler expects a node, but only uses its .config and .logger properties.
    # As well have SoloDbHandler take config and logger, and avoid creating a node just for that.
    # node_v2 = Node(digest_block, config_v2,  app_version=VERSION, logger=logger, keys=keys.Keys(), run_checks=False)
    try:
        solo_db_handler2 = SoloDbHandler(config=config_v2, logger=logger)
        if not solo_db_handler2.tables_exist():
            logger.app_log.error("NO V2 DB to compare")
            sys.exit()
    except Exception as e:
        logger.app_log.info(e)
        raise
    # Get latest tx from target (can be null)
    start = solo_db_handler2.block_height_max()
    print("V2 Ledger last block is ", start)
    TO_BLOCK = start
    # sys.exit()
    start = FROM_BLOCK
    step = 1  # 100
    while True:
        print(start)
        # EGG: This is not optimized for speed, but only needed once (and users can bootstrap instead).
        test = str(solo_db_handler.get_blocks(start, step - 1).to_listoftuples(simplified=True))
        test2 = str(solo_db_handler2.get_blocks(start, step - 1).to_listoftuples(simplified=True))
        start += step
        if test != test2:
            print(test)
            print(test2)
            sys.exit()
        # print(test)
        if start > TO_BLOCK:
            break

    """
    balance = solo_db_handler.balance_at_height(BALANCE_OF, BALANCE_AT)
    balance2 = solo_db_handler2.balance_at_height(BALANCE_OF, BALANCE_AT)
    print("Hyper", balance, balance2 / 1E8)
    balance = solo_db_handler.balance_at_height(BALANCE_OF, BALANCE_AT, hyper=False)
    balance2 = solo_db_handler2.balance_at_height(BALANCE_OF, BALANCE_AT, hyper=False)
    print("Ledger", balance, balance2 / 1E8)

    balance = solo_db_handler.balance_at_height(BALANCE_OF, BALANCE_AT, hyper=False, include_debit=False)
    balance2 = solo_db_handler2.balance_at_height(BALANCE_OF, BALANCE_AT, hyper=False, include_debit=False)
    print("Ledger credits only", balance, balance2 / 1E8)
    balance = solo_db_handler.balance_at_height(BALANCE_OF, BALANCE_AT, hyper=False, include_credit=False)
    balance2 = solo_db_handler2.balance_at_height(BALANCE_OF, BALANCE_AT, hyper=False, include_credit=False)
    print("Ledger debits only", balance, balance2 / 1E8)
    """

    """
    res = solo_db_handler._ledger_cursor.execute(
        "SELECT block_height, amount, reward FROM transactions WHERE recipient = ? AND (block_height < ? AND block_height > ?) ORDER BY block_height DESC LIMIT 0,10",
        (BALANCE_OF, BALANCE_AT, -BALANCE_AT))
    credit = res.fetchall()
    print("CREDIT")
    print(credit)
    res = solo_db_handler._ledger_cursor.execute(
        "SELECT block_height, amount, fee FROM transactions WHERE address = ? AND (block_height < ? AND block_height > ?)  ORDER BY block_height DESC, timestamp DESC LIMIT 0,10",
        (BALANCE_OF, BALANCE_AT, -BALANCE_AT))
    debit = res.fetchall()
    print("DEBIT")
    print(debit)

    res = solo_db_handler2._ledger_cursor.execute(
        "SELECT block_height, amount, reward FROM transactions WHERE recipient = ? AND (block_height < ? AND block_height > ?) ORDER BY block_height DESC LIMIT 0,10",
        (BALANCE_OF, BALANCE_AT, -BALANCE_AT))
    credit = res.fetchall()
    print("CREDIT2")
    print(credit)
    res = solo_db_handler2._ledger_cursor.execute(
        "SELECT block_height, amount, fee FROM transactions WHERE address = ? AND (block_height < ? AND block_height > ?)  ORDER BY block_height DESC, timestamp DESC LIMIT 0,10",
        (BALANCE_OF, BALANCE_AT, -BALANCE_AT))
    debit = res.fetchall()
    print("DEBIT2")
    print(debit)
    """
