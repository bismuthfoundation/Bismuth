"""
This class is a config and helper for managing fork data in a single place.
"""

# from __future__ import annotations  # python3.7 only
from typing import TYPE_CHECKING
if TYPE_CHECKING:
  from libs.node import Node
  from libs.dbhandler import DbHandler


class Fork:
    def __init__(self):
        # TODO: explain and document use of these params.
        self.POW_FORK = 1450000
        self.POW_FORK_TESTNET = 894170
        self.FORK_AHEAD = 5
        self.versions_remove = ['mainnet0020', 'mainnet0019', 'mainnet0018', 'mainnet0017']
        self.FORK_REWARD = None
        self.FORK_REWARD_TESTNET = None
        self.PASSED = False
        self.PASSED_TESTNET = False
        self.REWARD_MAX = 6

        #self.POW_FORK = 1168860 #HACK
        #self.versions_remove = [] #HACK
        #self.REWARD_MAX = 5 #HACK

    def limit_version(self, node: "Node"):
        for allowed_version in node.config.version_allow:
            if allowed_version in self.versions_remove:
                node.logger.app_log.warning(f"Beginning to reject old protocol versions - block {node.last_block}")
                node.config.version_allow.remove(allowed_version)

    def check_postfork_reward(self, db_handler: "DbHandler"):
        # EGG_EVO: low level calls to migrate to db_handler
        # ram
        try:
            db_handler._execute_param(db_handler.c, "SELECT reward FROM transactions WHERE block_height = ? AND reward != 0", (self.POW_FORK + 1,))
            self.FORK_REWARD = db_handler.c.fetchone()[0]

        except:
            # hdd in case we have not saved yet
            db_handler._execute_param(db_handler.h, "SELECT reward FROM transactions WHERE block_height = ? AND reward != 0", (self.POW_FORK + 1,))
            self.FORK_REWARD = db_handler.h.fetchone()[0]

        if self.FORK_REWARD < self.REWARD_MAX:
            self.PASSED = True
        return self.PASSED

    def check_postfork_reward_testnet(self, db_handler: "DbHandler"):
        # EGG_EVO: low level calls to migrate to db_handler
        #ram
        try:
            db_handler._execute_param(db_handler.c, "SELECT reward FROM transactions WHERE block_height = ? AND reward != 0", (self.POW_FORK_TESTNET + 1,))
            self.FORK_REWARD_TESTNET = db_handler.c.fetchone()[0]
        except:
            #hdd in case we have not saved yet
            db_handler._execute_param(db_handler.h, "SELECT reward FROM transactions WHERE block_height = ? AND reward != 0", (self.POW_FORK_TESTNET + 1,))
            self.FORK_REWARD_TESTNET = db_handler.h.fetchone()[0]

        # print(type(self.FORK_REWARD_TESTNET)) # said <class 'float'>

        if self.FORK_REWARD_TESTNET < self.REWARD_MAX:
            self.PASSED_TESTNET = True
        return self.PASSED_TESTNET
