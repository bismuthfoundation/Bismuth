# EGG: I see this as a class member of libs/Node
# It's the node background thread

import os
import sys
import threading
from time import time, sleep
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libs.node import Node
    # from libs.dbhandler import DbHandler
    from libs.mempool import Mempool


class NodeBackgroundThread (threading.Thread):
    def __init__(self, node: "Node", mempool: "Mempool"):
        threading.Thread.__init__(self, name="NodeBackgroundThread")
        self.node = node
        self.mempool = mempool

    def run(self) -> None:
        self.background_thread()

    def background_thread(self) -> None:
        self.node.logger.status_log.info("Starting Node background Thread")
        until_purge = 0
        tests = [0, 0, 0, 1, 0, 0, 2, 0, 0, 0]
        test_index = 0
        while not self.node.IS_STOPPING:
            # one loop every 30 sec
            try:
                # dict_keys = peer_dict.keys()
                # random.shuffle(peer_dict.items())
                if until_purge <= 0:
                    # will purge once at start, then about every half hour (60 * 30 sec)
                    self.mempool.purge()
                    until_purge = 60
                until_purge -= 1

                # peer management
                if not self.node.is_regnet:
                    # regnet never tries to connect
                    self.node.peers.client_loop(self.node, tests[test_index])
                    test_index += 1
                    if test_index >= len(tests):
                        test_index = 0
                self.node.logger.status_log.info(f"** Status: Threads at {threading.active_count()} "
                                                 f"/ {self.node.config.thread_limit} "
                                                 f"- {len(self.node.syncing)} Syncing nodes.")
                self.node.logger.status_log.debug(f"Syncing nodes: {self.node.syncing}")

                # Status display for Peers related info
                self.node.peers.print_status_log()
                self.mempool.status()
                # last block
                if self.node.last_block_ago:
                    self.node.last_block_ago = time() - int(self.node.last_block_timestamp)
                    self.node.logger.status_log.info(f"Last block {self.node.last_block} was generated "
                                                     f"{'%.2f' % (self.node.last_block_ago / 60) } minutes ago "
                                                     f"- End Status **")
                # status Hook
                uptime = int(time() - self.node.startup_time)
                status = {"protocolversion": self.node.config.version,
                          "walletversion": self.node.app_version,
                          "testnet": self.node.is_testnet,
                          # config data
                          "blocks": self.node.last_block,
                          "timeoffset": 0,
                          "connections": self.node.peers.consensus_size,
                          "difficulty": self.node.difficulty[0],  # live status, bitcoind format
                          "threads": threading.active_count(),
                          "uptime": uptime,
                          "consensus": self.node.peers.consensus,
                          "consensus_percent": self.node.peers.consensus_percentage,
                          "last_block_ago": self.node.last_block_ago}  # extra data
                if self.node.is_regnet:
                    status['regnet'] = True
                self.node.plugin_manager.execute_action_hook('status', status)
                # end status hook

                # logger.app_log.info(threading.enumerate() all threads)
                # time.sleep(30)
                for i in range(30):
                    # faster stop
                    if not self.node.IS_STOPPING:
                        sleep(1)
            except Exception as e:
                self.node.logger.app_log.warning(f"Error in NodeBackgroundThread ({e})")
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                self.node.close("Error NodeBackgroundThread")
