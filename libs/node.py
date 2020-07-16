"""
WIP - Core class handling the Bismuth node.
"""

import threading
import queue
import glob
import os
import tarfile
import sys
from sys import exc_info
import platform
from time import sleep, time as ttime
from shutil import copy
from math import floor

from libs import mining_heavy3, regnet
from bismuthcore.helpers import just_int_from, download_file
from libs.essentials import keys_check, keys_load_new  # To be handled by polysign
from libs.difficulty import difficulty  # where does this belongs? check usages

from libs.config import Config
from libs.solodbhandler import SoloDbHandler
from libs.apihandler import ApiHandler
from libs.peershandler import Peers
from libs.pluginmanager import PluginManager
from libs import mempool as mp

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from libs.dbhandler import DbHandler


__version__ = "0.0.15"


class Node:

    # Slots to enforce immutable properties names
    __slots__ = ("py_version", "linux", "IS_STOPPING", "app_version", "startup_time", "last_block_timestamp",
                 "last_block_ago", "difficulty", "ledger_temp", "hyper_temp", "recompress", "peerfile",
                 "ledger_ram_file", "index_db", "peerfile_suggested", "config", "logger", "keys", "plugin_manager",
                 "apihandler", "db_lock", "q", "is_testnet", "is_regnet", "is_mainnet", "hdd_block", "hdd_hash",
                 "last_block_hash", "last_block", "peers", "syncing", "checkpoint", "digest_block", "ram_db")

    def __init__(self, digest_block, config: Config=None, app_version: str="", logger=None, keys=None, run_checks=True):
        # TODO EGG: digest_block will need to be integrated in this class.
        # current hack necessary to avoid circular references.
        self.py_version = int(str(sys.version_info.major) + str(sys.version_info.minor) + str(sys.version_info.micro))
        self.linux = "Linux" in platform.system()
        # temp
        self.digest_block = digest_block
        # core flags
        self.IS_STOPPING = False
        # core properties
        self.app_version = app_version
        self.startup_time = None
        self.last_block_timestamp = None
        self.last_block_ago = None
        self.difficulty = None
        self.ledger_temp = None
        self.hyper_temp = None
        self.recompress = False
        self.hdd_block = None  # in ram mode, this differs from node.last_block
        self.hdd_hash = None  # in ram mode, this differs from node.last_block_hash
        self.last_block_hash = None  # in ram mode, this differs from node.hdd_hash
        self.last_block = None  # in ram mode, this differs from node.hdd_block
        self.peers = None
        self.syncing = []
        self.checkpoint = 0

        # default mainnet config
        self.peerfile = config.get_file_path("live", "peers.txt")
        self.ledger_ram_file = "file:ledger?mode=memory&cache=shared"
        self.ram_db = None
        self.index_db = config.get_index_db_path(config.legacy_db)
        self.peerfile_suggested = config.get_file_path("live", "suggested_peers.txt")

        # core objects and structures
        self.config = config
        self.logger = logger
        self.keys = keys

        self.plugin_manager = None
        self.apihandler = None
        self.db_lock = threading.Lock()
        self.q = queue.Queue()

        # startup sequence

        # Net type
        self.is_testnet = False
        self.is_regnet = False
        self.is_mainnet = True
        self._setup_net_type()
        self.load_keys()

        # Migrated all "single mode" methods from top level node.py in there
        if run_checks:
            self.single_user_checks()
        else:
            self.logger.app_log.warning("Warning: Node was instanciated without startup checks. "
                                        "Make sure you know what you are doing!!")
        # create a plugin manager, load all plugin modules and init
        self.plugin_manager = PluginManager(app_log=self.logger.app_log, config=self.config, init=True)
        # Egg: kept the detailled params instead of just "Node" so the plugin handler
        # remains generic outside of Node context.
        self.peers = Peers(self)
        self.apihandler = ApiHandler(self)

    def _setup_net_type(self):
        """
        Adjust node properties depending on mainnet, testnet or regnet config
        """
        self.logger.app_log.warning("Node init: Entering Net Type Setup")
        if "testnet" in self.config.version:
            self.is_testnet = True
            self.is_mainnet = False
            self.config.version_allow = "testnet"
            self.logger.app_log.warning("Testnet Mode")
            self.config.port = 2829
            # config helpers now take care of that
            # self.config.hyper_path = "static/hyper_test .db"
            # self.config.ledger_path = "static/ledger_test .db"

            self.ledger_ram_file = "file:ledger_testnet?mode=memory&cache=shared"
            self.peerfile = self.config.get_file_path("live", "peers_test.txt")
            self.peerfile_suggested = self.config.get_file_path("live", "suggested_peers_test.txt")

            self.index_db = self.config.get_index_db_path()

            redownload_test = input("Status: Welcome to the testnet. Redownload test ledger? y/n")
            if redownload_test == "y":
                types = [self.config.get_file_path("testnet", 'ledger_test.db-wal'),
                         self.config.get_file_path("testnet", 'ledger_test.db-shm'),
                         self.config.get_file_path("testnet", 'index_test.db'),
                         self.config.get_file_path("testnet", 'hyper_test.db-wal'),
                         self.config.get_file_path("testnet", 'hyper_test.db-shm')]
                for dbtype in types:
                    for file in glob.glob(dbtype):
                        os.remove(file)
                        print(file, "deleted")
                download_file("https://bismuth.cz/test.tar.gz", self.config.get_file_path("testnet", "test.tar.gz"))
                with tarfile.open(self.config.get_file_path("testnet", "test.tar.gz")) as tar:
                    tar.extractall(self.config.get_file_path("testnet", ""))
            else:
                print("Not redownloading test db")

        elif "regnet" in self.config.version:
            self.is_regnet = True
            self.is_testnet = False
            self.is_mainnet = False
            self.logger.app_log.warning("Regnet Mode")

            self.config.port = regnet.REGNET_PORT
            # Now taken care of by config
            # self.config.hyper_path = regnet.REGNET_DB
            # self.config.ledger_path = regnet.REGNET_DB
            self.ledger_ram_file = "file:ledger_regnet?mode=memory&cache=shared"
            self.peerfile = "peers_reg.txt"
            self.peerfile_suggested = "peers_reg.txt"

            self.config.hyper_recompress = False
            # self.index_db = regnet.REGNET_INDEX
            self.logger.app_log.warning("Regnet init...")
            regnet.REGNET_DB = self.config.ledger_path
            regnet.REGNET_INDEX = self.config.get_index_db_path()
            regnet.init(self, self.logger.app_log)
            mining_heavy3.is_regnet = True
        else:
            self.logger.app_log.warning("Mainnet Mode")
            # Allow only 21 and up
            if self.config.version != 'mainnet0021':
                self.config.version = 'mainnet0021'  # Force in code.
            if "mainnet0021" not in self.config.version_allow:
                self.config.version_allow = ['mainnet0021', 'mainnet0022']
            # Do not allow bad configs.
            if 'mainnet' not in self.config.version:
                self.close("Bad mainnet version, check config.txt", force_exit=True)
            num_ver = just_int_from(self.config.version)
            if num_ver < 21:
                # This can't happen since we forced to 21 above, but kept anyway in case of a future change.
                self.close("Too low mainnet version, check config.txt", force_exit=True)
            for allowed in self.config.version_allow:
                num_ver = just_int_from(allowed)
                if num_ver < 20:
                    self.close("Too low allowed version, check config.txt", force_exit=True)

    def close(self, message: str="", force_exit: bool=False):
        """Terminate the node, with an optional message.
        if force_exit is True, will call sys.exit(), else it will just raise its flag
        and wait for the main loop to terminate."""
        if message != '':
            self.logger.app_log.error(message)
        self.IS_STOPPING = True
        mining_heavy3.mining_close()
        if force_exit:
            sys.exit()

    def sleep(self) -> None:
        """Pause the current thread for the configured time to avoid cpu loads while in waiting loops"""
        sleep(self.config.pause)

    def load_keys(self):
        """Initial loading of crypto keys"""
        keys_check(self.logger.app_log, self.config.get_wallet_path())  # will create a wallet if none exist.
        """
        self.keys.key, self.keys.public_key_readable, self.keys.private_key_readable, _, _, \
            self.keys.public_key_b64encoded, self.keys.address, self.keys.keyfile \
            = keys_load("privkey.der", "pubkey.der")
        """
        self.keys.key, self.keys.public_key_readable, self.keys.private_key_readable, _, _, \
            self.keys.public_key_b64encoded, self.keys.address, self.keys.keyfile = \
            keys_load_new(self.config.get_wallet_path())
        if self.is_regnet:
            regnet.PRIVATE_KEY_READABLE = self.keys.private_key_readable
            regnet.PUBLIC_KEY_B64ENCODED = self.keys.public_key_b64encoded
            regnet.ADDRESS = self.keys.address
            regnet.KEY = self.keys.key
        self.logger.app_log.warning(f"Status: Local address: {self.keys.address}")

    def bootstrap(self):
        # EGG_EVO: Temp hack preventing deleting local DB at this dev stage.
        # stops the node dead on. To be commented out for prod
        self.close("Bootstrap was triggered, but is disabled by safety. Node will close.", force_exit=True)
        return

        self.logger.app_log.warning("Something went wrong during bootstrapping, aborted")
        try:
            # EGG_EVO: take care of these hardcoded paths and use datadir
            types = ['static/*.db-wal', 'static/*.db-shm']
            for t in types:
                for f in glob.glob(t):
                    os.remove(f)
                    print(f, "deleted")

            archive_path = self.config.ledger_path + ".tar.gz"
            download_file("https://bismuth.cz/ledger.tar.gz", archive_path)

            with tarfile.open(archive_path) as tar:
                tar.extractall("static/")  # NOT COMPATIBLE WITH CUSTOM PATH CONFS
        except:
            self.logger.app_log.warning("Something went wrong during bootstrapping, aborted")
            raise

    def _check_db_schema(self, solo_handler: SoloDbHandler):
        # Was named "check_integrity". It was rather a crude db schema check,
        # will need adjustments to handle the various possible dbs.
        # some parts below also where in "initial_db_check()" but also are schema checks. merged into here
        #if not os.path.exists("static"):
        #    os.mkdir("static")
        redownload = False
        # force bootstrap via adding an empty "fresh_sync" file in the dir.
        if os.path.exists("fresh_sync") and self.is_mainnet:
            self.logger.app_log.warning("Status: Fresh sync required, bootstrapping from the website")
            os.remove("fresh_sync")
            redownload = True
        try:
            ledger_schema = solo_handler.transactions_schema()
            print(ledger_schema, len(ledger_schema))
            if len(ledger_schema) != 12:
                # EGG_EVO: Kept this test for the time being, but will need more complete and distinctive test
                # depending on the db type
                self.logger.app_log.error(
                    f"Status: Integrity check on ledger failed, bootstrapping from the website")
                redownload = True
            command_field_type = ledger_schema[10][2]
            if command_field_type != "TEXT":
                redownload = True
                self.logger.app_log.error("Database column type outdated for Command field")
        except:
            redownload = True
        if redownload and self.is_mainnet:
            self.bootstrap()

    def _ledger_check_heights(self, solo_handler: SoloDbHandler) -> None:
        if self.is_regnet:
            return
        """Defines whether ledger needs to be compressed to hyper"""
        if os.path.exists(self.config.hyper_path):
            # cross-integrity check
            hdd_block_max = solo_handler.block_height_max()
            hdd_block_max_diff = solo_handler.block_height_max_diff()
            hdd2_block_last = solo_handler.block_height_max_hyper()
            hdd2_block_last_misc = solo_handler.block_height_max_diff_hyper()
            # cross-integrity check
            if hdd_block_max == hdd2_block_last == hdd2_block_last_misc == hdd_block_max_diff \
                    and self.config.hyper_recompress:  # cross-integrity check
                self.logger.app_log.warning("Status: Recompressing hyperblocks (keeping full ledger)")
                self.recompress = True
                # print (hdd_block_max,hdd2_block_last,node.config.hyper_recompress)
            elif hdd_block_max == hdd2_block_last and not self.config.hyper_recompress:
                self.logger.app_log.warning("Status: Hyperblock recompression skipped")
                self.recompress = False
            else:
                lowest_block = min(hdd_block_max, hdd2_block_last, hdd_block_max_diff, hdd2_block_last_misc)
                highest_block = max(hdd_block_max, hdd2_block_last, hdd_block_max_diff, hdd2_block_last_misc)
                self.logger.app_log.warning(
                    f"Status: Cross-integrity check failed, {highest_block} will be rolled back below {lowest_block}")
                solo_handler.rollback(lowest_block)  # rollback to the lowest value
                self.recompress = False
        else:
            self.logger.app_log.warning("Status: Compressing ledger to Hyperblocks")
            self.recompress = True

    def _recompress_ledger_prepare(self, rebuild: bool=False) -> None:
        """Aggregates transactions and compress old ledger entries into hyper blocks"""
        self.logger.app_log.warning(f"Status: Recompressing, please be patient...")

        files_remove = [self.config.ledger_path + '.temp', self.config.ledger_path + '.temp-shm',
                        self.config.ledger_path + '.temp-wal']
        for file in files_remove:
            if os.path.exists(file):
                os.remove(file)
                self.logger.app_log.warning(f"Removed old {file}")

        # We start from either ledger or current hyper as data base, then work on hyper only.
        if not os.path.isfile(self.config.hyper_path):
            # Force rebuild if there is no hyper.
            rebuild = True
        if rebuild:
            self.logger.app_log.warning(f"Status: Hyperblocks will be rebuilt")
            copy(self.config.ledger_path, self.config.ledger_path + '.temp')
        else:
            copy(self.config.hyper_path, self.config.ledger_path + '.temp')
        self.logger.app_log.warning(f"recompress_ledger_prepare done")

    def _recompress_ledger(self, solo_handler: SoloDbHandler, depth: int = 15000) -> None:
        solo_handler.prepare_hypo()  # avoid double processing by renaming Hyperblock addresses to Hypoblock
        self.logger.app_log.warning(f"Recompress: Opening temp db and adding indices...")
        solo_handler.open_temp_hyper()  # Use ledger.db.temp as temp. hyper, adding indices if needed
        db_block_height = solo_handler.block_height_max_hyper()
        depth_specific = db_block_height - depth
        self.logger.app_log.warning(f"Recompress: Block height {db_block_height}, depth_specific {depth_specific}")
        # Now gather all active addresses
        self.logger.app_log.warning(f"Gathering addresses...")
        unique_addressess = solo_handler.distinct_hyper_recipients(depth_specific)
        for address in unique_addressess:
            solo_handler.update_hyper_balance_at_height(address, depth_specific)
        """
        
        Looks like sqlite3 aggregates by block, then pickups the right address.
        Would be faster doing it for all addresses at once.
        Do more tests. Test on freshly converted ledger (no prior hyper) so all is compressible.
        
        explain query plan SELECT sum(amount + reward) FROM transactions WHERE recipient = "4b35e6dc26850d5f52c9e75ac28e22566f0e90dd25d953553079cd65" AND (block_height < 1000000 AND block_height > -1000000);
        0|0|0|SEARCH TABLE transactions USING INDEX Block Height Index (block_height>? AND block_height<?)
        
        explain SELECT sum(amount + reward) FROM transactions WHERE recipient = "4b35e6dc26850d5f52c9e75ac28e22566f0e90dd25d953553079cd65" AND (block_height < 1000000 AND block_height > -1000000);
        0|Init|0|23|0||00|
        1|Null|0|1|3||00|
        2|OpenRead|0|2|0|10|00|
        3|OpenRead|1|3|0|k(2,nil,nil)|00|
        4|Integer|-1000000|4|0||00|
        5|SeekGT|1|17|4|1|00|
        6|Integer|1000000|4|0||00|
        7|IdxGE|1|17|4|1|00|
        8|IdxRowid|1|5|0||00|
        9|Seek|0|5|0||00|
        10|Column|0|3|6||00|
        11|Ne|7|16|6|(BINARY)|52|
        12|Column|0|4|9||00|
        13|Column|0|9|10||00|
        14|Add|10|9|8||00|
        15|AggStep|0|8|1|sum(1)|01|
        16|Next|1|7|0||00|
        17|Close|0|0|0||00|
        18|Close|1|0|0||00|
        19|AggFinal|1|1|0|sum(1)|00|
        20|Copy|1|11|0||00|
        21|ResultRow|11|1|0||00|
        22|Halt|0|0|0||00|
        23|Transaction|0|0|4|0|01|
        24|TableLock|0|2|0|transactions|00|
        25|String8|0|7|0|4b35e6dc26850d5f52c9e75ac28e22566f0e90dd25d953553079cd65|00|
        26|Goto|0|1|0||00|
        
        
        Avec index recipient:
        explain query plan SELECT sum(amount + reward) FROM transactions WHERE recipient = "4b35e6dc26850d5f52c9e75ac28e22566f0e90dd25d953553079cd65" AND (block_height < 1000000 AND block_height > -1000000);
        0|0|0|SEARCH TABLE transactions USING INDEX Recipient Index (recipient=?)
        
        the more the tx, the slower.

        """

        solo_handler.hyper_commit()
        solo_handler.cleanup_hypo(depth_specific)
        solo_handler.close()

        if os.path.exists(self.config.hyper_path):
            os.remove(self.config.hyper_path)  # remove the old hyperblocks to rebuild
        if os.path.exists(self.config.ledger_path + '.temp'):
            os.rename(self.config.ledger_path + '.temp', self.config.hyper_path)
        self.logger.app_log.warning(f"Status: Recompressed!")
        # sys.exit()  # Temp

    def _ram_init(self, solo_handler: SoloDbHandler) -> None:
        # Copy hyper db into ram
        if not self.config.ram:
            # Early exit to limit indents
            self.ram_db = None
            return
        try:
            self.logger.app_log.warning("Status: Moving database to RAM")
            self.ram_db = solo_handler.db_to_ram(self.config.hyper_path, self.ledger_ram_file)
            self.logger.app_log.warning("Status: Hyperblock ledger moved to RAM")
        except Exception as e:
            self.logger.app_log.warning("Move to ram: {}".format(e))
            raise

    def node_block_init(self, db_handler: "DbHandler") -> None:
        """Init node heights properties from db"""
        # EGG_EVO: we could maybe delay this part until we have the final db_handler, in order to avoid dupped methods.
        # Check if these properties are of use or not in the following single user mode calls.
        self.logger.app_log.warning("Status: Starting Node blocks init...")
        self.hdd_block = db_handler.block_height_max()
        self.difficulty = difficulty(self, db_handler)  # check diff for miner
        print("Current difficulty", self.difficulty)
        self.last_block = self.hdd_block  # ram equals drive at this point

        self.last_block_hash = db_handler.last_block_hash()  # dup
        self.hdd_hash = self.last_block_hash  # ram equals drive at this point
        self.last_block_timestamp = db_handler.last_block_timestamp()  # dup

        self.checkpoint_set()
        self.logger.app_log.warning("Status: Indexing aliases")
        db_handler.aliases_update()

    def single_user_checks(self) -> None:
        """Called at instanciation time, when db is not shared yet.
        Exclusive checks, rollbacks aso are to be gathered here"""
        self.logger.app_log.warning("Status: Starting Single user checks...")
        # print("Initial files check")
        self._initial_files_checks()
        solo_handler = SoloDbHandler(config=self.config, logger=self.logger)  # This instance will only live for the scope of single_user_checks(),
        # why it's not a property of the Node instance and it passed to individual checks.
        print("single_user_checks - Checking schema")
        self._check_db_schema(solo_handler)
        # print("Checking Heights")
        self._ledger_check_heights(solo_handler)
        if self.recompress:
            # EGG_EVO: make sure we added indices on temp ledger before ledger recompress
            # todo: do not close database and move files, swap tables instead
            solo_handler.close()
            self._recompress_ledger_prepare()  # This will touch the files themselve.
            solo_handler = SoloDbHandler(config=self.config, logger=self.logger)
            self._recompress_ledger(solo_handler)  # Warning: this will close the solo instance!
            solo_handler = SoloDbHandler(config=self.config, logger=self.logger)

        solo_handler.add_indices()
        if not self.is_regnet:
            solo_handler.sequencing_check()
            if self.config.verify:
                solo_handler.verify()

        self._ram_init(solo_handler)  # Save this one for the end (time consuming if something goes wrong)
        #
        self.logger.app_log.warning("Status: Single user checks done.")

    def _initial_files_checks(self):
        if not self.config.full_ledger and os.path.exists(self.config.ledger_path) and self.is_mainnet:
            os.remove(self.config.ledger_path)
            self.logger.app_log.warning("Removed full ledger for hyperblock mode")
        if not self.config.full_ledger and not self.is_regnet:
            self.logger.app_log.warning("Cloning hyperblocks to ledger file")
            copy(self.config.hyper_path, self.config.ledger_path)  # hacked to remove all the endless checks
        if self.is_regnet:
            # Delete mempool
            if os.path.isfile(self.config.mempool_path):
                os.remove(self.config.mempool_path)
        # needed for docker logs
        self.logger.app_log.warning(f"Checking Heavy3 file, can take up to 5 minutes... {self.config.heavy3_path}")
        mining_heavy3.mining_open(self.config.heavy3_path)
        self.logger.app_log.warning(f"Status: Heavy3 file Ok!")

    def checkpoint_set(self):

        def round_down(number, order):  # Local helper
            return int(floor(number / order)) * order

        limit = 30
        if self.last_block < 1450000:
            limit = 1000
        checkpoint = round_down(self.last_block, limit) - limit
        if checkpoint != self.checkpoint:
            self.checkpoint = checkpoint
            self.logger.app_log.warning(f"Checkpoint set to {self.checkpoint}")

    def blocknf(self, block_hash_delete: str, peer_ip: str, db_handler: "DbHandler", hyperblocks: bool=False) -> None:
        """
        Rolls back a single block, updates node object variables.
        Rollback target must be above checkpoint.
        Hash to rollback must match in case our ledger moved.
        Not trusting hyperblock nodes for old blocks because of trimming,
        they wouldn't find the hash and cause rollback.
        """
        self.logger.app_log.warning(f"Rollback operation on {block_hash_delete} initiated by {peer_ip}", "General")
        my_time = ttime()
        if not self.db_lock.locked():
            self.db_lock.acquire()
            self.logger.app_log.warning(f"Database lock acquired")
            backup_data = None  # used in "finally" section
            skip = False
            reason = ""

            try:
                block_max_ram = db_handler.last_mining_transaction().to_dict(legacy=True)
                db_block_height = block_max_ram['block_height']
                db_block_hash = block_max_ram['block_hash']

                ip = {'ip': peer_ip}
                self.plugin_manager.execute_filter_hook('filter_rollback_ip', ip)
                if ip['ip'] == 'no':
                    reason = "Filter blocked this rollback"
                    skip = True

                elif db_block_height < self.checkpoint:
                    reason = "Block is past checkpoint, will not be rolled back"
                    skip = True

                elif db_block_hash != block_hash_delete:
                    # print db_block_hash
                    # print block_hash_delete
                    reason = "We moved away from the block to rollback, skipping"
                    skip = True

                elif hyperblocks and self.last_block_ago > 30000:  # more than 5000 minutes/target blocks away
                    reason = f"{peer_ip} is running on hyperblocks and our last block is too old, skipping"
                    skip = True

                else:
                    backup_data = db_handler.backup_higher(db_block_height)

                    self.logger.app_log.warning(f"Node {peer_ip} didn't find block {db_block_height} ({db_block_hash})")

                    # roll back hdd too
                    db_handler.rollback_under(db_block_height)
                    # /roll back hdd too

                    # rollback indices
                    db_handler.tokens_rollback(db_block_height)
                    db_handler.aliases_rollback(db_block_height)
                    # /rollback indices

                    self.last_block_timestamp = db_handler.last_block_timestamp()
                    self.last_block_hash = db_handler.last_block_hash()
                    self.last_block = db_block_height - 1
                    self.hdd_hash = db_handler.last_block_hash()
                    self.hdd_block = db_block_height - 1
                    db_handler.tokens_update()

            except Exception as e:
                if self.config.debug:
                    exc_type, exc_obj, exc_tb = exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    self.logger.app_log.warning("{} {} {}".format(exc_type, fname, exc_tb.tb_lineno))
                self.logger.app_log.warning(e)

            finally:
                self.db_lock.release()

                self.logger.app_log.warning(f"Database lock released")

                if skip:
                    rollback = {"timestamp": my_time, "height": db_block_height, "ip": peer_ip,
                                "hash": db_block_hash, "skipped": True, "reason": reason}
                    self.plugin_manager.execute_action_hook('rollback', rollback)
                    self.logger.app_log.info(f"Skipping rollback: {reason}")
                else:
                    try:
                        nb_tx = 0
                        for tx in backup_data:
                            tx_short = f"{tx[1]} - {tx[2]} to {tx[3]}: {tx[4]} ({tx[11]})"
                            if tx[9] == 0:
                                try:
                                    nb_tx += 1
                                    self.logger.app_log.info(
                                        mp.MEMPOOL.merge((tx[1], tx[2], tx[3], tx[4], tx[5], tx[6], tx[10], tx[11]),
                                                         peer_ip, db_handler, size_bypass=False, revert=True))
                                    # will get stuck if you change it to respect self.db_lock
                                    self.logger.app_log.warning(f"Moved tx back to mempool: {tx_short}")
                                except Exception as e:
                                    self.logger.app_log.warning(f"Error during moving tx back to mempool: {e}")
                            else:
                                # It's the coinbase tx, so we get the miner address
                                miner = tx[3]
                                height = tx[0]
                        rollback = {"timestamp": my_time, "height": height, "ip": peer_ip, "miner": miner,
                                    "hash": db_block_hash, "tx_count": nb_tx, "skipped": False, "reason": ""}
                        self.plugin_manager.execute_action_hook('rollback', rollback)

                    except Exception as e:
                        self.logger.app_log.warning(f"Error during moving txs back to mempool: {e}")

        else:
            reason = "Skipping rollback, other ledger operation in progress"
            rollback = {"timestamp": my_time, "ip": peer_ip, "skipped": True, "reason": reason}
            self.plugin_manager.execute_action_hook('rollback', rollback)
            self.logger.app_log.info(reason)
