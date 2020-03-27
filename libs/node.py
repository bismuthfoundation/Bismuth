"""
WIP - Core class handling the Bismuth node.
"""

import threading
import queue
import glob
import os
import tarfile
import sys
import platform
from time import sleep
from shutil import copy
from math import floor

import regnet
import mining_heavy3
from bismuthcore.helpers import just_int_from, download_file
from essentials import keys_check, keys_load  # To be handled by polysign
from difficulty import difficulty  # where does this belongs? check usages

from libs.config import Config
from libs.solodbhandler import SoloDbHandler
from libs.apihandler import ApiHandler
from libs.peershandler import Peers
from libs.plugins import PluginManager

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from libs.dbhandler import DbHandler


__version__ = "0.0.8"


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
        self.peerfile = "peers.txt"
        self.ledger_ram_file = "file:ledger?mode=memory&cache=shared"
        self.ram_db = None
        self.index_db = "static/index.db"
        self.peerfile_suggested = "suggested_peers.txt"

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
            self.config.hyper_path = "static/hyper_test.db"
            self.config.ledger_path = "static/ledger_test.db"

            self.ledger_ram_file = "file:ledger_testnet?mode=memory&cache=shared"
            self.peerfile = "peers_test.txt"
            self.peerfile_suggested = "suggested_peers_test.txt"

            self.index_db = "static/index_test.db"

            redownload_test = input("Status: Welcome to the testnet. Redownload test ledger? y/n")
            if redownload_test == "y":
                types = ['static/ledger_test.db-wal', 'static/ledger_test.db-shm', 'static/index_test.db',
                         'static/hyper_test.db-wal', 'static/hyper_test.db-shm']
                for dbtype in types:
                    for file in glob.glob(dbtype):
                        os.remove(file)
                        print(file, "deleted")
                download_file("https://bismuth.cz/test.tar.gz", "static/test.tar.gz")
                with tarfile.open("static/test.tar.gz") as tar:
                    tar.extractall("static/")  # NOT COMPATIBLE WITH CUSTOM PATH CONFS
            else:
                print("Not redownloading test db")

        elif "regnet" in self.config.version:
            self.is_regnet = True
            self.is_testnet = False
            self.is_mainnet = False
            self.logger.app_log.warning("Regnet Mode")

            self.config.port = regnet.REGNET_PORT
            self.config.hyper_path = regnet.REGNET_DB
            self.config.ledger_path = regnet.REGNET_DB
            self.ledger_ram_file = "file:ledger_regnet?mode=memory&cache=shared"
            self.peerfile = "peers_reg.txt"
            self.peerfile_suggested = "peers_reg.txt"

            self.config.hyper_recompress = False
            self.index_db = regnet.REGNET_INDEX
            self.logger.app_log.warning("Regnet init...")
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
        if force_exit:
            sys.exit()

    def sleep(self) -> None:
        """Pause the current thread for the configured time to avoid cpu loads while in waiting loops"""
        sleep(self.config.pause)

    def load_keys(self):
        """Initial loading of crypto keys"""
        keys_check(self.logger.app_log, "wallet.der")
        self.keys.key, self.keys.public_key_readable, self.keys.private_key_readable, _, _, \
            self.keys.public_key_b64encoded, self.keys.address, self.keys.keyfile \
            = keys_load("privkey.der", "pubkey.der")
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
            # EGG_EVO: take care of these hardcoded paths
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
        if not os.path.exists("static"):
            os.mkdir("static")
        redownload = False
        # force bootstrap via adding an empty "fresh_sync" file in the dir.
        if os.path.exists("fresh_sync") and self.is_mainnet:
            self.logger.app_log.warning("Status: Fresh sync required, bootstrapping from the website")
            os.remove("fresh_sync")
            redownload = True
        try:
            ledger_schema = solo_handler.transactions_schema()
            if len(ledger_schema) != 12:
                # EGG_EVO: Kept this test for the time being, but will need more complete and distinctive test
                # depending on the db type
                self.logger.app_log.error(
                    f"Status: Integrity check on ledger failed, bootstrapping from the website")
                redownload = True
            command_field_type = ledger_schema[10][2]
            if command_field_type != "TEXT":
                redownload = True
                self.logger.app_log.warning("Database column type outdated for Command field")
        except:
            redownload = True
        if redownload and self.is_mainnet:
            self.bootstrap()

    def _ledger_check_heights(self, solo_handler: SoloDbHandler) -> None:
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
        if rebuild:
            self.logger.app_log.warning(f"Status: Hyperblocks will be rebuilt")
            copy(self.config.ledger_path, self.config.ledger_path + '.temp')
        else:
            copy(self.config.hyper_path, self.config.ledger_path + '.temp')

    def _recompress_ledger(self, solo_handler: SoloDbHandler, depth: int = 15000) -> None:
        solo_handler.prepare_hypo()  # avoid double processing by renaming Hyperblock addresses to Hypoblock
        db_block_height = solo_handler.block_height_max_hyper()
        depth_specific = db_block_height - depth
        # Now gather all active addresses
        unique_addressess = solo_handler.distinct_hyper_recipients(depth_specific)
        for address in unique_addressess:
            solo_handler.update_hyper_balance_at_height(address, depth_specific)
        solo_handler.hyper_commit()
        solo_handler.cleanup_hypo(depth_specific)
        solo_handler.close()

        if os.path.exists(self.config.hyper_path):
            os.remove(self.config.hyper_path)  # remove the old hyperblocks to rebuild
            os.rename(self.config.ledger_path + '.temp', self.config.hyper_path)
        self.logger.app_log.warning(f"Status: Recompressed!")

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
        self._initial_files_checks()
        solo_handler = SoloDbHandler(self)  # This instance will only live for the scope of single_user_checks(),
        # why it's not a property of the Node instance and it passed to individual checks.
        self._check_db_schema(solo_handler)
        self._ledger_check_heights(solo_handler)
        if self.recompress:
            # todo: do not close database and move files, swap tables instead
            solo_handler.close()
            self._recompress_ledger_prepare()  # This will touch the files themselve.
            solo_handler = SoloDbHandler(self)
            self._recompress_ledger(solo_handler)  # Warning: this will close the solo instance!
            solo_handler = SoloDbHandler(self)

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
        if not self.config.full_ledger:
            self.logger.app_log.warning("Cloning hyperblocks to ledger file")
            copy(self.config.hyper_path, self.config.ledger_path)  # hacked to remove all the endless checks
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
