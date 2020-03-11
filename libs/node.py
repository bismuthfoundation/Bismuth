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

import regnet
import mining_heavy3
from bismuthcore.helpers import just_int_from, download_file
from essentials import keys_check  # To be handled by polysign

from libs.config import Config
from libs.solodbhandler import SoloDbHandler

__version__ = "0.0.4"


class Node:

    # Slots to enforce immutable properties names
    __slots__ = ("py_version", "linux", "IS_STOPPING", "app_version", "startup_time", "last_block_timestamp",
                 "last_block_ago", "difficulty", "ledger_temp", "hyper_temp", "recompress", "peerfile",
                 "ledger_ram_file", "index_db", "peerfile_suggested", "config", "logger", "keys", "plugin_manager",
                 "apihandler", "db_lock", "q", "is_testnet", "is_regnet", "is_mainnet", "hdd_block", "hdd_hash",
                 "last_block_hash", "last_block", "peers", "syncing", "checkpoint", "digest_block")

    def __init__(self, digest_block, config: Config=None, app_version: str="", logger=None, keys=None, run_checks=True):
        # TODO EGG: digest_block will need to be integrated in this class. current hack necessary to avoid circular references.
        # Self built info
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

        """ Processed items - all checked and converted on the whole codebase
        # config items, to be taken from config property
        #- self.version_allow = None
        #- self.version = None
        #- self.port = None
        #- self.hyper_path = None
        #- self.ledger_path = None
        #- self.hyper_recompress = True
        #- self.debug_level = None
        #- self.verify = None
        #- self.thread_limit = None
        #- self.rebuild_db = None
        #- self.debug = None
        #- self.pause = None
        #- self.tor = None
        #- self.ram = None
        #- self.reveal_address = None
        #- self.terminal_output = None
        #- self.egress = None
        #- self.genesis = None
        #- self.accept_peers = config.accept_peers
        #- self.full_ledger = config.full_ledger
        #- self.trace_db_calls = config.trace_db_calls
        #- self.heavy3_path = config.heavy3_path
        #- self.old_sqlite = config.old_sqlite
        """

        # startup sequence

        # Net type
        self.is_testnet = False
        self.is_regnet = False
        self.is_mainnet = True
        self._setup_net_type()

        self.load_keys()

        # TODO: EGG: migrate all "single mode" methods from top level node.py in there
        # Add a "level" inner state and trigger by outside call.
        if run_checks:
            self.single_user_checks()
        else:
            self.logger.app_log.warning("Warning: Node was instanciated without startup checks. Make sure you know what you are doing!!")

    def _setup_net_type(self):
        """
        Adjust node properties depending on mainnet, testnet or regnet config
        """
        # Done: only deals with 'node' structure, candidate for single user mode.
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
                types = ['static/ledger_test.db-wal', 'static/ledger_test.db-shm', 'static/index_test.db', 'static/hyper_test.db-wal', 'static/hyper_test.db-shm']
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
        if force_exit is True, will call sys.exit(), else it will just raise its flag and wait for the main loop to terminate."""
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
        self.keys.key, self.keys.public_key_readable, self.keys.private_key_readable, _, _, self.keys.public_key_b64encoded, self.keys.address, self.keys.keyfile = essentials.keys_load(
            "privkey.der", "pubkey.der")
        if self.is_regnet:
            regnet.PRIVATE_KEY_READABLE = self.keys.private_key_readable
            regnet.PUBLIC_KEY_B64ENCODED = self.keys.public_key_b64encoded
            regnet.ADDRESS = self.keys.address
            regnet.KEY = self.keys.key
        self.logger.app_log.warning(f"Status: Local address: {self.keys.address}")

    def single_user_checks(self) -> None:
        """Called at instanciation time, when db is not shared yet.
        Exclusive checks, rollbacks aso are to be gathered here"""
        self.logger.app_log.warning("Starting Single user checks...")
        self._initial_files_checks()
        solo_handler = SoloDbHandler(self)  # This instance will only live for the scope of single_user_checks()
        # TODO: WIP

        self.logger.app_log.warning("Single user checks done.")

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
        self.logger.app_log.warning(f"Heavy3 file Ok!")
