import json
import os.path as path
from os import makedirs
from sys import exit
from time import sleep
from typing import Union

__version__ = "0.0.8"


# "param_name":["type"] or "param_name"=["type","property_name"]
VARS = {
    "port": ["str"],
    "verify": ["bool", "verify"],
    "testnet": ["bool"],
    "regnet": ["bool"],
    "version": ["str", "version"],
    "version_allow": ["list"],
    "thread_limit": ["int", "thread_limit"],
    "rebuild_db": ["bool", "rebuild_db"],
    "debug": ["bool", "debug"],
    "purge": ["bool", "purge"],
    "pause": ["int", "pause"],
    "ledger_path": ["str", "ledger_path"],
    "hyper_path": ["str", "hyper_path"],
    "hyper_recompress": ["bool", "hyper_recompress"],
    "full_ledger": ["bool", "full_ledger"],
    "ban_threshold": ["int"],
    "tor": ["bool", "tor"],
    "debug_level": ["str", "debug_level"],
    "allowed": ["str", "allowed"],
    "ram": ["bool", "ram"],
    "node_ip": ["str", "node_ip"],
    "light_ip": ["dict"],
    "reveal_address": ["bool"],
    "accept_peers": ["bool"],
    "banlist": ["list"],
    "whitelist": ["list"],
    "nodes_ban_reset": ["int"],
    "mempool_allowed": ["list"],
    "terminal_output": ["bool"],
    "gui_scaling": ["str"],
    "mempool_ram": ["bool"],
    "egress": ["bool"],
    "trace_db_calls": ["bool"],
    "heavy3_path": ["str"],
    "mempool_path": ["str"],
    "old_sqlite": ["bool"],
    "mandatory_message": ["list"],
    "label": ["str"]
    #, "legacy_db": ["bool"]
}

# Optional default values so we don't bug if they are not in the config.
# For compatibility
DEFAULTS = {
    "testnet": False,
    "regnet": False,
    "trace_db_calls": False,
    "mempool_ram": True,
    "heavy3_path": "",
    "mempool_path": "",
    "old_sqlite": False,
    "ledger_path": "",
    "hyper_path": "",
    # "legacy_db": True,
    "mandatory_message": {
        "Address": "Comment - Dict for addresses that require a message. tx to these addresses withjout a message will not be accepted by mempool.",
        "f6c0363ca1c5aa28cc584252e65a63998493ff0a5ec1bb16beda9bac": "qTrade Exchange needs a message to route the deposit to your account",
        "d11ea307ea6de821bc28c645b1ff8dd25c6e8a9f70b3a6aeb9928754": "VGate/ViteX Exchange needs a message to route the deposit to your account",
        "14c1b5851634f0fa8145ceea1a52cabe2443dc10350e3febf651bd3a": "Graviex Exchange needs a message to route the deposit to your account",
        "1a174d7fdc2036e6005d93cc985424021085cc4335061307985459ce": "Finexbox Exchange needs a message to route the deposit to your account",
        "49ca873779b36c4a503562ebf5697fca331685d79fd3deef64a46888": "Tradesatoshi is no more listing bis but needed a message to route the deposit to your account",
        "edf2d63cdf0b6275ead22c9e6d66aa8ea31dc0ccb367fad2e7c08a25": "Old Cryptopia address, memo",
    },  # setup here by safety, but will use the json if present for easier updates.
    "label": "Default config label"
}


class Config:

    # Some dup info here, but allows hinting to work as intended.
    __slots__ = ("port", "verify", "testnet", "regnet", "version", "version_allow", "thread_limit", "rebuild_db",
                 "debug", "purge", "pause", "ledger_path", "hyper_path", "hyper_recompress", "full_ledger",
                 "ban_threshold", "tor", "debug_level", "allowed", "ram", "node_ip", "light_ip", "reveal_address",
                 "accept_peers", "banlist", "whitelist", "nodes_ban_reset", "mempool_allowed", "terminal_output",
                 "gui_scaling", "mempool_ram", "egress", "trace_db_calls", "heavy3_path", "mempool_path",
                 "old_sqlite", "mandatory_message", "genesis", "datadir", "label", "legacy_db")

    def __init__(self, datadir: str='', force_legacy=False, force_v2=False, wait: int=0):
        # Default genesis to keep compatibility
        self.genesis = "4edadac9093d9326ee4b17f869b14f1a2534f96f9c5d7b48dc9acaed"
        self.mandatory_message = {}
        if datadir == '':
            print("Config now needs to be fed with datadir param")
            exit()
        self.datadir = datadir
        if path.isfile(path.join(datadir,"chain-v2", "ledger.db")):
            print("Found v2 ledger")
            self.legacy_db = False
        if force_legacy:
            self.legacy_db = True
        if force_v2:
            self.legacy_db = False
        self.read()
        print("Config Label: {}".format(self.label))
        print("Legacy DB: {}".format(self.legacy_db))
        print("Ledger: {}".format(self.ledger_path))
        print("Hyper: {}".format(self.hyper_path))
        print("Index: {}".format(self.get_index_db_path()))
        if self.regnet and "regnet" not in self.version:
            print("regnet is set, but version is not regnet")
            exit()
        if "regnet" in self.version and not self.regnet:
            print("Version is regnet but regnet is not set")
            exit()
        if wait > 0:
            print("Sleeping {} sec... ctrl-c if bad config".format(wait))
            sleep(wait)  # Allows for ctrl-c before any action in case it's wrong at dev or setup time
        # exit()

    def load_file(self, filename: str) -> None:
        # print("Loading",filename)
        with open(filename) as fp:
            for line in fp:
                if "=" in line:
                    left, right = map(str.strip, line.rstrip("\n").split("="))
                    if "mempool_ram_conf" == left:
                        print(
                            "Inconsistent config, param is now mempool_ram in config.txt"
                        )
                        exit()
                    if left not in VARS:
                        # Warn for unknown param?
                        continue
                    params = VARS[left]
                    if params[0] == "int":
                        right = int(right)
                    elif params[0] == "dict":
                        try:
                            right = json.loads(right)
                        except:  # compatibility
                            right = [item.strip() for item in right.split(",")]
                    elif params[0] == "list":
                        right = [item.strip() for item in right.split(",")]
                    elif params[0] == "bool":
                        if right.lower() in ["false", "0", "", "no"]:
                            right = False
                        else:
                            right = True

                    else:
                        # treat as "str"
                        pass
                    if len(params) > 1:
                        # deal with properties that do not match the config name.
                        left = params[1]
                    setattr(self, left, right)

    def get_wallet_path(self) -> str:
        return self.get_file_path("", "wallet.der")

    def get_db_path(self, db_name: str, legacy: Union[bool, None]=None) -> str:
        legacy = self.legacy_db if legacy is None else legacy
        db_dir = "chain-legacy" if legacy else "chain-v2"
        return self.get_file_path(db_dir, db_name)

    def get_index_db_path(self, legacy: Union[bool, None]=None) -> str:
        if self.regnet:
            return self.get_file_path("regnet", "index_reg.db")
        legacy = self.legacy_db if legacy is None else legacy
        file_name = "index_test.db" if self.testnet else "index.db"
        return self.get_db_path(file_name, legacy)

    def get_ledger_db_path(self, legacy:  Union[bool, None]=None) -> str:
        if self.regnet:
            return self.get_file_path("regnet", "regmod.db")
        legacy = self.legacy_db if legacy is None else legacy
        file_name = "ledger_test.db" if self.testnet else "ledger.db"
        return self.get_db_path(file_name, legacy)

    def get_hyper_db_path(self, legacy:  Union[bool, None]=None) -> str:
        if self.regnet:
            return self.get_file_path("regnet", "regmod.db")
        legacy = self.legacy_db if legacy is None else legacy
        file_name = "hyper_test.db" if self.testnet else "hyper.db"
        return self.get_db_path(file_name, legacy)

    def get_file_path(self, dir_name: str, file_name: str) -> str:
        temp_dir = self.datadir if dir_name == '' else path.join(self.datadir, dir_name)
        if not path.isdir(temp_dir):
            # Ensure dir exists
            makedirs(temp_dir)
        return path.join(temp_dir, file_name)

    def get_live_path(self) -> str:
        return path.join(self.datadir, "live")

    def read(self) -> None:
        # first of all, set from default
        for key, default in DEFAULTS.items():
            setattr(self, key, default)
        # read from release config file
        self.load_file(self.get_file_path("config", "config.txt"))
        # then override with optional custom config
        if path.exists(self.get_file_path("config", "config_custom.txt")):
            self.load_file(self.get_file_path("config", "config_custom.txt"))
        if self.heavy3_path == "":
            # Defaut path, use datadir/
            self.heavy3_path = self.get_file_path("", "heavy3a.bin")  # path.join(self.datadir, "heavy3a.bin")
        if self.mempool_path == "":
            # Defaut path, use datadir/live
            self.mempool_path = self.get_file_path("live", "mempool.db")  # path.join(self.datadir, "live", "mempool.db")
            if not self.mempool_ram:
                print("Mempool path is {}".format(self.mempool_path))
        if self.ledger_path != "":
            self.ledger_path = self.get_ledger_db_path()
            print("ledger_path is no more used. Using '{}' as ledger".format(self.ledger_path))
        else:
            self.ledger_path = self.get_ledger_db_path()
        if self.hyper_path != "":
            self.hyper_path = self.get_hyper_db_path()
            print("hyper_path is no more used. Using '{}' as ledger".format(self.hyper_path))
        else:
            self.hyper_path = self.get_hyper_db_path()
        file_name = self.get_file_path("config", "mandatory_message.json")
        if path.isfile(file_name):
            try:
                with open(file_name) as fp:
                    data = json.load(fp)
                    if type(data) != dict:
                        raise RuntimeWarning("Bad file format")
                    self.mandatory_message = data
                    print("mandatory_message file loaded")
            except Exception as e:
                print("Error loading mandatory_message.json {}".format(e))

        """
        if "regnet" in self.version:
            print("Regnet, forcing ram = False")
            self.ram = False
        """
