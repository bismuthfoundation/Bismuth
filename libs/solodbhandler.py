"""
Sqlite3 Database handler module for Bismuth nodes
It's very alike DbHandler object, but
This class is to be used for single user mode, when node boots up and checks/compress/fixes the db.
Splitting means some slight dup code, but since the operations in solo mode are so different than from later ones,
it's better for clarity and maintenance to have them in a dedicated class.

ALL DB and table, index creation should take place here and here alone.
DB migration, upgrades, conversion as well
TODO: Lookup for "CREATE" in non deprecated files and remove them.
"""

import sqlite3
import sys
from decimal import Decimal
from bismuthcore.compat import quantize_two, quantize_eight
from bismuthcore.transaction import Transaction
from bismuthcore.block import Block
from bismuthcore.transactionslist import TransactionsList
import functools
from time import time as ttime
from os import path

from Cryptodome.Hash import SHA  # This should not belong there in the end, will be moved to Transaction object
from polysign.signerfactory import SignerFactory

from typing import Union, List, Tuple, Iterator
from typing import TYPE_CHECKING
if TYPE_CHECKING:
  # from libs.node import Node
  from libs.logger import Logger
  from libs.config import Config


__version__ = "1.0.6"

V2_LEDGER_CREATE = ('CREATE TABLE IF NOT EXISTS "transactions" (`block_height` INTEGER, '
                    '`timestamp` NUMERIC, `address` TEXT, `recipient` TEXT, '
                    '`amount` INTEGER, `signature` BINARY, `public_key` BINARY, '
                    '`block_hash` BINARY, `fee` INTEGER, `reward` INTEGER,'
                    '`operation` TEXT, `openfield` TEXT)',

                    'CREATE INDEX IF NOT EXISTS `Block Height Index` '
                    'ON `transactions` (`block_height`)'
                    )

# EGG_EVO: why text? move as int as well?
"""
V2_MISC_CREATE = ('CREATE TABLE IF NOT EXISTS "misc" ('
                  '`block_height` INTEGER, `difficulty` TEXT)',

                  'CREATE INDEX IF NOT EXISTS "Misc Block Height Index" on misc(block_height)'
                 )
"""
# EGG_EVO: why text? move as int as well?
V2_MISC_CREATE = ('CREATE TABLE IF NOT EXISTS "misc" ('
                  '`block_height` INTEGER PRIMARY KEY, `difficulty` TEXT)', )


CREATE_TXID4_INDEX_IF_NOT_EXISTS = "CREATE INDEX IF NOT EXISTS TXID4_Index ON transactions(substr(signature,1,4))"

# TODO: dup with clean v2
CREATE_MISC_BLOCK_HEIGHT_INDEX_IF_NOT_EXISTS = "CREATE INDEX IF NOT EXISTS 'Misc Block Height Index' on misc(block_height)"

"""
 1 704 000 blocks (inc mirror), 
 
 Legacy (full sig, not vacuumed)
 all indices   = 8 985 419 776
 vacuumed      = 8 849 080 320
 
 V2:                 
 default index = 3 267 529 728
 + timestamp   = 3 317 149 696
 + reward      = 3 350 320 128
 + recipient   = 3 547 339 776
 + openfield   = 3 683 634 176
 + fees        = 3 712 750 592
 + blockhash   = 3 820 225 536
 + amount      = 3 851 741 184
 + address     = 4 037 898 240
 + operation   = 4 067 203 072
 
 + full sign   = 6 662 548 480
  
 Vacuumed      = 6 655 652 864
 
 + misc        = 6 722 979 840
 
 (but misc table missing atm)
"""

# EGG_EVO: TODO, not applied atm?
V2_INDICES_CREATE = ("CREATE INDEX IF NOT EXISTS `Timestamp Index` ON `transactions` (`timestamp`)",
                     "CREATE INDEX IF NOT EXISTS `Reward Index` ON `transactions` (`reward`)",
                     "CREATE INDEX IF NOT EXISTS `Recipient Index` ON `transactions` (`recipient`)",
                     "CREATE INDEX IF NOT EXISTS `Openfield Index` ON `transactions` (`openfield`)",
                     "CREATE INDEX IF NOT EXISTS `Fee Index` ON `transactions` (`fee`)",
                     "CREATE INDEX IF NOT EXISTS `Block Hash Index` ON `transactions` (`block_hash`)",
                     "CREATE INDEX IF NOT EXISTS `Amount Index` ON `transactions` (`amount`)",
                     "CREATE INDEX IF NOT EXISTS `Address Index` ON `transactions` (`address`)",        # ledger, colored
                     "CREATE INDEX IF NOT EXISTS `Operation Index` ON `transactions` (`operation`)",    # ledger, colored
                     "CREATE INDEX IF NOT EXISTS `Signature Index` ON `transactions` (`signature`)",  # or partial
                     )

V2_MINIMAL_INDICES_CREATE = (
                     "CREATE INDEX IF NOT EXISTS `Recipient Index` ON `transactions` (`recipient`)",
                     "CREATE INDEX IF NOT EXISTS `Address Index` ON `transactions` (`address`)",
                     )

SQL_TO_TRANSACTIONS_LEGACY = "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
SQL_TO_TRANSACTIONS_V2 = "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
SQL_TO_MISC_V2 = "INSERT INTO misc VALUES (?,?)"


# TODO: factorize
def timeit(method):
    def timed(*args, **kw):
        ts = ttime()
        result = method(*args, **kw)
        te = ttime()
        if 'log_time' in kw:
            name = kw.get('log_name', method.__name__.upper())
            kw['log_time'][name] = int((te - ts) * 1000)
        else:
            print('%r  %2.2f ms' %  (method.__name__, (te - ts) * 1000))
        return result
    return timed


def sql_trace_callback(log, sql_id, statement: str):
    line = f"SQL[{sql_id}] {statement}"
    log.warning(line)


class SoloDbHandler:

    def __init__(self, config: "Config", logger: "Logger", trace_db_calls: bool=False):
        self.py_version = int(str(sys.version_info.major) + str(sys.version_info.minor) + str(sys.version_info.micro))
        self.logger = logger
        self.config = config
        self.trace_db_calls = trace_db_calls
        self.legacy_db = self.config.legacy_db

        if path.isfile(config.get_index_db_path()):
            self._index_db = sqlite3.connect(config.get_index_db_path(), timeout=1)
            if self.trace_db_calls:
                self._index_db.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "INDEX"))
            self._index_db.text_factory = str
            self._index_db.execute('PRAGMA case_sensitive_like = 1;')
            self._index_cursor = self._index_db.cursor()  # Cursor to the index db
        else:
            print("No Index")
            self._index_db = None
            self._index_cursor = None

        if path.isfile(config.ledger_path):
            self._ledger_db = sqlite3.connect(config.ledger_path, timeout=1)
            if self.trace_db_calls:
                self._ledger_db.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "HDD"))
            self._ledger_db.text_factory = str
            self._ledger_db.execute('PRAGMA case_sensitive_like = 1;')
            self._ledger_cursor = self._ledger_db.cursor()

        else:
            print("No Ledger")
            self._ledger_db = None
            self._ledger_cursor = None

        if path.isfile(config.hyper_path):
            self._hyper_db = sqlite3.connect(config.hyper_path, timeout=1)
            if self.trace_db_calls:
                self._hyper_db.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "HDD2"))
            self._hyper_db.text_factory = str
            self._hyper_db.execute('PRAGMA case_sensitive_like = 1;')
            self._hyper_cursor = self._hyper_db.cursor()
        else:
            # print("No Hyper")
            self._hyper_db = None
            self._hyper_cursor = None

    def create_db(self):
        """Will create db structure from scratch, not bootstrap.
        Only implemented for v2 db"""
        if self.legacy_db:
            print("create_db only is meant for V2 db")
            sys.exit()
        # Ledger
        if self._ledger_db is None:
            # first create the db file
            self._ledger_db = sqlite3.connect(self.config.ledger_path, timeout=1)
            if self.trace_db_calls:
                self._ledger_db.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "HDD"))
            self._ledger_db.text_factory = str
            self._ledger_db.execute('PRAGMA case_sensitive_like = 1;')
            self._ledger_cursor = self._ledger_db.cursor()
            # Now create the minimal structure, no extra indices yet.
            for sql in V2_LEDGER_CREATE:
                self._ledger_cursor.execute(sql)
                self._ledger_db.commit()
            # Now create the minimal structure, no extra indices yet.
            for sql in V2_MISC_CREATE:
                self._ledger_cursor.execute(sql)
                self._ledger_db.commit()
        else:
            print("Existing ledger")

    def tables_exist(self):
        """Tells whether the various required tables exist in the DB"""
        try:
            if not path.isfile(self.config.ledger_path):
                print("No ledger")
                return False
            # print("ledger cursor1", self._ledger_cursor)

            ledger_schema = self.table_schema('transactions')
            print("ledger schema", ledger_schema)
            if len(ledger_schema) < 10:
                print("No or broken ledger")
                return False
            if ledger_schema[4][2] == 'NUMERIC':
                print("Legacy ledger")
                if len(ledger_schema) != 12:
                    # TODO: better test
                    return False
                else:
                    return True
            elif ledger_schema[4][2] == 'INTEGER':
                print("V2 ledger")
            else:
                print("Unknown ledger")
            misc_schema = self.table_schema('misc')
            print(misc_schema)
            # hyper
            hyper_schema = self.table_schema('transactions', db_name="hyper")
            print(hyper_schema)
            # index
            index_schema = self.table_schema('tokens', db_name="index")
            print(index_schema)
            index_schema = self.table_schema('aliases', db_name="index")
            print(index_schema)
            # EGG_EVO: TODO
        except Exception as e:
            print(e)

    def add_indices(self, full: bool=False):
        """Add potential missing indices. - it's more of an automated upgrade path"""
        self.logger.status_log.info("Checking and creating indices")
        # ledger db
        if not self.config.old_sqlite:
            self._ledger_cursor.execute(CREATE_TXID4_INDEX_IF_NOT_EXISTS)
        else:
            self.logger.status_log.warning("Setting old_sqlite is True, lookups will be slower.")
        if self.legacy_db:
            self._ledger_cursor.execute(CREATE_MISC_BLOCK_HEIGHT_INDEX_IF_NOT_EXISTS)
        self._ledger_db.commit()

        if full:
            self.logger.status_log.info("Creating ledger full indices...")
            for sql in V2_INDICES_CREATE:
                self._ledger_cursor.execute(sql)
                self._ledger_db.commit()
        else:
            self.logger.status_log.warning("Creating ledger minimal indices...")
            for sql in V2_MINIMAL_INDICES_CREATE:
                self._ledger_cursor.execute(sql)
                self._ledger_db.commit()

        # hyper db
        self.logger.status_log.info("Creating hyper indices...")
        if not self.config.old_sqlite:
            self._hyper_cursor.execute(CREATE_TXID4_INDEX_IF_NOT_EXISTS)
        if self.legacy_db:
            self._hyper_cursor.execute(CREATE_MISC_BLOCK_HEIGHT_INDEX_IF_NOT_EXISTS)
        self._hyper_db.commit()
        if full:
            self.logger.status_log.info("Creating hyper full indices...")
            for sql in V2_INDICES_CREATE:
                self._hyper_cursor.execute(sql)
                self._hyper_db.commit()
        else:
            self.logger.status_log.warning("Creating hyper minimal indices...")
            for sql in V2_MINIMAL_INDICES_CREATE:
                self._hyper_cursor.execute(sql)
                self._hyper_db.commit()

        # RAM or hyper db is not created yet at this point.
        self.logger.status_log.info("Finished creating indices")

    def transactions_schema(self) -> list:
        """Returns the structure of the "transactions" table from the ledger db"""
        return self.table_schema('transactions')

    def table_schema(self, table_name: str="transactions", db_name: str="ledger") -> list:
        """Returns the structure of the "transactions" table from the ledger db"""
        # print("table_schema", table_name, db_name)
        if db_name == "ledger":
            # print("ledger cursor", self._ledger_cursor)
            res = self._ledger_cursor.execute("PRAGMA table_info('{}')".format(table_name))
        elif db_name == "hyper":
            res = self._hyper_cursor.execute("PRAGMA table_info('{}')".format(table_name))
        elif db_name == "index":
            res = self._index_cursor.execute("PRAGMA table_info('{}')".format(table_name))
        else:
            raise RuntimeError("Unknown db_name in SoloDbHandle.table_schema: {}".format(db_name))
        return res.fetchall()

    @timeit
    def get_blocks(self, block_height: int=0, limit: int=10) -> TransactionsList:
        """
        Returns a List of blocks, from block_height included and up to limit blocks max.
        :param block_height:
        :param limit:
        :return: Block, that is, a list of Transactions.
        """
        # EGG_EVO: This sql request is the same in both cases (int/float), but...
        # Also send mirror blocks.
        self._ledger_cursor.execute("SELECT * FROM transactions WHERE abs(block_height) >= ? "
                                    "AND abs(block_height) <= ? "
                                    "ORDER BY block_height, reward, timestamp",
                                    (block_height, block_height + limit))
        blocks = self._ledger_cursor.fetchall()
        # from_legacy only is valid for legacy db, so here we'll need to add context dependent code.
        # dbhandler will be aware of the db it runs on (simple flag) and call the right from_??? method.
        # Transaction objects - themselves - are db agnostic.
        if self.legacy_db:
            transaction_list = [Transaction.from_legacy(entry) for entry in blocks]
        else:
            transaction_list = [Transaction.from_v2(entry) for entry in blocks]
        return TransactionsList(transaction_list)

    @timeit
    def blocks_to_ledger(self, test: Block):
        for tx in test.transactions:  # we want to save to ledger db
            self._ledger_cursor.execute(SQL_TO_TRANSACTIONS_V2, tx.to_bin_tuple(sqlite_encode=True))
        self._ledger_db.commit()

    @timeit
    def miscs_to_ledger(self, test: List):
        for diff in test:  # we want to save to ledger db
            self._ledger_cursor.execute(SQL_TO_MISC_V2, diff)
        self._ledger_db.commit()

    @timeit
    def get_miscs(self, block_height: int=0, limit: int=10) -> List:
        """
        Returns a List of tuple
        :param block_height:
        :param limit:
        :return: a list of records.
        """
        # EGG_EVO: This sql request is the same in both cases (int/float), but...
        # print("get_miscs", block_height, limit)
        self._ledger_cursor.execute("SELECT * FROM misc WHERE block_height >= ? AND block_height <= ? ORDER BY block_height", (block_height, block_height + limit))
        miscs = self._ledger_cursor.fetchall()
        return miscs

    def block_height_max(self) -> int:
        self._ledger_cursor.execute("SELECT max(block_height) FROM transactions")
        res = self._ledger_cursor.fetchone()[0]
        res = int(res) if res else 0
        return res

    def block_height_max_diff(self) -> int:
        self._ledger_cursor.execute("SELECT max(block_height) FROM misc")
        res = self._ledger_cursor.fetchone()[0]
        res = int(res) if res else 0
        return res

    def block_height_max_hyper(self) -> int:
        self._hyper_cursor.execute("SELECT max(block_height) FROM transactions")
        return int(self._hyper_cursor.fetchone()[0])

    def block_height_max_diff_hyper(self) -> int:
        self._hyper_cursor.execute("SELECT max(block_height) FROM misc")
        return int(self._hyper_cursor.fetchone()[0])

    """
    def last_block_hash(self) -> str:
        # returns last block hash from live data as hex string - dupped from dbhandler
        self._ledger_cursor.execute( "SELECT block_hash FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1")
        # EGG_EVO: if new db, convert bin to hex
        return self._ledger_cursor.fetchone()[0]

    def last_block_timestamp(self) -> float:
        #  Returns the timestamp (python float) of the latest known block - dupped from dbhandler
        self._ledger_cursor.execute("SELECT timestamp FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1")
        return self._ledger_cursor.fetchone()[0]  # timestamps do not need quantize
    """

    def rollback(self, block_height: int) -> None:
        """Specific rollback method for single user mode"""
        self.logger.status_log.warning(f"Rolling back below: {block_height} (Solo)")
        # EGG: I dupped code there, I'm not proud of that. To be handled in a more generic way (solo/db handler)
        # Good thing is this is not db format dependant.
        #db_handler.rollback_under(block_height)
        self._ledger_cursor.execute("DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?",
                       (block_height, -block_height,))
        self._ledger_cursor.execute("DELETE FROM misc WHERE block_height >= ?", (block_height,))
        self._ledger_db.commit()
        self._hyper_cursor.execute("DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?",
                        (block_height, -block_height,))
        self._hyper_cursor.execute("DELETE FROM misc WHERE block_height >= ?", (block_height,))
        self._hyper_db.commit()
        # rollback indices
        #db_handler.tokens_rollback(block_height)
        try:
            self._index_cursor.execute("DELETE FROM tokens WHERE block_height >= ?;", (block_height,))
            self._index_db.commit()
            self.logger.app_log.info(f"Rolled back the token index below {(block_height)}")
        except Exception as e:
            self.logger.app_log.error(f"Failed to roll back the token index below {(block_height)} due to {e}")
            # Maybe it would be better (solo mode, once only at start) to just quit on error there and above, to avoid starting with a corrupted state.

        #db_handler.aliases_rollback(block_height)
        try:
            self._index_cursor.execute("DELETE FROM aliases WHERE block_height >= ?;", (block_height,))
            self._index_db.commit()
            self.logger.app_log.info(f"Rolled back the alias index below {(block_height)}")
        except Exception as e:
            self.logger.app_log.error(f"Failed to roll back the alias index below {(block_height)} due to {e}")

        self.logger.status_log.info(f"Chain rolled back below {block_height} (Solo)")

    def prepare_hypo(self) -> None:
        """avoid double processing by renaming Hyperblock addresses to Hypoblock"""
        if self._hyper_cursor is None:
            # No hyper yet, nothing to do
            self.logger.status_log.debug("Prepare_hypo was avoided")
            return
        self._hyper_cursor.execute("UPDATE transactions SET address = 'Hypoblock' WHERE address = 'Hyperblock'")
        self._hyper_db.commit()

    def open_temp_hyper(self) -> None:
        temp_db_name = self.config.ledger_path+'.temp'
        if not path.isfile(temp_db_name):
            self.logger.app_log.error(f"Unable to find {temp_db_name} temp db")
            sys.exit()
        self._hyper_db = sqlite3.connect(temp_db_name, timeout=1)
        if self.trace_db_calls:
            self._hyper_db.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "HDD2"))
        self._hyper_db.text_factory = str
        self._hyper_db.execute('PRAGMA case_sensitive_like = 1;')
        self._hyper_cursor = self._hyper_db.cursor()
        for sql in V2_MINIMAL_INDICES_CREATE:
            self._hyper_cursor.execute(sql)
            self._hyper_db.commit()

    def distinct_hyper_recipients(self, depth_specific: int) -> Tuple[str]:
        """Returns all recipients from hyper, at the given depth"""
        self._hyper_cursor.execute(
            "SELECT distinct(recipient) FROM transactions WHERE (block_height < ? AND block_height > ?)",
            (depth_specific, -depth_specific,))  # new addresses will be ignored until depth passed
        res = self._hyper_cursor.fetchall()
        return tuple((str(item[0]) for item in res))

    def update_hyper_balance_at_height_legacy(self, address: str, depth_specific: int) -> Decimal:
        """Used for hyper compression. Returns balance at given height and updates hyper."""
        # EGG_EVO: This method will have to be aware of the DB type, since balance calc will use different queries
        # solo handler will embed a dedicated flag and use a dynamic method here
        credit = Decimal("0")
        for entry in self._hyper_cursor.execute(
                "SELECT amount,reward FROM transactions WHERE recipient = ? "
                "AND (block_height < ? AND block_height > ?);",
                (address, depth_specific, -depth_specific)):
            try:
                credit = quantize_eight(credit) + quantize_eight(entry[0]) + quantize_eight(entry[1])
                credit = 0 if credit is None else credit
            except Exception:
                credit = 0

        debit = Decimal("0")
        for entry in self._hyper_cursor.execute(
                "SELECT amount,fee FROM transactions WHERE address = ? AND (block_height < ? AND block_height > ?);",
                (address, depth_specific, -depth_specific)):
            try:
                debit = quantize_eight(debit) + quantize_eight(entry[0]) + quantize_eight(entry[1])
                debit = 0 if debit is None else debit
            except Exception:
                debit = 0

        end_balance = quantize_eight(credit - debit)

        if end_balance > 0:
            timestamp = str(ttime())
            # Kept for compatibility, but take note that "0" as signature and privkey is not homogeneous
            # (can't be b64 decoded nor converted to bin like the regular fields)
            self._hyper_cursor.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                depth_specific - 1, timestamp, "Hyperblock", address, str(end_balance), "0", "0", "0", "0",
                "0", "0", "0"))

        return end_balance

    def update_hyper_balance_at_height(self, address: str, depth_specific: int) -> Union[Decimal, int]:
        """Used for hyper compression. Returns balance at given height and updates hyper."""
        # EGG_EVO: This method is aware of the DB type, since balance calc uses different queries
        if self.legacy_db:
            return self.update_hyper_balance_at_height_legacy(address, depth_specific)

        self.logger.app_log.debug(f"Update Hyper Balance v2 for {address}")
        res = self._hyper_cursor.execute(
                "SELECT sum(amount + reward) FROM transactions WHERE recipient = ? AND (block_height < ? AND block_height > ?)",
                (address, depth_specific, -depth_specific))
        credit = res.fetchone()[0]
        if credit is None:
            credit = 0
        res = self._hyper_cursor.execute(
            "SELECT sum(amount + fee) FROM transactions WHERE address = ? AND (block_height < ? AND block_height > ?);",
            (address, depth_specific, -depth_specific))
        debit = res.fetchone()[0]
        if debit is None:
            debit = 0
        end_balance = int(credit) - int(debit)
        # print(credit, debit, end_balance)

        if end_balance > 0:
            timestamp = str(ttime())
            # Kept for compatibility, but take note that "0" as signature and privkey is not homogeneous
            # (can't be b64 decoded nor converted to bin like the regular fields)
            self._hyper_cursor.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                depth_specific - 1, timestamp, "Hyperblock", address, end_balance, "0", "0", "0", "0",
                "0", "0", "0"))

        return end_balance

    def cleanup_hypo(self, depth_specific: int) -> None:
        """Cleanup after hyper recompression  at depth_specific - Not db type dependant"""
        # TODO: check we have the correct indices at this stage, this is the longuest step.
        # print(f"DELETE FROM transactions WHERE address != 'Hyperblock' AND block_height < {depth_specific} AND block_height > {-depth_specific} ...")
        self.logger.status_log.info(f"Cleaning up hyper transactions......")
        self._hyper_cursor.execute(
            "DELETE FROM transactions WHERE address != 'Hyperblock' AND block_height < ? AND block_height > ?",
            (depth_specific, -depth_specific))
        # print(f"DELETE FROM misc WHERE block_height < {depth_specific} AND block_height > {-depth_specific} ...")
        self.logger.status_log.info(f"Cleaning up hyper misc...")
        self._hyper_cursor.execute("DELETE FROM misc WHERE block_height < ? AND block_height > ?",
                                   (depth_specific, -depth_specific))  # remove diff calc
        self._hyper_db.commit()
        self.logger.status_log.info("Defragmenting hyper...")
        self._hyper_cursor.execute("VACUUM")  # Can take some time

    def db_to_ram(self, source_db: str, dest_ram_db: str) -> sqlite3.Connection:
        """Copies source db to provided ram instance"""
        if self.py_version >= 370:
            target = sqlite3.connect(dest_ram_db, uri=True, isolation_level=None, timeout=1)
            if self.trace_db_calls:
                target.set_trace_callback(
                    functools.partial(sql_trace_callback, self.logger.app_log, "TEMP-TARGET"))
            temp_source = sqlite3.connect(source_db, uri=True, isolation_level=None, timeout=1)
            if self.trace_db_calls:
                temp_source.set_trace_callback(
                    functools.partial(sql_trace_callback, self.logger.app_log, "TEMP-SOURCE"))
            temp_source.backup(target)
            temp_source.close()
        else:
            # Older python version do not have a backup method
            self.logger.app_log.warning("Using pre Python3.7 method")
            temp_source = sqlite3.connect(source_db, timeout=1)
            if self.trace_db_calls:
                temp_source.set_trace_callback(
                    functools.partial(sql_trace_callback, self.logger.app_log, "TEMP-SOURCE"))
            target = sqlite3.connect(dest_ram_db, uri=True, timeout=1, isolation_level=None)
            if self.trace_db_calls:
                target.set_trace_callback(
                    functools.partial(sql_trace_callback, self.logger.app_log, "TEMP-TARGET"))
                target.text_factory = str
            query = "".join(line for line in temp_source.iterdump())
            target.executescript(query)
            temp_source.close()
        return target

    def _sequencing_check(self, sequencing_last, cursor, name) -> int:
        y = 0
        for row in cursor.execute(
                "SELECT block_height FROM transactions WHERE reward != 0 AND block_height >= ? ORDER BY block_height ASC",
                (sequencing_last,)):
            y_init = row[0]
            if y < 1:
                y = y_init
            if row[0] != y:
                self.logger.status_log.warning(f"Chain {name} transaction sequencing error at: {row[0]}. {row[0]} instead of {y}")
                self.rollback(y)  # Will also rollback the other db, misc, tokens and aliases
                self.logger.status_log.info(
                    f"Due to a sequencing issue at block {y}, chain has been rolled back and will be resynchronized")
                return y
            y += 1
        return y

    def sequencing_check(self):
        """Quick check of block sequence.
        Does **not** check sigs nor hash, just that there is no gap nor dup blocks heights"""
        try:
            with open(self.config.get_db_path("sequencing_last"), 'r') as filename:
                sequencing_last = int(filename.read())
        except:
            self.logger.status_log.warning("Sequencing anchor not found, Checking whole chain")
            sequencing_last = 0
        self.logger.status_log.info(f"Testing chain sequencing, starting with block {sequencing_last}")
        y1 = self._sequencing_check(sequencing_last, self._ledger_cursor, "Ledger")
        y2 = self._sequencing_check(sequencing_last, self._hyper_cursor, "Hyper")

        # perform test on misc table - start at 1300000 min
        start = max(1300000, sequencing_last)
        y = 0
        for row in self._ledger_cursor.execute("SELECT block_height FROM misc WHERE block_height > ? ORDER BY block_height ASC",
                             (start,)):
            y_init = row[0]
            if y < 1:
                y = y_init
                # print(y)
            if row[0] != y:
                self.logger.status_log.warning(
                    f"Chain Index sequencing error at: {row[0]}. {row[0]} instead of {y}")
                self.rollback(y)
                self.logger.status_log.info(
                    f"Due to a sequencing issue at block {y}, chain has been rolled back and will be resynchronized")
            y = y + 1

        self.logger.status_log.info(f"Chains sequencing test complete.")
        y3 = y
        y = min(y1, y2, y3)
        if y > 2000:
            self.logger.status_log.info(f"Set new sequencing anchor to {y}")
            with open(self.config.get_db_path("sequencing_last"), 'w') as filename:
                filename.write(str(y - 1000))  # room for rollbacks

    def verify(self):
        # deeper check of the chain, including sig and hashes.
        try:
            self.logger.status_log.info("Blockchain verification started...")
            # verify blockchain
            self._ledger_cursor.execute("SELECT Count(*) FROM transactions")
            db_rows = self._ledger_cursor.fetchone()[0]
            self.logger.status_log.debug("Total steps: {}".format(db_rows))
            # verify genesis
            try:
                self._ledger_cursor.execute("SELECT block_height, recipient FROM transactions WHERE block_height = 1")
                result = self._ledger_cursor.fetchall()[0]
                block_height = result[0]
                genesis = result[1]
                self.logger.status_log.info(f"Genesis: {genesis}")
                if str(genesis) != self.config.genesis and int(
                        block_height) == 0:
                    self.logger.app_log.error("Invalid genesis address")
                    sys.exit(1)
            except:
                self.logger.status_log.info("Hyperblock mode in use")
            # verify genesis
            db_hashes = {
                '27258-1493755375.23': 'acd6044591c5baf121e581225724fc13400941c7',
                '27298-1493755830.58': '481ec856b50a5ae4f5b96de60a8eda75eccd2163',
                '30440-1493768123.08': 'ed11b24530dbcc866ce9be773bfad14967a0e3eb',
                '32127-1493775151.92': 'e594d04ad9e554bce63593b81f9444056dd1705d',
                '32128-1493775170.17': '07a8c49d00e703f1e9518c7d6fa11d918d5a9036',
                '37732-1493799037.60': '43c064309eff3b3f065414d7752f23e1de1e70cd',
                '37898-1493799317.40': '2e85b5c4513f5e8f3c83a480aea02d9787496b7a',
                '37898-1493799774.46': '4ea899b3bdd943a9f164265d51b9427f1316ce39',
                '38083-1493800650.67': '65e93aab149c7e77e383e0f9eb1e7f9a021732a0',
                '52233-1493876901.73': '29653fdefc6ca98aadeab37884383fedf9e031b3',
                '52239-1493876963.71': '4c0e262de64a5e792601937a333ca2bf6d6681f2',
                '52282-1493877169.29': '808f90534e7ba68ee60bb2ea4530f5ff7b9d8dea',
                '52308-1493877257.85': '8919548fdbc5093a6e9320818a0ca058449e29c2',
                '52393-1493877463.97': '0eba7623a44441d2535eafea4655e8ef524f3719',
                '62507-1493946372.50': '81c9ca175d09f47497a57efeb51d16ee78ddc232',
                '70094-1494032933.14': '2ca4403387e84b95ed558e7c9350c43efff8225c',
                '107579-1495499385.55': '4c01d491b35583e6a880a016bd08ac992b25e946',
                '109032-1495581934.71': 'e81caa48f4e04272b764bc58a0a68e07e44e50be',
                '109032-1495581968.35': '26419351bc5cea781ac4b41c6a5ea757585ddbe4',
                '109032-1495581997.74': 'ad634a23b69b6d5cf8514d6e3a5d8c7311240b58',
                '109032-1495582052.39': '9a5815e1aaa50c129fad05d9502b2b83518ab0c6',
                '109032-1495582073.80': 'c3ecbc412ed82539f866d5ce95a46df8f1bbc992',
                '109032-1495582093.85': 'eff64357d0320c77c7774bdffbf0032bfbbcf40a',
                '109032-1495582137.48': 'e3f34c3b0608a2276c3d179fe2091ae3b5b33458',
                '109032-1495582167.81': 'dd9cf2436672c2b2b5a6cc230fe0bf548d3856c9',
                '109032-1495582188.16': '978f7e42a98d00dd0b520fa330aec136976f2b10',
                '109032-1495582212.49': '7991d2efed6c21509d104c4bb9a41db873a186bf',
                '109032-1495582261.99': '496491a8243f92ef216b308a4b8e160f9ac8902f',
                '109032-1495582281.92': 'c3eb75f099546cd1afec051194a4f0ce72808811',
                '109032-1495582326.49': 'f6a2d15c18692c1507a2f0f31fb98ed126f6285d',
                '109032-1495582345.66': 'c61b3073ae3345146589ef31a565874f3506aa3b',
                '109032-1495582362.29': '91f0c2eb7c7d8badf279130f9d8810c31bca0738',
                '109032-1495582391.27': '86ba22a36ad1604fcbeccb7b53a4f1878e42e7c8',
                '109032-1495582414.48': '6c7fb968c6df05e6c41a2b57417265fcd21cf049',
                '109032-1495582431.57': '85b846479fcf65e0b0407ae5a62a43e548a05b0f',
                '109032-1495582452.90': 'be5985949a9f9c05e1087c373179f4699c9a285b',
                '109032-1495582474.30': '5f8f33ccd3861dbaf3a9de679b2c57bb4dc6aa9e',
                '109032-1495582491.33': 'bbca4c2cfb3b073dc26e2882a0c635b4f545c796',
                '109032-1495582519.66': 'e8acaf4c324ad6380e95f05b5488507c1f677f0d',
                '109032-1495582552.33': '1d19efbe74f1dcc0f3eecc97e57602a854cee80c',
                '109032-1495582566.89': '6f855517a5a15764275b6b473df3d8b0424e14ca',
                '109032-1495582578.06': '55d4af749af916a4af4190106133c4bd618fccd8',
                '109032-1495582590.27': '312009efa7d8fbf3bd788704b9f4f9f4cca2bf6b',
                '109032-1495582605.78': '92dd15a93e5fdc6d419e40e73c738618830778bf',
                '109032-1495582629.72': 'c90a2baeeffb8283a781787af1b9a2d4e7390768',
                '109032-1495582650.66': '76919616b3b26a13fbfccdb1f6a70478ecc99f5b',
                '109032-1495582673.69': '8228a29ec46f4c017c983073e4bf52306d30a20e',
                '109032-1495582692.76': 'd7f83c9cda72380748c9e697e864e64f371b0c87',
                '109032-1495582705.82': 'd87f74eaa82d2566129d45f0040c6a796e6c00d6',
                '109032-1495582718.75': '41e4b6595ecc0087b7a370c08b9e911ddf70621e',
                '109032-1495582731.23': '11b95e7f210e616a39f1f3fc67055fed34d06d58',
                '109032-1495582743.92': '118bcaf2a4064b64d1f48aaae2382ad9505027a4',
                '109032-1495582756.92': '67a81e040ebf257024b56bf99de5763079d9c38b',
                '109032-1495582768.07': '0afbcd111bedf61f67ee5eafc2e2792991254f33',
                '109032-1495582780.58': 'd7351ae8a29e27327fc0952ce27405be487d4dcf',
                '109032-1495582793.76': '56eca3202795443669b35af18c316a0bdc0166ab',
                '109032-1495582810.24': '4841f3f01cd986863110fc9e61622c3598d7f6c4',
                '109032-1495582823.22': '7a4244e0549fc2da9fa15328506f5afeb7fc36f4',
                '109032-1495582833.89': '7af9fc46b2d70c5070737c0a1ecaccac11f420dd',
                '109032-1495582860.55': 'eb8742ae1ec649e01b5ca5064da52b8be75a0be1',
                '109034-1495582892.79': 'ef00516b9f723fe7eeed98465a2521f1d1910189',
                '109034-1495582904.05': '56172b6625a163cd1e90e7676b33774b30dbe9a6',
                '109034-1495582915.38': '90290d53ff8f16ffa9cf8ca5add1f155612dbefe',
                '109035-1495582926.98': '8c5fc98e23948df56e9c05acc73e0f8f18df176e',
                '109035-1495582943.53': '8c6ececc083b4fcadac2022f815407c685a7fcaf',
                '109035-1495582976.65': '4cf4d45d0c98be3f1a8553f5ff2d183770ec1d27',
                '109035-1495583322.14': '8d1c49a5c3e029a3c420a5361f3ed0ef629a3e91'
            }
            invalid = 0

            # EGG_EVO - will need int/bin case taken care of
            for row in self._ledger_cursor.execute(
                    'SELECT * FROM transactions WHERE block_height > 0 and reward = 0 ORDER BY block_height'):  # native sql fx to keep compatibility
                db_block_height = str(row[0])
                db_timestamp = '%.2f' % (quantize_two(row[1]))
                db_address = str(row[2])[:56]
                db_recipient = str(row[3])[:56]
                db_amount = '%.8f' % (quantize_eight(row[4]))
                db_signature_enc = str(row[5])[:684]
                db_public_key_b64encoded = str(row[6])[:1068]
                db_operation = str(row[10])[:30]
                db_openfield = str(row[11])  # no limit for backward compatibility
                db_transaction = str((db_timestamp, db_address, db_recipient, db_amount, db_operation, db_openfield))\
                    .encode("utf-8")
                try:
                    # Signer factory is aware of the different tx schemes, and will b64 decode public_key once or twice as needed.
                    SignerFactory.verify_bis_signature(db_signature_enc, db_public_key_b64encoded, db_transaction,
                                                       db_address)
                except Exception as e:
                    sha_hash = SHA.new(db_transaction)
                    try:
                        if sha_hash.hexdigest() != db_hashes[db_block_height + "-" + db_timestamp]:
                            self.logger.app_log.warning(
                                "Signature validation problem: {} {}".format(db_block_height, db_transaction))
                            invalid = invalid + 1
                    except Exception as e:
                        self.logger.app_log.warning(
                            "Signature validation problem: {} {}".format(db_block_height, db_transaction))
                        invalid = invalid + 1

            if invalid == 0:
                self.logger.status_log.info("All transactions in the local ledger are valid")
            else:
                self.logger.app_log.error("Full transactions check unsuccessful")
                sys.exit(1)

        except Exception as e:
            self.logger.app_log.warning("Error: {}".format(e))
            raise

    def hyper_commit(self) -> None:
        self._hyper_db.commit()

    def close(self) -> None:
        if self._index_db:
            self._index_db.close()
        if self._ledger_db:
            self._ledger_db.close()
        if self._hyper_db:
            self._hyper_db.close()


