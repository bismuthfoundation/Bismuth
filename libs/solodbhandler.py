"""
Sqlite3 Database handler module for Bismuth nodes
It's very alike DbHandler object, but
This class is to be used for single user mode, when node bootsup and checks/compress/fixes the db.
Splitting means some slight dup code, but since the operations in solo mode are so different than from later ones,
it's better for clarity and maintenance to have them in a dedicated class.
"""

import sqlite3
import sys
from decimal import Decimal
from bismuthcore.compat import quantize_two, quantize_eight
from bismuthcore.transaction import Transaction
from bismuthcore.block import Block
from bismuthcore.helpers import fee_calculate
import functools
from time import time as ttime
from libs.fork import Fork

from typing import Union, List, Tuple, Iterator
from typing import TYPE_CHECKING
if TYPE_CHECKING:
  from libs.node import Node
  from libs.logger import Logger
  # from libs.config import Config


__version__ = "1.0.2"


def sql_trace_callback(log, sql_id, statement: str):
    line = f"SQL[{sql_id}] {statement}"
    log.warning(line)


class SoloDbHandler:

    def __init__(self, node: "Node", trace_db_calls: bool=False):
        self.logger = node.logger
        self.trace_db_calls = trace_db_calls

        self._index_db = sqlite3.connect(node.index_db, timeout=1)
        if self.trace_db_calls:
            self._index_db.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "INDEX"))
        self._index_db.text_factory = str
        self._index_db.execute('PRAGMA case_sensitive_like = 1;')
        self._index_cursor = self._index_db.cursor()  # Cursor to the index db

        self._ledger_db = sqlite3.connect(node.config.ledger_path, timeout=1)
        if self.trace_db_calls:
            self._ledger_db.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "HDD"))
        self._ledger_db.text_factory = str
        self._ledger_db.execute('PRAGMA case_sensitive_like = 1;')
        self._ledger_cursor = self._ledger_db.cursor()

        self._hyper_db = sqlite3.connect(node.config.hyper_path, timeout=1)
        if self.trace_db_calls:
            self._hyper_db.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "HDD2"))
        self._hyper_db.text_factory = str
        self._hyper_db.execute('PRAGMA case_sensitive_like = 1;')
        self._hyper_cursor = self._hyper_db.cursor()

    def transactions_schema(self) -> list:
        """Returns the structure of the "transactions" table from the ledger db"""
        res = self._ledger_cursor.execute("PRAGMA table_info('transactions')")
        return res.fetchall()

    def block_height_max(self) -> int:
        self._ledger_cursor.execute("SELECT max(block_height) FROM transactions")
        return int(self._ledger_cursor.fetchone()[0])

    def block_height_max_diff(self) -> int:
        self._ledger_cursor.execute("SELECT max(block_height) FROM misc")
        return int(self._ledger_cursor.fetchone()[0])

    def block_height_max_hyper(self) -> int:
        self._hyper_cursor.execute("SELECT max(block_height) FROM transactions")
        return int(self._hyper_cursor.fetchone()[0])

    def block_height_max_diff_hyper(self) -> int:
        self._hyper_cursor.execute("SELECT max(block_height) FROM misc")
        return int(self._hyper_cursor.fetchone()[0])

    def rollback(self, block_height: int) -> None:
        """Specific rollback method for single user mode"""
        self.logger.app_log.warning(f"Status: Rolling back below: {block_height} (Solo)")
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
            self.logger.app_log.warning(f"Rolled back the token index below {(block_height)}")
        except Exception as e:
            self.logger.app_log.warning(f"Failed to roll back the token index below {(block_height)} due to {e}")
            # Maybe it would be better (solo mode, once only at start) to just quit on error there and above, to avoid starting with a corrupted state.

        #db_handler.aliases_rollback(block_height)
        try:
            self._index_cursor.execute("DELETE FROM aliases WHERE block_height >= ?;", (block_height,))
            self._index_db.commit()
            self.logger.app_log.warning(f"Rolled back the alias index below {(block_height)}")
        except Exception as e:
            self.logger.app_log.warning(f"Failed to roll back the alias index below {(block_height)} due to {e}")

        self.logger.app_log.warning(f"Status: Chain rolled back below {block_height} (Solo)")

    def prepare_hypo(self) -> None:
        """avoid double processing by renaming Hyperblock addresses to Hypoblock"""
        self._hyper_cursor.execute("UPDATE transactions SET address = 'Hypoblock' WHERE address = 'Hyperblock'")
        self._hyper_db.commit()

    def distinct_hyper_recipients(self, depth_specific: int) -> Iterator[str]:
        """Returns all recipients from hyper, at the given depth"""
        self._hyper_cursor.execute(
            "SELECT distinct(recipient) FROM transactions WHERE (block_height < ? AND block_height > ?)",
            (depth_specific, -depth_specific,))  # new addresses will be ignored until depth passed
        res = self._hyper_cursor.fetchall()
        return (item[0] for item in res)

    def update_hyper_balance_at_height(self, address: str, depth_specific: int) -> Decimal:
        """Used for hyper compression. Returns balance at given height and updates hyper."""
        # EGG_EVO: This method will have to be aware of the DB type, since balance calc will use different queries
        # solo handler will embed a dedicated flag and use a dynamic method here
        credit = Decimal("0")
        for entry in self._hyper_cursor.execute(
                "SELECT amount,reward FROM transactions WHERE recipient = ? AND (block_height < ? AND block_height > ?);",
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

    def cleanup_hypo(self, depth_specific: int) -> None:
        """Cleanup after hyper recompression  at depth_specific - Not db type dependant"""
        self._hyper_cursor.execute(
            "DELETE FROM transactions WHERE address != 'Hyperblock' AND (block_height < ? AND block_height > ?);",
            (depth_specific, -depth_specific,))
        self._hyper_cursor.execute("DELETE FROM misc WHERE (block_height < ? AND block_height > ?);",
                                   (depth_specific, -depth_specific,))  # remove diff calc
        self._hyper_db.commit()
        self.logger.app_log.warning("Defragmenting hyper...")
        self._hyper_cursor.execute("VACUUM")  # Can take some time

    def hyper_commit(self) -> None:
        self._hyper_db.commit()

    def close(self) -> None:
        self._index_db.close()
        self._ledger_db.close()
        self._hyper_db.close()
