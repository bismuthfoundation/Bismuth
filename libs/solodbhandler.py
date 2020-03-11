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
from libs.fork import Fork

from typing import Union, List
from typing import TYPE_CHECKING
if TYPE_CHECKING:
  from libs.node import Node
  from libs.logger import Logger
  # from libs.config import Config


__version__ = "1.0.0"


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
