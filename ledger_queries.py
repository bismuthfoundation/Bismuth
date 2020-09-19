"""
This module hosts LedgerQueries, a class grouping all data extraction queries from the DB.
It is closely related to db handler, as it relies on the same db engine and structure.
This module only make use of a single DB handler, and suppose all data will be taken from that one.
In the context of wallet servers or hypernodes, this supposes full ledger, on disk.

The goal of this class is to provide optimized requests to be used by plugins,
so they don't have to deal with low level, and possibly changing, db structure.

Borrows code from Hypernodes, pow_interface

Still very alpha and not optimized.
"""

# TODO EGG: used by hypernodes plugin. low level sql, dup with ledger queries...
# HN plugin will need a rework, either amend dbHandler with hn required queries, either reworking ledger_queries

import math
from logging import getLogger
from time import sleep

# from typing import Union

__version__ = "0.0.5"


K1E8 = 100000000

SQL_BLOCK_HEIGHT_PRECEDING_TS_SLOW = (
    "SELECT block_height FROM transactions WHERE timestamp <= ? "
    "ORDER BY block_height DESC limit 1"
    )

SQL_BLOCK_HEIGHT_PRECEDING_TS = (
    "SELECT max(block_height) FROM transactions WHERE timestamp <= ? AND reward > 0"
    )

SQL_BLOCK_HEIGHT_FOLLOWING_TS = (
    "SELECT block_height FROM transactions WHERE timestamp > ? AND reward > 0 LIMIT 1"
    )

SQL_TS_OF_BLOCK = (
    "SELECT timestamp FROM transactions WHERE reward > 0 AND block_height = ?"
    )

SQL_REGS_FROM_TO = (
    "SELECT block_height, address, operation, openfield, timestamp FROM transactions "
    "WHERE block_height >= ? AND block_height <= ? "
    "AND (operation='hypernode:register' OR operation='hypernode:unregister') "
    "ORDER BY block_height ASC"
    )

"""
SQL_QUICK_BALANCE_CREDITS = "SELECT sum(amount+reward) FROM transactions WHERE recipient = ? AND block_height <= ?"

SQL_QUICK_BALANCE_DEBITS = (
    "SELECT sum(amount+fee) FROM transactions WHERE address = ? AND block_height <= ?"
    )
"""

SQL_QUICK_BALANCE_ALL = (
    "SELECT sum(a.amount+a.reward)-debit FROM transactions as a , "
    "(SELECT sum(b.amount+b.fee) as debit FROM transactions b "
    "WHERE address = ? AND block_height <= ?) "
    "WHERE a.recipient = ? AND a.block_height <= ?"
    )

SQL_QUICK_BALANCE_ALL_MIRROR = (
    "SELECT sum(a.amount+a.reward)-debit FROM transactions as a , "
    "(SELECT sum(b.amount+b.fee) as debit FROM transactions b "
    "WHERE address = ? AND abs(block_height) <= ?) "
    "WHERE a.recipient = ? AND abs(a.block_height) <= ?"
    )

SQL_LAST_BLOCK_TS = (
    "SELECT timestamp FROM transactions WHERE block_height = "
    "(SELECT max(block_height) FROM transactions) LIMIT 0, 1"
    )

SQL_LAST_BLOCK_HEIGHT = (
    "SELECT max(block_height) FROM transactions"
    )


app_log = getLogger()


class LedgerQueries:
    @classmethod
    def execute(cls, db, sql: str, param: tuple = None, many: bool = False):
        """
        Safely _execute the request

        :param db:
        :param sql:
        :param param:
        :param many: If True, will use an executemany call with param being a list of params.
        :return: cursor
        """
        tries = 0
        while True:
            try:
                if many:
                    cursor = db.executemany(sql, param)
                elif param:
                    cursor = db.execute(sql, param)
                else:
                    cursor = db.execute(sql)
                break
            except Exception as e:
                app_log.warning("LedgerQueries: {}".format(sql))
                app_log.warning("LedgerQueries retry reason: {}".format(e))
                tries += 1
                if tries >= 10:
                    app_log.error("Database Error, closing")
                    # raise ValueError("Too many retries")
                    exit()
                sleep(0.1)
        return cursor

    @classmethod
    def fetchone(cls, db, sql: str, param: tuple = None, as_dict: bool = False):
        """
        Fetch one and Returns data.

        :param db:
        :param sql:
        :param param:
        :param as_dict: returns result as a dict, default False.
        :return: tuple()
        """
        cursor = cls.execute(db, sql, param)
        data = cursor.fetchall()[0]
        if not data:
            return None
        if as_dict:
            return dict(data)
        return tuple(data)

    @classmethod
    def fetchall(cls, db, sql: str, param: tuple = None, as_dict: bool = False):
        """
        Fetch all and Returns data.

        :param db:
        :param sql:
        :param param:
        :param as_dict: returns result as a dict, default False.
        :return: tuple()
        """
        cursor = cls.execute(db, sql, param)
        data = cursor.fetchall()
        if not data:
            return None
        if as_dict:
            return [dict(line) for line in data]
        return list(data)

    @classmethod
    def reg_check_weight(cls, db, address: str, height: int, legacy: bool=True) -> int:
        """
        Calc rough estimate (not up to 1e-8) of the balance of an account at a certain point in the past.
        Raise if not enough for an HN, or return the matching Weight.

        Requires a full ledger.

        :param db: db cursor
        :param address:
        :param height:
        :param legacy:
        :return: weight (1, 2 or 3)
        """
        res = cls.fetchone(
            db, SQL_QUICK_BALANCE_ALL, (address, height, address, height)
        )
        # print(address, height, res)
        try:
            balance = res[0]
            if not legacy:
                balance = balance / K1E8
            weight = math.floor(balance / 10000)
            if weight > 3:
                weight = 3
        except Exception:
            weight = -1
        return weight

    @classmethod
    def quick_check_balance(cls, db, address: str, height: int, legacy: bool=True) -> int:
        """
        Calc rough estimate (not up to 1e-8) of the balance of an account at a certain point in the past.
        Raise if not enough for an HN, or return the matching Weight.

        Requires a full ledger.

        :param db: db cursor
        :param address:
        :param height:
        :param legacy:
        :return: balance
        """
        try:
            res = cls.fetchone(
                db, SQL_QUICK_BALANCE_ALL_MIRROR, (address, height, address, height)
            )
            balance = res[0]
            if not legacy:
                balance = balance / K1E8
        except Exception:
            balance = 0
        return balance

    @classmethod
    def get_block_before_ts(cls, db, a_timestamp, check_after=True):
        """
        Returns the last PoW block height preceding the given timestamp.
        If check_after, also checks that the pow chain has a later block.
        If not, just checks that the timestamp of last block is not older than 20 min.

        DB version insensible.

        :param a_timestamp:
        :return: block_height preceding the given TS
        """
        try:
            res = cls.fetchone(db, SQL_BLOCK_HEIGHT_PRECEDING_TS, (a_timestamp,))
            height1 = int(res[0]) if res else 0
            app_log.warning(
                "Block before ts {} height is {}".format(a_timestamp, height1)
            )
            if check_after:
                res = cls.fetchone(db, SQL_LAST_BLOCK_HEIGHT)
                height2 = int(res[0]) if res else 0
                if height2 - height1 <= 20:
                    app_log.warning("POW is late! Needs 20 block after {}".format(height1))
                    return 0
            return height1
        except Exception as e:
            app_log.warning("get_block_before_ts: {}".format(e))
            return 0

    @classmethod
    def get_last_block_ts(cls, db) -> float:
        """
        Returns the latest PoW block timestamp. DB Version insensible.
        """
        try:
            res = cls.fetchone(db, SQL_LAST_BLOCK_TS)
            ts = float(res[0])
            return ts
        except Exception as e:
            app_log.warning("get_last_block_ts: {}".format(e))
            return 0

    @classmethod
    def get_ts_of_block(cls, db, block_height: int) -> float:
        """
        Returns the timestamp of given POW block height. Insensible to DB version
        """
        try:
            res = cls.fetchone(db, SQL_TS_OF_BLOCK, (block_height,))
            ts = float(res[0])
            return ts
        except Exception as e:
            app_log.warning("get_last_block_ts: {}".format(e))
            return 0

    @classmethod
    def get_hn_regs_from_to(cls, db, from_pow: int, to_pow: int):
        """Insensible to DB Version"""
        res = cls.fetchall(db, SQL_REGS_FROM_TO, (from_pow, to_pow))
        return res
