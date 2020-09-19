"""
Sqlite3 Database handler module for Bismuth nodes
"""

import functools
import os
import re
import sqlite3
import sys
from decimal import Decimal
from sqlite3 import Binary
from time import sleep, time as ttime
from typing import TYPE_CHECKING
from typing import Union, List

from bismuthcore.block import Block
from bismuthcore.compat import quantize_eight
from bismuthcore.helpers import fee_calculate, K1E8
from bismuthcore.transaction import Transaction
from bismuthcore.transactionslist import TransactionsList
from libs.fork import Fork
from libs.helpers import blake2bhash_generate

if TYPE_CHECKING:
    from libs.node import Node
    from libs.mempool import Mempool  # for type hints
    from libs.logger import Logger


__version__ = "1.0.9"

"""
See https://gist.github.com/rianhunter/10bfcff17c18d112de16
Create and close cursors for temp reads instead of using the same shared one?
local temp cursor would make sure no transaction is left open and will close all cursors.
TODO: benchmark to see if cursor creation consumes much more time.
"""

ALIAS_REGEXP = r'^alias='
SQL_TO_TRANSACTIONS = "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
# Same but safer this way
SQL_TO_TRANSACTIONS_V2 = "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
SQL_TO_MISC = "INSERT INTO misc VALUES (?, ?)"


def sql_trace_callback(log, sql_id, statement: str):
    line = f"SQL[{sql_id}] {statement}"
    log.warning(line)


class DbHandler:
    # Define  slots. One instance per thread, can be significant.
    __slots__ = ("ram", "ledger_ram_file", "ledger_path", "hyper_path", "logger", "trace_db_calls", "index_db",
                 "index", "index_cursor", "hdd", "h", "hdd2", "h2", "conn", "c", "old_sqlite", "plugin_manager",
                 "legacy_db")

    def __init__(self, index_db: str, ledger_path: str, hyper_path: str, ram: bool, ledger_ram_file: str,
                 logger: "Logger", old_sqlite: bool=False, trace_db_calls: bool=False, plugin_manager=None,
                 legacy_db=True):
        """To be used only for tests - See .from_node() factory above."""
        self.legacy_db = legacy_db
        self.ram = ram
        self.ledger_ram_file = ledger_ram_file
        self.hyper_path = hyper_path
        self.logger = logger
        self.trace_db_calls = trace_db_calls
        self.index_db = index_db
        self.ledger_path = ledger_path
        self.old_sqlite = old_sqlite
        self.plugin_manager = plugin_manager

        self.index = sqlite3.connect(self.index_db, timeout=1)
        if self.trace_db_calls:
            self.index.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "INDEX"))
        self.index.text_factory = str
        self.index.execute('PRAGMA case_sensitive_like = 1')
        self.index_cursor = self.index.cursor()  # Cursor to the index db
        # EGG_EVO: cursors to be moved to private properties at a later stage.

        self.hdd = sqlite3.connect(self.ledger_path, timeout=1)
        if self.trace_db_calls:
            self.hdd.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "HDD"))
        self.hdd.text_factory = str
        # self.conn.execute('PRAGMA journal_mode = WAL')  # Comment on top of node.py says no
        self.hdd.execute('PRAGMA case_sensitive_like = 1')
        self.h = self.hdd.cursor()  # h is a Cursor to the - on disk - ledger db

        self.hdd2 = sqlite3.connect(self.hyper_path, timeout=1)
        if self.trace_db_calls:
            self.hdd2.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "HDD2"))
        self.hdd2.text_factory = str
        self.hdd2.execute('PRAGMA case_sensitive_like = 1')
        self.h2 = self.hdd2.cursor()  # h2 is a Cursor to the - on disk - hyper db

        if self.ram:
            self.conn = sqlite3.connect(self.ledger_ram_file, uri=True, isolation_level=None, timeout=1)
        else:
            self.conn = sqlite3.connect(self.hyper_path, uri=True, timeout=1)

        if self.trace_db_calls:
            self.conn.set_trace_callback(functools.partial(sql_trace_callback, self.logger.app_log, "CONN"))
        self.conn.execute('PRAGMA journal_mode = WAL')
        self.conn.execute('PRAGMA case_sensitive_like = 1')
        self.conn.text_factory = str
        self.c = self.conn.cursor()  # c is a Cursor to either on disk hyper db or in ram ledger, depending on config.
        # It's the working db for all recent queries.

    @classmethod
    def from_node(cls, node: "Node") -> "DbHandler":
        """All params we need are known to node."""
        return DbHandler(node.index_db, node.config.ledger_path, node.config.hyper_path, node.config.ram,
                         node.ledger_ram_file, node.logger, old_sqlite=node.config.old_sqlite,
                         trace_db_calls=node.config.trace_db_calls, plugin_manager=node.plugin_manager,
                         legacy_db=node.config.legacy_db)

    # ==== Aliases ==== #

    def addfromalias(self, alias: str) -> str:
        # TODO: I would rename to address_from_alias() for naming consistency and avoid confusion with "add" verb.
        """
        Lookup the address matching the provided alias
        :param alias:
        :return:
        """
        self._execute_param(self.index_cursor, "SELECT address FROM aliases WHERE alias = ? "
                                               "ORDER BY block_height ASC LIMIT 1",
                            (alias, ))
        try:
            address_fetch = self.index_cursor.fetchall()[0][0]
        except Exception:
            address_fetch = "No alias"
        return address_fetch

    def alias_exists(self, alias: str) -> bool:
        # very similar to above, but returns a bool
        """
        Lookup the address matching the provided alias
        :param alias:
        :return:
        """
        address_fetch = False
        self._execute_param(self.index_cursor, "SELECT address FROM aliases WHERE alias = ? "
                                               "ORDER BY block_height ASC LIMIT 1",
                            (alias, ))
        try:
            address_fetch = self.index_cursor.fetchall()[0][0] is not None
        except Exception:
            pass
        return address_fetch

    def aliasget(self, alias_address: str) -> List[List[str]]:
        self._execute_param(self.index_cursor, "SELECT alias FROM aliases WHERE address = ? ",
                            (alias_address, ))
        result = self.index_cursor.fetchall()
        if not result:
            result = [[alias_address]]
        return result

    def aliasesget(self, aliases_request: str) -> List[tuple]:
        results = []
        for alias_address in aliases_request:
            self._execute_param(self.index_cursor, (
                "SELECT alias FROM aliases WHERE address = ? ORDER BY block_height ASC LIMIT 1"),
                                (alias_address, ))
            try:
                result = self.index_cursor.fetchall()[0][0]
            except Exception:
                result = alias_address
            results.append(result)
        return results

    def aliases_rollback(self, height: int) -> None:
        """Rollback Alias index

        :param height: height index of token in chain

        Simply deletes from the `aliases` table where the block_height is
        greater than or equal to the :param height: and logs the new height

        returns None
        """
        try:
            self._execute_param(self.index_cursor, "DELETE FROM aliases WHERE block_height >= ?;", (height, ))
            self.commit(self.index)

            self.logger.status_log.warning(f"Rolled back the alias index below {height}")
        except Exception as e:
            self.logger.status_log.warning(f"Failed to roll back the alias index below {height} due to {e}")

    def aliases_update(self):
        """Updates the aliases index"""
        self._execute(self.index_cursor, "SELECT block_height FROM aliases ORDER BY block_height DESC LIMIT 1")
        try:
            alias_last_block = int(self.index_cursor.fetchall()[0][0])
        except Exception:
            alias_last_block = 0
        # Egg note: this is not the real last anchor. We use the last alias index as anchor.
        # If many blocks passed by since, every call to update will have to parse large data (with like% query).
        # We could have an anchor table in index .db , with real anchor from last check.
        # to be dropped in case of rollback ofc.
        self.logger.status_log.info("Alias anchor block: {}".format(alias_last_block))
        self.h.execute("SELECT block_height, address, openfield FROM transactions "
                       "WHERE openfield LIKE ? AND block_height >= ? "
                       "ORDER BY block_height ASC, timestamp ASC",
                       ("alias=%", alias_last_block))
        # include the anchor block in case indexation stopped there
        result = self.h.fetchall()
        for openfield in result:
            alias = re.sub(ALIAS_REGEXP, "", openfield[2])  # Remove leading "alias="
            # Egg: since the query filters on openfield beginning with "alias=", a [6:] may be as simple.
            self.logger.status_log.info(f"Processing alias registration: {alias}")
            try:
                self.index_cursor.execute("SELECT * from aliases WHERE alias = ? limit 0, 1", (alias, ))
                dummy = self.index_cursor.fetchall()[0]  # check for uniqueness
                self.logger.status_log.warning(f"Alias already registered: {alias} - Ignored.")
            except Exception:
                self.index_cursor.execute("INSERT INTO aliases VALUES (?,?,?)", (openfield[0], openfield[1], alias))
                self.index.commit()
                self.logger.status_log.info(f"Added alias to the database: {alias} from block {openfield[0]}")

    # ==== Tokens ==== #

    def tokens_user(self, tokens_address: str) -> List[str]:
        """
        Returns the list of tokens a specific user has or had.
        :param tokens_address:
        :return:
        """
        self.index_cursor.execute("SELECT DISTINCT token FROM tokens WHERE address OR recipient = ?",
                                  (tokens_address, ))
        result = self.index_cursor.fetchall()
        return result

    def tokens_rollback(self, height: int) -> None:
        """Rollback Token index
        :param height: height index of token in chain

        Simply deletes from the `tokens` table where the block_height is
        greater than or equal to the :param height: and logs the new height

        returns None
        """
        try:
            self._execute_param(self.index_cursor, "DELETE FROM tokens WHERE block_height >= ?", (height, ))
            self.commit(self.index)

            self.logger.status_log.info(f"Rolled back the token index below {height}")
        except Exception as e:
            self.logger.status_log.warning(f"Failed to roll back the token index below {height} due to {e}")

    def tokens_update(self):
        # TODO: move at init/Single user stage, not every run - Move into plugin as well
        self.index_cursor.execute("CREATE TABLE IF NOT EXISTS tokens "
                                  "(block_height INTEGER, timestamp, token, address, recipient, txid, amount INTEGER)")
        self.index.commit()

        self.index_cursor.execute("SELECT block_height FROM tokens ORDER BY block_height DESC LIMIT 1")
        try:
            token_last_block = int(self.index_cursor.fetchall()[0][0])
        except Exception:
            token_last_block = 0
        self.logger.status_log.info("Token anchor block: {}".format(token_last_block))
        self.c.execute("SELECT block_height, timestamp, address, recipient, signature, operation, openfield "
                       "FROM transactions "
                       "WHERE block_height >= ? AND operation = ? AND reward = 0 ORDER BY block_height ASC;",
                       (token_last_block, "token:issue"))
        results = self.c.fetchall()
        # self.logger.status_log.warning(results)
        tokens_processed = []

        for x in results:
            try:
                token_name = x[6].split(":")[0].lower().strip()
                try:
                    self.index_cursor.execute("SELECT * from tokens WHERE token = ? limit 0, 1", (token_name, ))
                    dummy = self.index_cursor.fetchall()[0]  # check for uniqueness
                    self.logger.status_log.warning("Token issuance already processed: {} - Ignored."
                                                   .format(token_name, ))
                except Exception:
                    if token_name not in tokens_processed:
                        block_height = x[0]
                        timestamp = x[1]
                        tokens_processed.append(token_name)
                        issued_by = x[3]
                        txid = x[4][:56]
                        total = x[6].split(":")[1]
                        # EGG Note: Maybe force this to be positive int?
                        self.index_cursor.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?,?)",
                                                  (block_height, timestamp, token_name, "issued",
                                                   issued_by, txid, total))
                        self.logger.status_log.info(f"Block height {block_height} - "
                                                    f"Timestamp {timestamp} - Txid {txid}")
                        self.logger.status_log.warning(f"New Token: {token_name} - "
                                                       f"Issued by: {issued_by} - Total amount: {total}")

                        if self.plugin_manager:
                            self.plugin_manager.execute_action_hook('token_issue',
                                                                    {'token': token_name, 'issuer': issued_by,
                                                                     'txid': txid, 'total': total})
                    else:
                        self.logger.status_log.warning("This token is already registered: {} - Ignored.".format(x[1]))
            except Exception as e:
                self.logger.app_log.warning(f"Error {e} parsing token registration")

        self.index.commit()
        self.c.execute(
            "SELECT operation, openfield FROM transactions "
            "WHERE (block_height >= ? OR block_height <= ?) AND operation = ? and reward = 0 ORDER BY block_height ASC",
            (token_last_block, -token_last_block, "token:transfer", ))  # includes mirror blocks
        openfield_transfers = self.c.fetchall()
        # print(openfield_transfers)
        tokens_transferred = []
        for transfer in openfield_transfers:
            token_name = transfer[1].split(":")[0].lower().strip()
            if token_name not in tokens_transferred:
                tokens_transferred.append(token_name)
        if tokens_transferred:
            self.logger.status_log.info("Token transferred: {}".format(tokens_transferred))
        for token in tokens_transferred:
            try:
                self.logger.status_log.info("processing {}".format(token))
                self.c.execute(
                    "SELECT block_height, timestamp, address, recipient, signature, operation, openfield "
                    "FROM transactions WHERE (block_height >= ? OR block_height <= ?) "
                    "AND operation = ? AND openfield LIKE ? AND reward = 0 ORDER BY block_height ASC;",
                    (token_last_block, -token_last_block, "token:transfer", token + ':%', ))
                results2 = self.c.fetchall()
                # self.logger.app_log.warning(results2)
                for r in results2:
                    block_height = r[0]
                    timestamp = r[1]
                    token = r[6].split(":")[0]
                    sender = r[2]
                    recipient = r[3]
                    txid = r[4][:56]
                    if txid == "0":
                        txid = blake2bhash_generate(r)
                    try:
                        transfer_amount = int(r[6].split(":")[1])
                    except Exception:
                        transfer_amount = 0

                    self.logger.status_log.info(f"Block height {block_height} - Timestamp {timestamp} - Txid {txid}")
                    # calculate balances
                    self.index_cursor.execute(
                        "SELECT sum(amount) FROM tokens WHERE recipient = ? AND block_height < ? AND token = ?",
                        (sender, block_height, token))
                    try:
                        credit_sender = int(self.index_cursor.fetchall()[0][0])
                    except Exception:
                        credit_sender = 0
                    self.index_cursor.execute(
                        "SELECT sum(amount) FROM tokens WHERE address = ? AND block_height <= ? AND token = ?",
                        (sender, block_height, token))
                    try:
                        debit_sender = int(self.index_cursor.fetchall()[0][0])
                    except Exception:
                        debit_sender = 0
                    # self.logger.app_log.warning("Sender's debit: {}".format(debit_sender))
                    # /calculate balances

                    balance_sender = credit_sender - debit_sender
                    self.logger.status_log.info(f"Token '{token}'': Transfer {transfer_amount} "
                                                f"from {sender} to {recipient}. "
                                                f"Sender's balance {balance_sender}")
                    # self.logger.app_log.warning("Sender's balance {}".format(balance_sender))
                    try:
                        self.index_cursor.execute("SELECT txid from tokens WHERE txid = ? limit 1", (txid, ))
                        dummy = self.index_cursor.fetchall()[0]  # check for uniqueness
                        if dummy:
                            self.logger.status_log.warning(f"Token operation already processed: {token} {txid} - "
                                                           f"Ignored.")
                        else:
                            if (balance_sender - transfer_amount >= 0) and (transfer_amount > 0):
                                self.index_cursor.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?,?)",
                                                          (abs(block_height), timestamp, token, sender, recipient,
                                                           txid, transfer_amount))
                                if self.plugin_manager:
                                    self.plugin_manager.execute_action_hook('token_transfer',
                                                                            {'token': token, 'from': sender,
                                                                             'to': recipient, 'txid': txid,
                                                                             'amount': transfer_amount})

                            else:
                                # save block height and txid so that we do not have
                                # to process the invalid transactions again
                                self.logger.status_log.warning("Invalid transaction by {}".format(sender))
                                self.index_cursor.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?,?)",
                                                          (block_height, "", "", "", "", txid, ""))
                    except Exception as e:
                        self.logger.status_log.warning("Exception {} transfering token.".format(e))

                    self.logger.status_log.info("Processing of {} finished".format(token))
            except Exception as e:
                self.logger.app_log.warning(f"Error {e} parsing token op")

            self.index.commit()

    # ==== Main chain methods ==== #

    # ---- Current state queries ---- #

    def last_mining_transaction(self) -> Transaction:
        """
        Returns the latest mining (coinbase) transaction.
        Renamed for consistency since it's not the full block data, just one tx.
        :return:
        """
        # Only things really used from here are block_height, block_hash.
        self._execute(self.c, 'SELECT * FROM transactions where reward != 0 ORDER BY block_height DESC LIMIT 1')
        # TODO EGG_EVO: benchmark vs "SELECT * FROM transactions
        # WHERE reward != 0 AND block_height= (select max(block_height) from transactions)")
        # Q: Does it help or make it safer/faster to add AND reward > 0 ?
        if self.legacy_db:
            transaction = Transaction.from_legacy(self.c.fetchall()[0])
        else:
            # V2
            transaction = Transaction.from_v2(self.c.fetchall()[0])
        # now returns the transaction object itself, higher level adjustments processed.
        # return transaction.to_dict(legacy=True)
        return transaction

    def last_block_hash(self) -> str:
        # returns last block hash from live data as hex string
        self._execute(self.c,
                      "SELECT block_hash FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1")
        last_hash = self.c.fetchall()[0][0]
        # if new db, convert bin to hex
        if not self.legacy_db:
            last_hash = last_hash.hex()
        self.logger.status_log.warning(f"Temp: last_block_hash {last_hash}")
        return last_hash

    def last_block_timestamp(self, back: int=0) -> Union[float, None]:
        """
        Returns the timestamp (python float) of the latest known block
        back = 0 gives the last block
        back = 1 gives the previous block timestamp
        :return:
        """
        self._execute(self.c, f"SELECT timestamp FROM transactions WHERE reward != 0 "
                              f"ORDER BY block_height DESC LIMIT {back}, 1")
        try:
            return self.c.fetchall()[0][0]  # timestamps do not need quantize
        except Exception:
            return None

    def difflast(self) -> List[Union[int, float]]:
        """
        Returns the list of latest [block_height, difficulty]
        :return:
        """
        self._execute(self.h, "SELECT block_height, difficulty FROM misc ORDER BY block_height DESC LIMIT 1")
        difflast = self.h.fetchall()[0]
        return difflast

    def annverget(self, genesis: str) -> str:
        """
        Returns the current annver string for the given genesis address
        :param genesis:
        :return:
        """
        try:
            self._execute_param(self.h,
                                "SELECT openfield FROM transactions WHERE address = ? AND operation = ? "
                                "ORDER BY block_height DESC LIMIT 1",
                                (genesis, "annver"))
            result = self.h.fetchall()[0][0]
        except Exception:
            result = "?"
        return result

    def annget(self, genesis: str) -> str:
        # Returns the current ann string for the given genesis address
        try:
            self._execute_param(self.h,
                                "SELECT openfield FROM transactions WHERE address = ? AND operation = ? "
                                "ORDER BY block_height DESC LIMIT 1",
                                (genesis, "ann"))
            result = self.h.fetchall()[0][0]
        except Exception:
            result = "No announcement"
        return result

    def balance_get_full(self, balance_address: str, mempool: "Mempool", as_dict: bool=False) -> Union[tuple, dict]:
        """Returns full detailed balance info
        Ported from node.py
            return str(balance), str(credit_ledger), str(debit), str(fees), str(rewards), str(balance_no_mempool)
        needs db and float/int abstraction
        Sends a tuple or a structured dict depending on as_dict param
        """
        # mempool fees
        base_mempool = mempool.mp_get(balance_address)
        # TODO: EGG_EVO Here, we get raw txs. we should ask the mempool object for its mempool balance,
        # not rely on a specific low level format.
        debit_mempool = 0
        if base_mempool:
            for x in base_mempool:
                debit_tx = Decimal(x[0])
                fee = fee_calculate(x[1], x[2])
                debit_mempool = quantize_eight(debit_mempool + debit_tx + fee)
        else:
            debit_mempool = 0
        # /mempool fees

        # TODO: EGG_EVO this will be completely rewritten when using int db
        credit_ledger = Decimal("0")
        try:
            self._execute_param(self.h, "SELECT amount FROM transactions WHERE recipient = ?;", (balance_address, ))
            entries = self.h.fetchall()
        except Exception:
            entries = []
        try:
            for entry in entries:
                credit_ledger = quantize_eight(credit_ledger) + quantize_eight(entry[0])
                credit_ledger = 0 if credit_ledger is None else credit_ledger
        except Exception:
            credit_ledger = 0
        fees = Decimal("0")
        debit_ledger = Decimal("0")
        try:
            self._execute_param(self.h, "SELECT fee, amount FROM transactions WHERE address = ?",
                                (balance_address, ))
            entries = self.h.fetchall()
        except Exception:
            entries = []
        try:
            for entry in entries:
                fees = quantize_eight(fees) + quantize_eight(entry[0])
                fees = 0 if fees is None else fees
        except Exception:
            fees = 0
        try:
            for entry in entries:
                debit_ledger = debit_ledger + Decimal(entry[1])
                debit_ledger = 0 if debit_ledger is None else debit_ledger
        except Exception:
            debit_ledger = 0
        debit = quantize_eight(debit_ledger + debit_mempool)
        rewards = Decimal("0")
        try:
            self._execute_param(self.h, "SELECT reward FROM transactions WHERE recipient = ?",
                                (balance_address, ))
            entries = self.h.fetchall()
        except Exception:
            entries = []
        try:
            for entry in entries:
                rewards = quantize_eight(rewards) + quantize_eight(entry[0])
                rewards = 0 if str(rewards) == "0E-8" else rewards
                rewards = 0 if rewards is None else rewards
        except Exception:
            rewards = 0

        balance = quantize_eight(credit_ledger - debit - fees + rewards)
        balance_no_mempool = float(credit_ledger) - float(debit_ledger) - float(fees) + float(rewards)
        # self.logger.app_log.info("Mempool: Projected transaction address balance: " + str(balance))
        if as_dict:
            # To be factorized in a helper function if used elsewhere.
            return {"balance": str(balance),
                    "credit": str(credit_ledger),
                    "debit": str(debit),
                    "fees":  str(fees),
                    "rewards": str(rewards),
                    "balance_no_mempool": str(balance_no_mempool)}
        else:
            return str(balance), str(credit_ledger), str(debit), str(fees), str(rewards), str(balance_no_mempool)

    def transactions_for_address(self, address: str, limit: int=0, mirror: bool=False) -> List[Transaction]:
        if mirror:
            self._execute_param(self.h,
                                "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) "
                                "AND block_height < 1 ORDER BY block_height ASC LIMIT ?",
                                (address, address, limit))
        else:
            if limit < 1:
                self._execute_param(self.h, "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) "
                                            "ORDER BY block_height DESC", (address, address))
            else:
                self._execute_param(self.h, "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) "
                                            "ORDER BY block_height DESC LIMIT ?", (address, address, limit))
        result = self.h.fetchall()
        return [Transaction.from_legacy(raw_tx) for raw_tx in result]

    def last_n_transactions(self, n: int) -> List[Transaction]:
        # No mirror transactions in there
        self._execute_param(self.h, "SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?", (n, ))
        result = self.h.fetchall()
        return [Transaction.from_legacy(raw_tx) for raw_tx in result]

    def ledger_balance3(self, address: str, cache: Union[dict, None]=None) -> Decimal:
        """Cached balance from hyper - used by digest, cache is local to one block         """
        if not self.legacy_db:
            self.logger.status_log.error("ledger_balance3 but not legacy db!")
            sys.exit()
        # Important: keep this as c (ram hyperblock access)
        # Many heavy blocks are pool payouts, same address.
        # Cache pre_balance instead of recalc for every tx
        if cache is not None and address in cache:
            return cache[address]
        credit_ledger = Decimal(0)
        self._execute_param(self.c,
                            "SELECT amount, reward FROM transactions WHERE recipient = ?",
                            (address, ))
        entries = self.c.fetchall()
        for entry in entries:
            credit_ledger += quantize_eight(entry[0]) + quantize_eight(entry[1])
        debit_ledger = Decimal(0)
        self._execute_param(self.c,
                            "SELECT amount, fee FROM transactions WHERE address = ?",
                            (address, ))
        entries = self.c.fetchall()
        for entry in entries:
            debit_ledger += quantize_eight(entry[0]) + quantize_eight(entry[1])
        if cache is not None:
            cache[address] = quantize_eight(credit_ledger - debit_ledger)
            return cache[address]
        else:
            return quantize_eight(credit_ledger - debit_ledger)

    def ledger_balance3_int(self, address: str, cache: Union[dict, None]=None) -> int:
        """Cached balance from hyper - used by digest, cache is local to one block         """
        if self.legacy_db:
            self.logger.status_log.error("ledger_balance3_int but legacy db!")
            sys.exit()
        # Important: keep this as c (ram hyperblock access)
        # Many heavy blocks are pool payouts, same address.
        # Cache pre_balance instead of recalc for every tx
        if cache is not None and address in cache:
            return cache[address]
        self._execute_param(self.c, "SELECT sum(amount + reward) FROM transactions WHERE recipient = ?", (address, ))
        entries = self.c.fetchall()[0]
        # print("EE", entries)
        credit_ledger = 0 if entries[0] is None else entries[0]
        self._execute_param(self.c, "SELECT sum(amount + fee) FROM transactions WHERE address = ?", (address, ))
        entries = self.c.fetchall()[0]
        # print("EE", entries)
        debit_ledger = 0 if entries[0] is None else entries[0]
        if cache is not None:
            cache[address] = credit_ledger - debit_ledger
            return cache[address]
        else:
            return credit_ledger - debit_ledger

    # ---- Lookup queries ---- #

    def block_height_from_hash(self, hex_hash: str) -> int:
        """Lookup a block height from its hash."""
        # provided hash is supposed to be in hex format.
        # tweaked to allow either bin or hex and convert or not depending on the underlying db.
        try:
            # start = ttime()
            # Note: there's a try..except, but _execute can retry forever if DB is locked for instance.
            if self.legacy_db:
                self._execute_param(self.h, "SELECT block_height FROM transactions WHERE block_hash = ? limit 0, 1",
                                    (hex_hash, ))
            else:
                self._execute_param(self.h, "SELECT block_height FROM transactions WHERE block_hash = ? limit 0, 1",
                                    (Binary(bytes.fromhex(hex_hash)), ))
            result = self.h.fetchall()[0][0]  # Fetchall vs fetch one releases the shared lock,
            # see https://gist.github.com/rianhunter/10bfcff17c18d112de16
            # print("block_height_from_hash", ttime() - start)
            # Roughly 0.0001s -(ssd)
        except Exception:
            result = None
        return result

    def block_height_from_binhash(self, block_hash: bytes) -> int:
        """Lookup a block height from its hash."""
        # provided hash is supposed to be binary.
        try:
            # Note: there's a try..except, but _execute can retry forever if DB is locked for instance.
            self._execute_param(self.h, "SELECT block_height FROM transactions WHERE block_hash = ? limit 0, 1",
                                (Binary(block_hash), ))
            result = self.h.fetchall()[0][0]
        except Exception:
            result = None
        return result

    def pubkeyget(self, address: str) -> str:
        # TODO: make sure address, when it comes from the network or user input, is sanitized and validated.
        # Not to be added here, for perf reasons, but in the top layers.
        self._execute_param(self.c,
                            "SELECT public_key FROM transactions WHERE address = ? and reward = 0 LIMIT 1",
                            (address, ))
        # Note: this returns the first it finds.
        # Could be dependent of the local db. *if* one address was to have several different pubkeys (I don't see how)
        # could be problematic.
        # EGG_EVO: if new db, convert bin to hex
        return self.c.fetchall()[0][0]

    def known_address(self, address: str) -> bool:
        """Returns whether the address appears in chain, be it as sender or receiver"""
        # EGG EVO: db format invariant
        # TODO: we don't care the result, maybe another query would be faster.
        # TODO: add a testnet test on that
        self.h.execute('SELECT block_height FROM transactions WHERE address= ? or recipient= ? LIMIT 1',
                       (address, address))
        res = self.h.fetchall()[0]
        return res is not None

    def blocksync(self, block_height: int) -> List[list]:
        """
        Returns a list of blocks following block_height, until end of chain or total size >= 500000 octets
        Each block is a list of raw transactions, legacy format, float.
        :param block_height:
        :return:
        """
        blocks_fetched = []
        # Strangely, block height is not included, neither are block_hash, fee, reward
        # EGG_EVO: So this is a new alternate format to potentially take into account into BismuthCore
        # But this is only used to feed a peer, over the network.
        # So maybe we better have handle it by hand here.
        # Update: in fact, same format as what is hashed. Done, see Transaction.to_tuple_for_block_hash
        # TODO: to be tested with regnet or testnet, make sure the format is right.

        while sys.getsizeof(str(blocks_fetched)) < 500000:  # limited size based on txs in blocks
            block_height += 1
            if self.legacy_db:
                self._execute_param(self.h,
                                    "SELECT timestamp,address,recipient,amount,signature,public_key,operation,openfield"
                                    " FROM transactions WHERE block_height = ?",
                                    (block_height, ))
                result = self.h.fetchall()
                if not result:
                    break
                blocks_fetched.extend([result])
            else:
                block = self.get_block(block_height)
                if len(block.transactions) == 0:
                    break
                # Possible optimization: keep a cache of recent blocks there, into network format.
                # Clear cache on rollback.
                blocks_fetched.extend([block.tx_list_for_hash()])
        return blocks_fetched

    def get_block(self, block_height: int) -> Block:
        """
        Returns a Block instance matching the requested height.
        Block will be empty if height is unknown but will throw no exception
        :param block_height:
        :return:
        """
        # EGG_EVO: This sql request is the same in both cases (int/float), but...
        self._execute_param(self.h, "SELECT * FROM transactions WHERE block_height = ?", (block_height, ))
        block_desired_result = self.h.fetchall()
        # from_legacy only is valid for legacy db, so here we need to add context dependent code.
        # Transaction objects - themselves - are db agnostic.
        if self.legacy_db:
            transaction_list = [Transaction.from_legacy(entry) for entry in block_desired_result]
        else:
            transaction_list = [Transaction.from_v2(entry) for entry in block_desired_result]
        return Block(transaction_list)

    def get_block_hash_for_height(self, block_height: int) -> str:
        """
        Returns a Block hash - hex string - for the requested height.
        hash will be empty if height is unknown but will throw no exception
        :param block_height:
        :return:
        """
        try:
            self._execute_param(self.h, "SELECT block_hash FROM transactions WHERE block_height = ? limit 0, 1", (block_height, ))
            hash_hex = self.h.fetchall()[0][1]
            if self.legacy_db:
                return hash_hex
            else:
                return hash_hex.hex()  # v2 db stores as bin
        except Exception:
            return ''

    def get_difficulty_for_height(self, block_height: int) -> float:
        return float(self._fetchone(self.h,
                                    "SELECT difficulty FROM misc WHERE block_height = ? limit 0, 1",
                                    (block_height, )))

    def get_block_from_hash(self, hex_hash: str) -> Block:
        """
        Returns a Block instance matching the requested height.
        Block will be empty if hash is unknown but will throw no exception
        :param hex_hash:
        :return:
        """
        # EGG_EVO: hash is currently supposed to be into hex format.
        # To be tweaked to allow either bin or hex and convert or not depending on the underlying db.

        # EGG_EVO: This sql request is the same in both cases (int/float), but...
        self._execute_param(self.h, "SELECT * FROM transactions WHERE block_hash = ?", (hex_hash, ))
        block_desired_result = self.h.fetchall()
        # from_legacy only is valid for legacy db, so here we'll need to add context dependent code.
        # dbhandler will be aware of the db it runs on (simple flag) and call the right from_??? method.
        # Transaction objects - themselves - are db agnostic.
        if self.legacy_db:
            transaction_list = [Transaction.from_legacy(entry) for entry in block_desired_result]
        else:
            # from_v2 is TODO EGG_EVO - to add to BismuthCore. Not needed for legacy -> V2 conversion.
            print("get_address_range Transaction.from_v2 not supported yet")
            sys.exit()
        return Block(transaction_list)

    def get_address_range(self, address: str, starting_block: int, limit: int) -> Block:
        """Very specific, but needed for bitcoin like api and json rpc server"""
        self._execute_param(self.h, "SELECT * FROM transactions "
                                    "WHERE ? IN (address, recipient) "
                                    "AND block_height >= ? "
                                    "ORDER BY block_height "
                                    "ASC LIMIT ?", (address, starting_block, limit))
        transactions = self.h.fetchall()
        # from_legacy only is valid for legacy db, so here we'll need to add context dependent code.
        # dbhandler will be aware of the db it runs on (simple flag) and call the right from_??? method.
        # Transaction objects - themselves - are db agnostic.
        if self.legacy_db:
            transaction_list = [Transaction.from_legacy(entry) for entry in transactions]
        else:
            # from_v2 is TODO EGG_EVO - to add to BismuthCore. Not needed for legacy -> V2 conversion.
            print("get_address_range Transaction.from_v2 not supported yet")
            sys.exit()
        return TransactionsList(transaction_list)

    def transaction_signature_exists(self, encoded_signature: str) -> bool:
        """Tells whether that transaction already exists in the ledger"""
        # EGG_EVO will need convert and alt sql for bin storage
        if self.old_sqlite:
            self._execute_param(self.c, "SELECT timestamp FROM transactions WHERE signature = ?1 limit 0, 1",
                                (encoded_signature, ))
        else:
            self._execute_param(self.c, "SELECT timestamp FROM transactions "
                                        "WHERE substr(signature,1,4) = substr(?1,1,4) AND signature = ?1 limit 0, 1",
                                (encoded_signature, ))
        return bool(self.c.fetchall()[0])

    # ====  TODO: check usage of these methods ==== Update: 1 occ. was moved to solo handler, process the other one.

    def block_height_max(self) -> int:
        self.h.execute("SELECT max(block_height) FROM transactions")
        return self.h.fetchall()[0][0]

    def block_height_max_diff(self) -> int:
        self.h.execute("SELECT max(block_height) FROM misc")
        return self.h.fetchall()[0][0]

    def block_height_max_hyper(self) -> int:
        self.h2.execute("SELECT max(block_height) FROM transactions")
        return self.h2.fetchall()[0][0]

    def block_height_max_diff_hyper(self) -> int:
        self.h2.execute("SELECT max(block_height) FROM misc")
        return self.h2.fetchall()[0][0]

    # ====  Maintenance methods ====

    def backup_higher(self, block_height: int):
        # EGG_EVO: returned data is dependent of db format.
        # Is this an issue if consistent? What is it then used for?
        # => It's used in node.py, blocknf: backup txs are re-inserted into mempool via mp.MEMPOOL.merge()
        # which expects legacy format.
        #
        # "backup higher blocks than given, takes data from c, which normally means RAM"
        self._execute_param(self.c, "SELECT * FROM transactions WHERE block_height >= ?", (block_height, ))
        backup_data = self.c.fetchall()

        self._execute_param(self.c, "DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?",
                            (block_height, -block_height))  # this belongs to rollback_under
        self.commit(self.conn)

        self._execute_param(self.c, "DELETE FROM misc WHERE block_height >= ?",
                            (block_height, ))  # this belongs to rollback_under
        self.commit(self.conn)

        return backup_data

    def rollback_under(self, block_height: int) -> None:
        """
        # EGG: TEMP debug for int-db only
        if not self.legacy_db:
            self.logger.app_log.error(f"rollback_under {block_height} - STOPPED - Temp Debug")
            sys.exit()
        """
        self.h.execute("DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?",
                       (block_height, -block_height))
        self.commit(self.hdd)

        self.h.execute("DELETE FROM misc WHERE block_height >= ?", (block_height, ))
        self.commit(self.hdd)

        self.h2.execute("DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?",
                        (block_height, -block_height))
        self.commit(self.hdd2)

        self.h2.execute("DELETE FROM misc WHERE block_height >= ?", (block_height, ))
        self.commit(self.hdd2)

    def rollback_to(self, block_height: int) -> None:
        self.logger.dev_log.warning("rollback_to is deprecated, use rollback_under")
        self.rollback_under(block_height)

    def to_db_v2(self, block: Block, diff_save: int) -> None:
        # TODO EGG_EVO: many possible traps and params there, to be examined later on.
        # print("** to_db")
        # self.logger.status_log.error("TODO: dbhandler.to_db_v2()")
        try:
            self._execute_param(self.c, SQL_TO_MISC, (block.height, diff_save))
            self.commit(self.conn)
        except Exception as e:
            self.logger.digest_log.error(f"dbhandler.to_db_v2 error {e} writing to misc")
            raise
        try:
            for transaction in block.transactions:
                self._execute_param(self.c, SQL_TO_TRANSACTIONS_V2, transaction.to_bin_tuple(sqlite_encode=True))
            self.commit(self.conn)
            # self.logger.digest_log.warning(f"TEMP DEBUG to_db_v2 {len(block.transactions)} transactions")
        except Exception as e:
            self.logger.digest_log.error(f"dbhandler.to_db_v2 error {e} writing to transactions")
            raise

    def to_db(self, block_array, diff_save, block_transactions) -> None:
        # TODO EGG_EVO: many possible traps and params there, to be examined later on.
        # print("** to_db")
        if not self.legacy_db:
            self.logger.status_log.error("dbhandler.to_db() but V2 DB !!!")
            return
        try:
            self._execute_param(self.c, SQL_TO_MISC,
                                (block_array.block_height_new, diff_save))
            self.commit(self.conn)
        except Exception as e:
            self.logger.digest_log.error(f"dbhandler.to_db error {e} writing to misc")

        # db_handler.execute_many(db_handler.c, SQL_TO_TRANSACTIONS, block_transactions)

        for transaction2 in block_transactions:
            # print(transaction2[0])
            self._execute_param(self.c, SQL_TO_TRANSACTIONS,
                                (str(transaction2[0]), str(transaction2[1]), str(transaction2[2]),
                                 str(transaction2[3]), str(transaction2[4]), str(transaction2[5]),
                                 str(transaction2[6]), str(transaction2[7]), str(transaction2[8]),
                                 str(transaction2[9]), str(transaction2[10]), str(transaction2[11])))
        # secure commit for slow nodes
        self.commit(self.conn)

    def db_to_drive(self, node: "Node") -> None:
        if not self.legacy_db:
            self.logger.status_log.error("dbhandler.db_to_drive() but v2 db")
            return

        def transactions_to_h(data):
            for x in data:  # we want to save to ledger db
                self._execute_param(self.h, SQL_TO_TRANSACTIONS,
                                    (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]))
            self.commit(self.hdd)

        def misc_to_h(data):
            for x in data:  # we want to save to ledger db from RAM/hyper db depending on ram conf
                self._execute_param(self.h, SQL_TO_MISC, (x[0], x[1]))
            self.commit(self.hdd)

        def transactions_to_h2(data):
            for x in data:
                self._execute_param(self.h2, SQL_TO_TRANSACTIONS,
                                    (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]))
            self.commit(self.hdd2)

        def misc_to_h2(data):
            for x in data:
                self._execute_param(self.h2, SQL_TO_MISC, (x[0], x[1]))
            self.commit(self.hdd2)

        try:
            if node.is_regnet:
                node.hdd_block = node.last_block
                node.hdd_hash = node.last_block_hash
                self.logger.app_log.warning(f"Chain: Regnet simulated move to HDD")
                return
            self.logger.app_log.info(f"Chain: Moving new data to HDD, {node.hdd_block + 1} to {node.last_block} ")

            self._execute_param(self.c,
                                "SELECT * FROM transactions WHERE block_height > ? "
                                "OR block_height < ? ORDER BY block_height ASC",
                                (node.hdd_block, -node.hdd_block))

            result1 = self.c.fetchall()

            transactions_to_h(result1)
            if node.config.ram:  # we want to save to hyper db from RAM/hyper db depending on ram conf
                transactions_to_h2(result1)

            self._execute_param(self.c, "SELECT * FROM misc WHERE block_height > ? ORDER BY block_height ASC",
                                (node.hdd_block,))
            result2 = self.c.fetchall()

            misc_to_h(result2)
            if node.config.ram:  # we want to save to hyper db from RAM
                misc_to_h2(result2)

            node.hdd_block = node.last_block
            node.hdd_hash = node.last_block_hash

            self.logger.status_log.info(f"Chain: {len(result1)} txs moved to HDD, up to {node.last_block}")
        except Exception as e:
            self.logger.app_log.warning(f"Chain: Exception Moving new data to HDD: {e}")
            # app_log.warning("Ledger digestion ended")  # dup with more informative digest_block notice.

    def db_to_drive_v2(self, node: "Node") -> None:
        """Renamed and copied to v2, but almost no code changed.
        Can be optimized however"""

        def transactions_to_h(data):
            for x in data:  # we want to save to ledger db
                # print("aa", x)
                try:
                    self._execute_param(self.h, SQL_TO_TRANSACTIONS,
                                        (x[0], x[1], x[2], x[3], x[4],
                                         Binary(x[5]), Binary(x[6]), Binary(x[7]),
                                         x[8], x[9], x[10], x[11]))
                except Exception as ex:
                    print("aaa", x)
                    print(str(ex))
                    raise
            self.commit(self.hdd)

        def misc_to_h(data):
            for x in data:  # we want to save to ledger db from RAM/hyper db depending on ram conf
                self._execute_param(self.h, SQL_TO_MISC, (x[0], x[1]))
            self.commit(self.hdd)

        def transactions_to_h2(data):
            for x in data:
                self._execute_param(self.h2, SQL_TO_TRANSACTIONS,
                                    (x[0], x[1], x[2], x[3], x[4],
                                     Binary(x[5]), Binary(x[6]), Binary(x[7]),
                                     x[8], x[9], x[10], x[11]))
            self.commit(self.hdd2)

        def misc_to_h2(data):
            for x in data:
                self._execute_param(self.h2, SQL_TO_MISC, (x[0], x[1]))
            self.commit(self.hdd2)

        try:
            if node.is_regnet:
                node.hdd_block = node.last_block
                node.hdd_hash = node.last_block_hash
                self.logger.app_log.warning(f"Chain: Regnet simulated move to HDD")
                return
            self.logger.digest_log.info(f"Chain v2: Moving new data to HDD, {node.hdd_block + 1} to {node.last_block} ")

            self._execute_param(self.c,
                                "SELECT * FROM transactions WHERE block_height > ? "
                                "OR block_height < ? ORDER BY block_height ASC",
                                (node.hdd_block, -node.hdd_block))
            result1 = self.c.fetchall()
            self.logger.digest_log.info(f"Chain v2 Temp Debug: Got tx data")

            transactions_to_h(result1)
            self.logger.digest_log.info(f"Chain v2 Temp Debug: transactions_to_h ok")

            if node.config.ram:  # we want to save to hyper db from RAM/hyper db depending on ram conf
                transactions_to_h2(result1)
                self.logger.digest_log.info(f"Chain v2 Temp Debug: transactions_to_h2 ok")

            self._execute_param(self.c, "SELECT * FROM misc WHERE block_height > ? ORDER BY block_height ASC",
                                (node.hdd_block,))
            result2 = self.c.fetchall()
            self.logger.digest_log.info(f"Chain v2 Temp Debug: Got misc data")

            misc_to_h(result2)
            self.logger.digest_log.info(f"Chain v2 Temp Debug: misc_to_h ok")

            if node.config.ram:  # we want to save to hyper db from RAM
                misc_to_h2(result2)

            node.hdd_block = node.last_block
            node.hdd_hash = node.last_block_hash
            self.logger.status_log.info(f"Chain: {len(result1)} txs moved to HDD, up to {node.last_block}")
        except Exception as e:
            self.logger.app_log.warning(f"Chain: Exception Moving new data to HDD: {e}")
            # app_log.warning("Ledger digestion ended")  # dup with more informative digest_block notice.
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

    # ====  Rewards ====

    def dev_reward(self, node: "Node", block_array, miner_tx, mining_reward, mirror_hash) -> None:
        if not self.legacy_db:
            self.logger.status_log.error("dbhandler.dev_reward, but v2")
            return
        self._execute_param(self.c, SQL_TO_TRANSACTIONS,
                            (-block_array.block_height_new, str(miner_tx.q_block_timestamp),
                             "Development Reward", node.config.genesis,
                             str(mining_reward), "0", "0", mirror_hash, 0, 0, "0", "0"))
        self.commit(self.conn)

    def dev_reward_v2(self, node: "Node", block: "Block", mirror_hash: bytes) -> None:
        # mining_reward = block.miner_tx.reward  # This is block reward + included fees reward
        mining_reward = block.mining_reward  # This is block reward only
        if mining_reward <= 0:
            self.logger.status_log.error(f"dbhandler.dev_reward_v2, mining_reward={mining_reward}.")
            raise ValueError("Wrong dev rewards")
        self._execute_param(self.c, SQL_TO_TRANSACTIONS,
                            (-block.height, str(block.miner_tx.timestamp),
                             "Development Reward", node.config.genesis,
                             mining_reward, b"", b"", mirror_hash, 0, 0, "0", "0"))
        self.commit(self.conn)

    def hn_reward_v2(self, node, block: Block, mirror_hash: bytes):
        fork = Fork(node.config)
        reward_sum = 24 * K1E8 * 300000
        if node.is_testnet and node.last_block >= fork.POW_FORK_TESTNET:
            reward_sum -= (node.last_block + 5 - fork.POW_FORK_TESTNET) * K1E8
        elif node.is_mainnet and node.last_block >= fork.POW_FORK:
            reward_sum -= (node.last_block + 5 - fork.POW_FORK) * K1E8
        reward_sum = round(reward_sum / 300000)
        if reward_sum < K1E8 // 2:
            reward_sum = K1E8 // 2

        self._execute_param(self.c, SQL_TO_TRANSACTIONS,
                            (-block.height, str(block.miner_tx.timestamp), "Hypernode Payouts",
                             "3e08b5538a4509d9daa99e01ca5912cda3e98a7f79ca01248c2bde16",
                             reward_sum, b"", b"", mirror_hash, "0", "0", "0", "0"))
        self.commit(self.conn)

    def hn_reward(self, node, block_array, miner_tx, mirror_hash):
        if not self.legacy_db:
            self.logger.status_log.error("dbhandler.hn_reward, but v2")
            return
        # This part could be factorized to bismuthcore, but dependency from fork() makes it difficult.
        fork = Fork(node.config)
        reward_sum = 24
        if node.is_testnet and node.last_block >= fork.POW_FORK_TESTNET:
            reward_sum -= (node.last_block + 5 - fork.POW_FORK_TESTNET) / 300000
        elif node.is_mainnet and node.last_block >= fork.POW_FORK:
            reward_sum -= (node.last_block + 5 - fork.POW_FORK) / 300000
        if reward_sum < 0.5:
            reward_sum = 0.5
        reward_sum = '{:.8f}'.format(reward_sum)

        self._execute_param(self.c, SQL_TO_TRANSACTIONS,
                            (-block_array.block_height_new, str(miner_tx.q_block_timestamp), "Hypernode Payouts",
                             "3e08b5538a4509d9daa99e01ca5912cda3e98a7f79ca01248c2bde16",
                             reward_sum, "0", "0", mirror_hash, "0", "0", "0", "0"))
        self.commit(self.conn)

    # ====  Core helpers that should not be called from the outside ====
    # TODO EGG_EVO: Stopped there for now.

    def commit(self, connection: sqlite3.Connection) -> None:
        """Secure commit for slow nodes"""
        while True:
            try:
                connection.commit()
                break
            except Exception as e:
                self.logger.app_log.warning(f"Database connection: {connection}")
                self.logger.app_log.warning(f"Database retry reason: {e}")
                sleep(1)

    def _execute(self, cursor, query: str) -> None:
        """Secure _execute for slow nodes"""
        while True:
            try:
                cursor.execute(query)
                break
            except sqlite3.InterfaceError as e:
                self.logger.app_log.warning(f"Database query to abort: {cursor} {query[:100]}")
                self.logger.app_log.warning(f"Database abortion reason: {e}")
                break
            except sqlite3.IntegrityError as e:
                self.logger.app_log.warning(f"Database query to abort: {cursor} {query[:100]}")
                self.logger.app_log.warning(f"Database abortion reason: {e}")
                break
            except Exception as e:
                self.logger.app_log.warning(f"Database query: {cursor} {query[:100]}")
                self.logger.app_log.warning(f"Database retry reason: {e}")
                sleep(1)

    def _execute_param(self, cursor, query: str, param: Union[list, tuple]) -> None:
        """Secure _execute w/ param for slow nodes"""

        while True:
            try:
                cursor.execute(query, param)
                break
            except sqlite3.InterfaceError as e:
                self.logger.app_log.warning(f"Database query to abort: {cursor} {str(query)[:100]} {str(param)[:100]}")
                self.logger.app_log.warning(f"Database abortion reason: {e}")
                break
            except sqlite3.IntegrityError as e:
                self.logger.app_log.warning(f"Database query to abort: {cursor} {str(query)[:100]}")
                self.logger.app_log.warning(f"Database abortion reason: {e}")
                break
            except Exception as e:
                self.logger.app_log.warning(f"Database query: {cursor} {str(query)[:100]} {str(param)[:100]}")
                self.logger.app_log.warning(f"Database retry reason: {e}")
                if "database is locked" in str(e):
                    self.logger.app_log.error(f"Temp debug: aborting")
                    sys.exit()
                sleep(1)

    def fetchall(self, cursor, query: str, param: Union[list, tuple, None]=None) -> list:
        """Helper to simplify calling code, _execute and fetch in a single line instead of 2"""
        # EGG_EVO: convert to a private method as well.
        if param is None:
            self._execute(cursor, query)
        else:

            self._execute_param(cursor, query, param)
        return cursor.fetchall()

    def fetchone(self, cursor, query: str, param: Union[list, tuple, None]=None) -> Union[None, str, int, float, bool]:
        print("DbHandler.fetchone() has to be converted")
        # Do NOT auto convert, risk of confusion with sqlite core fetchone.
        return self._fetchone(cursor, query, param)

    def _fetchone(self, cursor, query: str, param: Union[list, tuple, None]=None) -> Union[None, str, int, float, bool]:
        """Helper to simplify calling code, _execute and fetch in a single line instead of 2"""
        # EGG_EVO: convert to a private method as well.
        try:
            if param is None:
                self._execute(cursor, query)
            else:
                self._execute_param(cursor, query, param)
            res = cursor.fetchall()[0]  # fetchall to release the lock
            if res:
                return res[0]
            return None
        except Exception:
            return None

    def close(self) -> None:
        self.index.close()
        self.hdd.close()
        self.hdd2.close()
        self.conn.close()
