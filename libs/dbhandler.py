"""
Sqlite3 Database handler module for Bismuth nodes
"""

from time import sleep
import sqlite3
# import essentials
from decimal import Decimal
from bismuthcore.compat import quantize_two, quantize_eight
from bismuthcore.transaction import Transaction
from bismuthcore.block import Block
from bismuthcore.helpers import fee_calculate
import functools
from libs.fork import Fork
from mempool import Mempool
import sys


__version__ = "1.0.2"


def sql_trace_callback(log, sql_id, statement):
    line = f"SQL[{sql_id}] {statement}"
    log.warning(line)


class DbHandler:
    # todo: define  slots
    def __init__(self, index_db, ledger_path, hyper_path, ram, ledger_ram_file, logger, trace_db_calls=False):
        # TODO: most of the params could be taken from the config object instead of being listed in the call
        # prototype would become __init__(self, config, logger=None, trace_db_calls=False):
        # logguer, as it's a global one, could be a config property as well.
        # __init__(self, config, trace_db_calls=False):
        self.ram = ram
        self.ledger_ram_file = ledger_ram_file
        self.hyper_path = hyper_path
        self.logger = logger
        self.trace_db_calls = trace_db_calls
        self.index_db = index_db
        self.ledger_path = ledger_path

        self.index = sqlite3.connect(self.index_db, timeout=1)
        if self.trace_db_calls:
            self.index.set_trace_callback(functools.partial(sql_trace_callback,self.logger.app_log,"INDEX"))
        self.index.text_factory = str
        self.index.execute('PRAGMA case_sensitive_like = 1;')
        self.index_cursor = self.index.cursor()  # Cursor to the index db

        self.hdd = sqlite3.connect(self.ledger_path, timeout=1)
        if self.trace_db_calls:
            self.hdd.set_trace_callback(functools.partial(sql_trace_callback,self.logger.app_log,"HDD"))
        self.hdd.text_factory = str
        self.hdd.execute('PRAGMA case_sensitive_like = 1;')
        self.h = self.hdd.cursor()  # h is a Cursor to the - on disk - ledger db

        self.hdd2 = sqlite3.connect(self.hyper_path, timeout=1)
        if self.trace_db_calls:
            self.hdd2.set_trace_callback(functools.partial(sql_trace_callback,self.logger.app_log,"HDD2"))
        self.hdd2.text_factory = str
        self.hdd2.execute('PRAGMA case_sensitive_like = 1;')
        self.h2 = self.hdd2.cursor()  # h2 is a Cursor to the - on disk - hyper db

        if self.ram:
            self.conn = sqlite3.connect(self.ledger_ram_file, uri=True, isolation_level=None, timeout=1)
        else:
            self.conn = sqlite3.connect(self.hyper_path, uri=True, timeout=1)

        if self.trace_db_calls:
            self.conn.set_trace_callback(functools.partial(sql_trace_callback,self.logger.app_log,"CONN"))
        self.conn.execute('PRAGMA journal_mode = WAL;')
        self.conn.execute('PRAGMA case_sensitive_like = 1;')
        self.conn.text_factory = str
        self.c = self.conn.cursor()  # c is a Cursor to either on disk hyper db or in ram ledger, depending on config. It's the working db for all recent queries.

        self.SQL_TO_TRANSACTIONS = "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
        self.SQL_TO_MISC = "INSERT INTO misc VALUES (?,?)"

    # ==== Aliases ==== #

    def addfromalias(self, alias: str) -> str:
        # TODO: I would rename to address_from_alias() for naming consistency and avoid confusion with "add" verb.
        """
        Lookup the address matching the provided alias
        :param alias:
        :return:
        """
        self._execute_param(self.index_cursor, "SELECT address FROM aliases WHERE alias = ? ORDER BY block_height ASC LIMIT 1;", (alias,))
        try:
            address_fetch = self.index_cursor.fetchone()[0]
        except:
            address_fetch = "No alias"
        return address_fetch

    def aliasget(self, alias_address):
        self._execute_param(self.index_cursor, "SELECT alias FROM aliases WHERE address = ? ", (alias_address,))
        result = self.index_cursor.fetchall()
        if not result:
            result = [[alias_address]]
        return result

    def aliasesget(self, aliases_request):
        results = []
        for alias_address in aliases_request:
            self._execute_param(self.index_cursor, (
                "SELECT alias FROM aliases WHERE address = ? ORDER BY block_height ASC LIMIT 1"), (alias_address,))
            try:
                result = self.index_cursor.fetchall()[0][0]
            except:
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
            self._execute_param(self.index_cursor, "DELETE FROM aliases WHERE block_height >= ?;", (height,))
            self.commit(self.index)

            self.logger.app_log.warning(f"Rolled back the alias index below {(height)}")
        except Exception as e:
            self.logger.app_log.warning(f"Failed to roll back the alias index below {(height)} due to {e}")

    # ==== Tokens ==== #

    def tokens_user(self, tokens_address: str) -> list:
        """
        Returns the list of tokens a specific user has or had.
        :param tokens_address:
        :return:
        """
        self.index_cursor.execute("SELECT DISTINCT token FROM tokens WHERE address OR recipient = ?", (tokens_address,))
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
            self._execute_param(self.index_cursor, "DELETE FROM tokens WHERE block_height >= ?;", (height,))
            self.commit(self.index)

            self.logger.app_log.warning(f"Rolled back the token index below {(height)}")
        except Exception as e:
            self.logger.app_log.warning(f"Failed to roll back the token index below {(height)} due to {e}")

    # ==== Main chain methods ==== #

    # ---- Current state queries ---- #

    def last_mining_transaction(self) -> Transaction:
        """
        Returns the latest mining (coinbase) transaction. Renamed for consistency since it's not the full block data, just one tx.
        :return:
        """
        # Only things really used from here are block_height, block_hash.
        self._execute(self.c, 'SELECT * FROM transactions where reward != 0 ORDER BY block_height DESC LIMIT 1')
        # TODO EGG_EVO: benchmark vs "SELECT * FROM transactions WHERE reward != 0 AND block_height= (select max(block_height) from transactions)")
        # Q: Does it help or make it safer/faster to add AND reward > 0 ?
        transaction = Transaction.from_legacy(self.c.fetchone())
        # EGG_EVO: now returns the transaction object itself, higher level adjustments processed.
        # return transaction.to_dict(legacy=True)
        return transaction

    def last_block_hash(self) -> str:
        # returns last block hash from live data as hex string
        self._execute(self.c, "SELECT block_hash FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")
        # EGG_EVO: if new db, convert bin to hex
        return self.c.fetchone()[0]

    def last_block_timestamp(self) -> float:
        """
        Returns the timestamp (python float) of the latest known block
        :return:
        """
        self._execute(self.c, "SELECT timestamp FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")
        # return quantize_two(self.c.fetchone()[0])
        return self.c.fetchone()[0]  # timestamps do not need quantize

    def difflast(self) -> list:
        """
        Returns the list of latest [block_height, difficulty]
        :return:
        """
        self._execute(self.h, "SELECT block_height, difficulty FROM misc ORDER BY block_height DESC LIMIT 1")
        difflast = self.h.fetchone()
        return difflast

    def annverget(self, genesis: str) -> str:
        """
        Returns the current annver string for the given genesis address
        :param genesis:
        :return:
        """
        try:
            self._execute_param(self.h, "SELECT openfield FROM transactions WHERE address = ? AND operation = ? ORDER BY block_height DESC LIMIT 1", (genesis, "annver",))
            result = self.h.fetchone()[0]
        except:
            result = "?"
        return result

    def annget(self, genesis: str) -> str:
        # Returns the current ann string for the given genesis address
        try:
            self._execute_param(self.h, "SELECT openfield FROM transactions WHERE address = ? AND operation = ? ORDER BY block_height DESC LIMIT 1", (genesis, "ann",))
            result = self.h.fetchone()[0]
        except:
            result = "No announcement"
        return result

    def balance_get_full(self, balance_address: str, mempool: Mempool) -> tuple:
        """Returns full detailed balance info
        Ported from node.py
            return str(balance), str(credit_ledger), str(debit), str(fees), str(rewards), str(balance_no_mempool)
        needs db and float/int abstraction
        """
        # mempool fees
        base_mempool = mempool.mp_get(balance_address)
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
            self._execute_param(self.h, "SELECT amount FROM transactions WHERE recipient = ?;", (balance_address,))
            entries = self.h.fetchall()
        except:
            entries = []
        try:
            for entry in entries:
                credit_ledger = quantize_eight(credit_ledger) + quantize_eight(entry[0])
                credit_ledger = 0 if credit_ledger is None else credit_ledger
        except:
            credit_ledger = 0
        fees = Decimal("0")
        debit_ledger = Decimal("0")
        try:
            self._execute_param(self.h, "SELECT fee, amount FROM transactions WHERE address = ?;",
                                      (balance_address,))
            entries = self.h.fetchall()
        except:
            entries = []
        try:
            for entry in entries:
                fees = quantize_eight(fees) + quantize_eight(entry[0])
                fees = 0 if fees is None else fees
        except:
            fees = 0
        try:
            for entry in entries:
                debit_ledger = debit_ledger + Decimal(entry[1])
                debit_ledger = 0 if debit_ledger is None else debit_ledger
        except:
            debit_ledger = 0
        debit = quantize_eight(debit_ledger + debit_mempool)
        rewards = Decimal("0")
        try:
            self._execute_param(self.h, "SELECT reward FROM transactions WHERE recipient = ?;",
                                      (balance_address,))
            entries = self.h.fetchall()
        except:
            entries = []
        try:
            for entry in entries:
                rewards = quantize_eight(rewards) + quantize_eight(entry[0])
                rewards = 0 if str(rewards) == "0E-8" else rewards
                rewards = 0 if rewards is None else rewards
        except:
            rewards = 0

        balance = quantize_eight(credit_ledger - debit - fees + rewards)
        balance_no_mempool = float(credit_ledger) - float(debit_ledger) - float(fees) + float(rewards)
        # self.logger.app_log.info("Mempool: Projected transaction address balance: " + str(balance))
        return str(balance), str(credit_ledger), str(debit), str(fees), str(rewards), str(balance_no_mempool)

    # ---- Lookup queries ---- #

    def block_height_from_hash(self, hash: str) -> int:
        """Lookup a block height from its hash."""
        # EGG_EVO: hash is currently supposed to be into hex format.
        # To be tweaked to allow either bin or hex - auto recognition - and convert or not depending on the underlying db.
        try:
            self._execute_param(self.h, "SELECT block_height FROM transactions WHERE block_hash = ?;", (hash,))
            result = self.h.fetchone()[0]
        except:
            result = None
        return result

    def pubkeyget(self, address: str) -> str:
        # TODO: make sure address, when it comes from the network or user input, is sanitized and validated.
        # Not to be added here, for perf reasons, but in the top layers.
        self._execute_param(self.c, "SELECT public_key FROM transactions WHERE address = ? and reward = 0 LIMIT 1", (address,))
        # Note: this returns the first it finds. Could be dependent of the local db. *if* one address was to have several different pubkeys (I don't see how)
        # could be problematic.
        # EGG_EVO: if new db, convert bin to hex
        return self.c.fetchone()[0]

    def blocksync(self, block_height: int) -> list:
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
        while sys.getsizeof(
                str(blocks_fetched)) < 500000:  # limited size based on txs in blocks
            """
            self._execute_param(self.h, (
                "SELECT timestamp,address,recipient,amount,signature,public_key,operation,openfield FROM transactions WHERE block_height > ? AND block_height <= ?;"),
                                (str(int(block)), str(int(block + 1)),))
            """
            # Simplify request
            block_height += 1
            self._execute_param(self.h, (
                "SELECT timestamp,address,recipient,amount,signature,public_key,operation,openfield FROM transactions WHERE block_height = ?"), (block_height,))
            result = self.h.fetchall()
            if not result:
                break
            blocks_fetched.extend([result])
        return blocks_fetched

    def get_block(self, block_height: int) -> Block:
        """
        Returns a Block instance matching the requested height. Block will be empty if height is unknown but will throw no exception
        :param block_height:
        :return:
        """
        # EGG_EVO: This sql request is the same in both cases (int/float), but...
        self._execute_param(self.h, "SELECT * FROM transactions WHERE block_height = ?", (block_height,))
        block_desired_result = self.h.fetchall()
        # from_legacy only is valid for legacy db, so here we'll need to add context dependent code.
        # dbhandler will be aware of the db it runs on (simple flag) and call the right from_??? method.
        # Transaction objects - themselves - are db agnostic.
        transaction_list = [Transaction.from_legacy(entry) for entry in block_desired_result]
        return Block(transaction_list)

    # ====  TODO: check usage of these methods ====

    def block_height_max(self) -> int:
        self.h.execute("SELECT max(block_height) FROM transactions")
        return self.h.fetchone()[0]

    def block_height_max_diff(self) -> int:
        self.h.execute("SELECT max(block_height) FROM misc")
        return self.h.fetchone()[0]

    def block_height_max_hyper(self) -> int:
        self.h2.execute("SELECT max(block_height) FROM transactions")
        return self.h2.fetchone()[0]

    def block_height_max_diff_hyper(self) -> int:
        self.h2.execute("SELECT max(block_height) FROM misc")
        return self.h2.fetchone()[0]

    # ====  Maintenance methods ====

    def backup_higher(self, block_height: int):
        # TODO EGG_EVO, returned data is dependent of db format. is this an issue if consistent? What is it then used for?
        # "backup higher blocks than given, takes data from c, which normally means RAM"
        self._execute_param(self.c, "SELECT * FROM transactions WHERE block_height >= ?;", (block_height,))
        backup_data = self.c.fetchall()

        self._execute_param(self.c, "DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?", (block_height, -block_height)) #this belongs to rollback_under
        self.commit(self.conn)  # this belongs to rollback_under

        self._execute_param(self.c, "DELETE FROM misc WHERE block_height >= ?;", (block_height,)) #this belongs to rollback_under
        self.commit(self.conn)  # this belongs to rollback_under

        return backup_data

    def rollback_under(self, block_height: int) -> None:
        self.h.execute("DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?", (block_height, -block_height,))
        self.commit(self.hdd)

        self.h.execute("DELETE FROM misc WHERE block_height >= ?", (block_height,))
        self.commit(self.hdd)

        self.h2.execute("DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?", (block_height, -block_height,))
        self.commit(self.hdd2)

        self.h2.execute("DELETE FROM misc WHERE block_height >= ?", (block_height,))
        self.commit(self.hdd2)

    def rollback_to(self, block_height: int) -> None:
        self.logger.app_log.error("rollback_to is deprecated, use rollback_under")
        self.rollback_under(block_height)

    def to_db(self, block_array, diff_save, block_transactions):
        # TODO EGG_EVO: many possible traps and params there, to be examined later on.
        self._execute_param(self.c, "INSERT INTO misc VALUES (?, ?)",
                            (block_array.block_height_new, diff_save))
        self.commit(self.conn)

        # db_handler.execute_many(db_handler.c, self.SQL_TO_TRANSACTIONS, block_transactions)

        for transaction2 in block_transactions:
            self._execute_param(self.c, self.SQL_TO_TRANSACTIONS,
                                (str(transaction2[0]), str(transaction2[1]), str(transaction2[2]),
                                      str(transaction2[3]), str(transaction2[4]), str(transaction2[5]),
                                      str(transaction2[6]), str(transaction2[7]), str(transaction2[8]),
                                      str(transaction2[9]), str(transaction2[10]), str(transaction2[11])))
            # secure commit for slow nodes
            self.commit(self.conn)

    def db_to_drive(self, node):
        # TODO EGG_EVO: many possible traps and params there, to be examined later on.
        def transactions_to_h(data):
            for x in data:  # we want to save to ledger.db
                self._execute_param(self.h, self.SQL_TO_TRANSACTIONS,
                                    (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]))
            self.commit(self.hdd)

        def misc_to_h(data):
            for x in data:  # we want to save to ledger.db from RAM/hyper.db depending on ram conf
                self._execute_param(self.h, self.SQL_TO_MISC, (x[0], x[1]))
            self.commit(self.hdd)

        def transactions_to_h2(data):
            for x in data:
                self._execute_param(self.h2, self.SQL_TO_TRANSACTIONS,
                                    (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]))
            self.commit(self.hdd2)

        def misc_to_h2(data):
            for x in data:
                self._execute_param(self.h2, self.SQL_TO_MISC, (x[0], x[1]))
            self.commit(self.hdd2)


        try:
            node.logger.app_log.warning(f"Chain: Moving new data to HDD, {node.hdd_block + 1} to {node.last_block} ")

            self._execute_param(self.c, "SELECT * FROM transactions WHERE block_height > ? "
                                                   "OR block_height < ? ORDER BY block_height ASC",
                                (node.hdd_block, -node.hdd_block))

            result1 = self.c.fetchall()

            transactions_to_h(result1)
            if node.ram:  # we want to save to hyper.db from RAM/hyper.db depending on ram conf
                transactions_to_h2(result1)

            self._execute_param(self.c, "SELECT * FROM misc WHERE block_height > ? ORDER BY block_height ASC",
                                (node.hdd_block,))
            result2 = self.c.fetchall()

            misc_to_h(result2)
            if node.ram:  # we want to save to hyper.db from RAM
                misc_to_h2(result2)

            node.hdd_block = node.last_block
            node.hdd_hash = node.last_block_hash

            node.logger.app_log.warning(f"Chain: {len(result1)} txs moved to HDD")
        except Exception as e:
            node.logger.app_log.warning(f"Chain: Exception Moving new data to HDD: {e}")
            # app_log.warning("Ledger digestion ended")  # dup with more informative digest_block notice.

    # ====  Rewards ====

    def dev_reward(self, node, block_array, miner_tx, mining_reward, mirror_hash) -> None:
        # TODO EGG_EVO: many possible traps and params there, to be examined later on.
        self._execute_param(self.c, self.SQL_TO_TRANSACTIONS,
                            (-block_array.block_height_new, str(miner_tx.q_block_timestamp), "Development Reward", str(node.genesis),
                                  str(mining_reward), "0", "0", mirror_hash, "0", "0", "0", "0"))
        self.commit(self.conn)

    def hn_reward(self,node,block_array,miner_tx,mirror_hash):
        # TODO EGG_EVO: many possible traps and params there, to be examined later on.
        fork = Fork()

        if node.is_testnet and node.last_block >= fork.POW_FORK_TESTNET:
            self.reward_sum = 24 - 10 * (node.last_block + 5 - fork.POW_FORK_TESTNET) / 3000000

        elif node.is_mainnet and node.last_block >= fork.POW_FORK:
            self.reward_sum = 24 - 10*(node.last_block + 5 - fork.POW_FORK)/3000000
        else:
            self.reward_sum = 24

        if self.reward_sum < 0.5:
            self.reward_sum = 0.5

        self.reward_sum = '{:.8f}'.format(self.reward_sum)

        self._execute_param(self.c, self.SQL_TO_TRANSACTIONS,
                            (-block_array.block_height_new, str(miner_tx.q_block_timestamp), "Hypernode Payouts",
                            "3e08b5538a4509d9daa99e01ca5912cda3e98a7f79ca01248c2bde16",
                            self.reward_sum, "0", "0", mirror_hash, "0", "0", "0", "0"))
        self.commit(self.conn)

    # ====  Core helpers that should not be called from the outside ====
    # TODO EGG_EVO: Stopped there for now.

    def commit(self, connection):
        """Secure commit for slow nodes"""
        while True:
            try:
                connection.commit()
                break
            except Exception as e:
                self.logger.app_log.warning(f"Database connection: {connection}")
                self.logger.app_log.warning(f"Database retry reason: {e}")
                sleep(1)

    def _execute(self, cursor, query):
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

    def _execute_param(self, cursor, query, param):
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
                sleep(1)

    def fetchall(self, cursor, query, param=None):
        """Helper to simplify calling code, _execute and fetch in a single line instead of 2"""
        if param is None:
            self._execute(cursor, query)
        else:
            self._execute_param(cursor, query, param)
        return cursor.fetchall()

    def fetchone(self, cursor, query, param=None):
        """Helper to simplify calling code, _execute and fetch in a single line instead of 2"""
        if param is None:
            self._execute(cursor, query)
        else:
            self._execute_param(cursor, query, param)
        res = cursor.fetchone()
        if res:
            return res[0]
        return None

    def close(self):
        self.index.close()
        self.hdd.close()
        self.hdd2.close()
        self.conn.close()
