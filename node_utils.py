import functools
import glob
import os
import shutil
import sqlite3
import sys
import tarfile
import time

from Cryptodome.Hash import SHA
from _decimal import Decimal
from polysign.signerfactory import SignerFactory

import aliases
import dbhandler
import essentials
import mempool
import mining_heavy3
import tokensv2
from db_hashes import db_hashes
from difficulty import difficulty
from digest import quantize_two, quantize_eight, digest_block
from essentials import download_file, fee_calculate, checkpoint_set


def add_indices(db_handler: dbhandler.DbHandler, node):
    CREATE_TXID4_INDEX_IF_NOT_EXISTS = "CREATE INDEX IF NOT EXISTS TXID4_Index ON transactions(substr(signature,1,4))"
    CREATE_MISC_BLOCK_HEIGHT_INDEX_IF_NOT_EXISTS = "CREATE INDEX IF NOT EXISTS 'Misc Block Height Index' on misc(block_height)"

    node.logger.app_log.warning("Creating indices")

    # ledger.db
    if not node.old_sqlite:
        db_handler.execute(db_handler.h, CREATE_TXID4_INDEX_IF_NOT_EXISTS)
    else:
        node.logger.app_log.warning("Setting old_sqlite is True, lookups will be slower.")
    db_handler.execute(db_handler.h, CREATE_MISC_BLOCK_HEIGHT_INDEX_IF_NOT_EXISTS)

    # hyper.db
    if not node.old_sqlite:
        db_handler.execute(db_handler.h2, CREATE_TXID4_INDEX_IF_NOT_EXISTS)
    db_handler.execute(db_handler.h2, CREATE_MISC_BLOCK_HEIGHT_INDEX_IF_NOT_EXISTS)

    # RAM or hyper.db
    if not node.old_sqlite:
        db_handler.execute(db_handler.c, CREATE_TXID4_INDEX_IF_NOT_EXISTS)
    db_handler.execute(db_handler.c, CREATE_MISC_BLOCK_HEIGHT_INDEX_IF_NOT_EXISTS)

    node.logger.app_log.warning("Finished creating indices")


def verify(db_handler, node):
    # TODO: candidate for single user mode
    try:
        node.logger.app_log.warning("Blockchain verification started...")
        # verify blockchain
        db_handler.execute(db_handler.h, "SELECT Count(*) FROM transactions")
        db_rows = db_handler.h.fetchone()[0]
        node.logger.app_log.warning("Total steps: {}".format(db_rows))

        # verify genesis
        try:
            db_handler.execute(db_handler.h, "SELECT block_height, recipient FROM transactions WHERE block_height = 1")
            result = db_handler.h.fetchall()[0]
            block_height = result[0]
            genesis = result[1]
            node.logger.app_log.warning(f"Genesis: {genesis}")
            if str(genesis) != node.genesis and int(
                    block_height) == 0:
                node.logger.app_log.warning("Invalid genesis address")
                sys.exit(1)
        except:
            node.logger.app_log.warning("Hyperblock mode in use")
        # verify genesis

        invalid = 0

        for row in db_handler.h.execute('SELECT * FROM transactions WHERE block_height > 0 and reward = 0 ORDER BY block_height'):  # native sql fx to keep compatibility

            db_block_height = str(row[0])
            db_timestamp = '%.2f' % (quantize_two(row[1]))
            db_address = str(row[2])[:56]
            db_recipient = str(row[3])[:56]
            db_amount = '%.8f' % (quantize_eight(row[4]))
            db_signature_enc = str(row[5])[:684]
            db_public_key_b64encoded = str(row[6])[:1068]
            db_operation = str(row[10])[:30]
            db_openfield = str(row[11])  # no limit for backward compatibility
            db_transaction = str((db_timestamp, db_address, db_recipient, db_amount, db_operation, db_openfield)).encode("utf-8")

            try:
                # Signer factory is aware of the different tx schemes, and will b64 decode public_key once or twice as needed.
                SignerFactory.verify_bis_signature(db_signature_enc, db_public_key_b64encoded, db_transaction, db_address)
            except Exception as e:
                sha_hash = SHA.new(db_transaction)
                try:
                    if sha_hash.hexdigest() != db_hashes[db_block_height + "-" + db_timestamp]:
                        node.logger.app_log.warning("Signature validation problem: {} {}".format(db_block_height, db_transaction))
                        invalid = invalid + 1
                except Exception as e:
                    node.logger.app_log.warning("Signature validation problem: {} {}".format(db_block_height, db_transaction))
                    invalid = invalid + 1

        if invalid == 0:
            node.logger.app_log.warning("All transacitons in the local ledger are valid")

    except Exception as e:
        node.logger.app_log.warning("Error: {}".format(e))
        raise


def blocknf(node, block_hash_delete, peer_ip, db_handler, hyperblocks=False, mp=None, tokens=None):
    """
    Rolls back a single block, updates node object variables.
    Rollback target must be above checkpoint.
    Hash to rollback must match in case our ledger moved.
    Not trusting hyperblock nodes for old blocks because of trimming,
    they wouldn't find the hash and cause rollback.
    """
    node.logger.app_log.info(f"Rollback operation on {block_hash_delete} initiated by {peer_ip}")

    my_time = time.time()

    if not node.db_lock.locked():
        node.db_lock.acquire()
        node.logger.app_log.warning(f"Database lock acquired")
        backup_data = None  # used in "finally" section
        skip = False
        reason = ""

        try:
            block_max_ram = db_handler.block_max_ram()
            db_block_height = block_max_ram ['block_height']
            db_block_hash = block_max_ram ['block_hash']

            ip = {'ip': peer_ip}
            node.plugin_manager.execute_filter_hook('filter_rollback_ip', ip)
            if ip['ip'] == 'no':
                reason = "Filter blocked this rollback"
                skip = True

            elif db_block_height < node.checkpoint:
                reason = "Block is past checkpoint, will not be rolled back"
                skip = True

            elif db_block_hash != block_hash_delete:
                # print db_block_hash
                # print block_hash_delete
                reason = "We moved away from the block to rollback, skipping"
                skip = True

            elif hyperblocks and node.last_block_ago > 30000: #more than 5000 minutes/target blocks away
                reason = f"{peer_ip} is running on hyperblocks and our last block is too old, skipping"
                skip = True

            else:
                backup_data = db_handler.backup_higher(db_block_height)

                node.logger.app_log.warning(f"Node {peer_ip} didn't find block {db_block_height}({db_block_hash})")

                # roll back hdd too
                db_handler.rollback_under(db_block_height)
                # /roll back hdd too

                # rollback indices
                db_handler.tokens_rollback(node, db_block_height)
                db_handler.aliases_rollback(node, db_block_height)
                # /rollback indices

                node.last_block_timestamp = db_handler.last_block_timestamp()
                node.last_block_hash = db_handler.last_block_hash()
                node.last_block = db_block_height - 1
                node.hdd_hash = db_handler.last_block_hash()
                node.hdd_block = db_block_height - 1
                tokens.tokens_update(node, db_handler)

        except Exception as e:
            node.logger.app_log.warning(e)

        finally:
            node.db_lock.release()

            node.logger.app_log.warning(f"Database lock released")

            if skip:
                rollback = {"timestamp": my_time, "height": db_block_height, "ip": peer_ip,
                            "hash": db_block_hash, "skipped": True, "reason": reason}
                node.plugin_manager.execute_action_hook('rollback', rollback)
                node.logger.app_log.info(f"Skipping rollback: {reason}")
            else:
                try:
                    nb_tx = 0
                    for tx in backup_data:
                        tx_short = f"{tx[1]} - {tx[2]} to {tx[3]}: {tx[4]} ({tx[11]})"
                        if tx[9] == 0:
                            try:
                                nb_tx += 1
                                node.logger.app_log.info(
                                    mp.MEMPOOL.merge((tx[1], tx[2], tx[3], tx[4], tx[5], tx[6], tx[10], tx[11]),
                                                     peer_ip, db_handler.c, False, revert=True))  # will get stuck if you change it to respect node.db_lock
                                node.logger.app_log.warning(f"Moved tx back to mempool: {tx_short}")
                            except Exception as e:
                                node.logger.app_log.warning(f"Error during moving tx back to mempool: {e}")
                        else:
                            # It's the coinbase tx, so we get the miner address
                            miner = tx[3]
                            height = tx[0]
                    rollback = {"timestamp": my_time, "height": height, "ip": peer_ip, "miner": miner,
                                "hash": db_block_hash, "tx_count": nb_tx, "skipped": False, "reason": ""}
                    node.plugin_manager.execute_action_hook('rollback', rollback)

                except Exception as e:
                    node.logger.app_log.warning(f"Error during moving txs back to mempool: {e}")

    else:
        reason = "Skipping rollback, other ledger operation in progress"
        rollback = {"timestamp": my_time, "ip": peer_ip, "skipped": True, "reason": reason}
        node.plugin_manager.execute_action_hook('rollback', rollback)
        node.logger.app_log.info(reason)


def sequencing_check(db_handler, node):
    # TODO: Candidate for single user mode
    try:
        with open("sequencing_last", 'r') as filename:
            sequencing_last = int(filename.read())

    except:
        node.logger.app_log.warning("Sequencing anchor not found, going through the whole chain")
        sequencing_last = 0

    node.logger.app_log.warning(f"Status: Testing chain sequencing, starting with block {sequencing_last}")

    chains_to_check = [node.ledger_path, node.hyper_path]

    for chain in chains_to_check:
        conn = sqlite3.connect(chain)
        if node.trace_db_calls:
            conn.set_trace_callback(functools.partial(sql_trace_callback,node.logger.app_log,"SEQUENCE-CHECK-CHAIN"))
        c = conn.cursor()

        # perform test on transaction table
        y = None
        # Egg: not sure block_height != (0 OR 1)  gives the proper result, 0 or 1  = 1. not in (0, 1) could be better.
        for row in c.execute(
                "SELECT block_height FROM transactions WHERE reward != 0 AND block_height > 1 AND block_height >= ? ORDER BY block_height ASC",
                (sequencing_last,)):
            y_init = row[0]

            if y is None:
                y = y_init

            if row[0] != y:

                for chain2 in chains_to_check:
                    conn2 = sqlite3.connect(chain2)
                    if node.trace_db_calls:
                        conn2.set_trace_callback(functools.partial(sql_trace_callback,node.logger.app_log,"SEQUENCE-CHECK-CHAIN2"))
                    c2 = conn2.cursor()
                    node.logger.app_log.warning(f"Status: Chain {chain} transaction sequencing error at: {row[0]}. {row[0]} instead of {y}")
                    c2.execute("DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?", (row[0], -row[0],))
                    conn2.commit()
                    c2.execute("DELETE FROM misc WHERE block_height >= ?", (row[0],))
                    conn2.commit()

                    # rollback indices
                    db_handler.tokens_rollback(node, y)
                    db_handler.aliases_rollback(node, y)

                    # rollback indices

                    node.logger.app_log.warning(f"Status: Due to a sequencing issue at block {y}, {chain} has been rolled back and will be resynchronized")
                break

            y = y + 1

        # perform test on misc table
        y = None

        for row in c.execute("SELECT block_height FROM misc WHERE block_height > ? ORDER BY block_height ASC",
                             (300000,)):
            y_init = row[0]

            if y is None:
                y = y_init
                # print("assigned")
                # print(row[0], y)

            if row[0] != y:
                # print(row[0], y)
                for chain2 in chains_to_check:
                    conn2 = sqlite3.connect(chain2)
                    if node.trace_db_calls:
                        conn2.set_trace_callback(functools.partial(sql_trace_callback,node.logger.app_log,"SEQUENCE-CHECK-CHAIN2B"))
                    c2 = conn2.cursor()
                    node.logger.app_log.warning(
                        f"Status: Chain {chain} difficulty sequencing error at: {row[0]}. {row[0]} instead of {y}")
                    c2.execute("DELETE FROM transactions WHERE block_height >= ?", (row[0],))
                    conn2.commit()
                    c2.execute("DELETE FROM misc WHERE block_height >= ?", (row[0],))
                    conn2.commit()

                    db_handler.execute_param(conn2, (
                        'DELETE FROM transactions WHERE address = "Development Reward" AND block_height <= ?'),
                                             (-row[0],))
                    conn2.commit()

                    db_handler.execute_param(conn2, (
                        'DELETE FROM transactions WHERE address = "Hypernode Payouts" AND block_height <= ?'),
                                             (-row[0],))
                    conn2.commit()
                    conn2.close()

                    # rollback indices
                    db_handler.tokens_rollback(node, y)
                    db_handler.aliases_rollback(node, y)
                    # rollback indices

                    node.logger.app_log.warning(f"Status: Due to a sequencing issue at block {y}, {chain} has been rolled back and will be resynchronized")
                break

            y = y + 1

        node.logger.app_log.warning(f"Status: Chain sequencing test complete for {chain}")
        conn.close()

        if y:
            with open("sequencing_last", 'w') as filename:
                filename.write(str(y - 1000))  # room for rollbacks


def sql_trace_callback(log, id, statement):
    line = f"SQL[{id}] {statement}"
    log.warning(line)


def bootstrap(node):
    # TODO: Candidate for single user mode
    try:
        types = ['static/*.db-wal', 'static/*.db-shm']
        for t in types:
            for f in glob.glob(t):
                os.remove(f)
                print(f, "deleted")

        archive_path = node.ledger_path + ".tar.gz"
        download_file("https://bismuth.cz/ledger.tar.gz", archive_path)

        with tarfile.open(archive_path) as tar:
            tar.extractall("static/")  # NOT COMPATIBLE WITH CUSTOM PATH CONFS

    except:
        node.logger.app_log.warning("Something went wrong during bootstrapping, aborted")
        raise


def check_integrity(database, node):
    # TODO: Candidate for single user mode
    # check ledger integrity

    if not os.path.exists("static"):
        os.mkdir("static")

    with sqlite3.connect(database) as ledger_check:
        if node.trace_db_calls:
            ledger_check.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "CHECK_INTEGRITY"))

        ledger_check.text_factory = str
        l = ledger_check.cursor()

        try:
            l.execute("PRAGMA table_info('transactions')")
            redownload = False
        except:
            redownload = True

        if len(l.fetchall()) != 12:
            node.logger.app_log.warning(
                f"Status: Integrity check on database {database} failed, bootstrapping from the website")
            redownload = True

    if redownload and node.is_mainnet:
        bootstrap(node)


def bin_convert(string):
    # TODO: Move to essentials.py
    return ''.join(format(ord(x), '8b').replace(' ', '0') for x in string)


def balanceget(balance_address, db_handler, mp, node):
    # Get mempool transactions for the address
    base_mempool = mp.MEMPOOL.mp_get(balance_address)
    debit_mempool = Decimal("0")

    # Calculate mempool fees and debit
    if base_mempool:
        for tx in base_mempool:
            debit_tx = Decimal(tx[0])
            fee = fee_calculate(tx[1], tx[2], node.last_block)
            debit_mempool += quantize_eight(debit_tx + fee)

    # Use a single query to get ledger balances
    query = """
        SELECT 
            COALESCE(SUM(CASE WHEN recipient = ? THEN amount ELSE 0 END), 0) as credit,
            COALESCE(SUM(CASE WHEN address = ? THEN amount ELSE 0 END), 0) as debit,
            COALESCE(SUM(CASE WHEN address = ? THEN fee ELSE 0 END), 0) as fees,
            COALESCE(SUM(CASE WHEN recipient = ? THEN reward ELSE 0 END), 0) as rewards
        FROM transactions
        WHERE recipient = ? OR address = ?
    """

    try:
        db_handler.execute_param(db_handler.h, query,
                                 (balance_address, balance_address, balance_address,
                                  balance_address, balance_address, balance_address))
        result = db_handler.h.fetchone()
        credit_ledger, debit_ledger, fees, rewards = map(Decimal, result)
    except Exception:
        credit_ledger = debit_ledger = fees = rewards = Decimal("0")

    # Calculate balances
    balance = quantize_eight(credit_ledger - debit_ledger - fees + rewards - debit_mempool)
    balance_no_mempool = quantize_eight(credit_ledger - debit_ledger - fees + rewards)

    return (
        str(balance),
        str(credit_ledger),
        str(debit_ledger + debit_mempool),
        str(fees),
        str(rewards),
        str(balance_no_mempool)
    )


def ledger_check_heights(node, db_handler,db_handler_initial):
    # TODO: Candidate for single user mode
    """conversion of normal blocks into hyperblocks from ledger.db or hyper.db to hyper.db"""
    if os.path.exists(node.hyper_path):

        # cross-integrity check
        hdd_block_max = db_handler.block_height_max()
        hdd_block_max_diff = db_handler.block_height_max_diff()
        hdd2_block_last = db_handler.block_height_max_hyper()
        hdd2_block_last_misc = db_handler.block_height_max_diff_hyper()

        # cross-integrity check

        if hdd_block_max == hdd2_block_last == hdd2_block_last_misc == hdd_block_max_diff and node.hyper_recompress:  # cross-integrity check
            node.logger.app_log.warning("Status: Recompressing hyperblocks (keeping full ledger)")
            node.recompress = True

            #print (hdd_block_max,hdd2_block_last,node.hyper_recompress)
        elif hdd_block_max == hdd2_block_last and not node.hyper_recompress:
            node.logger.app_log.warning("Status: Hyperblock recompression skipped")
            node.recompress = False
        else:
            lowest_block = min(hdd_block_max, hdd2_block_last, hdd_block_max_diff, hdd2_block_last_misc)
            highest_block = max(hdd_block_max, hdd2_block_last, hdd_block_max_diff, hdd2_block_last_misc)

            node.logger.app_log.warning(
                f"Status: Cross-integrity check failed, {highest_block} will be rolled back below {lowest_block}")

            rollback(node,db_handler_initial,lowest_block) #rollback to the lowest value
            node.recompress = False

    else:
        node.logger.app_log.warning("Status: Compressing ledger to Hyperblocks")
        node.recompress = True


def recompress_ledger(node, rebuild=False, depth=15000):
    # TODO: Candidate for single user mode
    node.logger.app_log.warning(f"Status: Recompressing, please be patient")

    files_remove = [node.ledger_path + '.temp',node.ledger_path + '.temp-shm',node.ledger_path + '.temp-wal']
    for file in files_remove:
        if os.path.exists(file):
            os.remove(file)
            node.logger.app_log.warning(f"Removed old {file}")

    if rebuild:
        node.logger.app_log.warning(f"Status: Hyperblocks will be rebuilt")

        shutil.copy(node.ledger_path, node.ledger_path + '.temp')
        hyper = sqlite3.connect(node.ledger_path + '.temp')
    else:
        shutil.copy(node.hyper_path, node.ledger_path + '.temp')
        hyper = sqlite3.connect(node.ledger_path + '.temp')
    if node.trace_db_calls:
       hyper.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "HYPER"))
    hyper.text_factory = str
    hyp = hyper.cursor()

    hyp.execute("UPDATE transactions SET address = 'Hypoblock' WHERE address = 'Hyperblock'")

    hyp.execute("SELECT max(block_height) FROM transactions")
    db_block_height = int(hyp.fetchone()[0])
    depth_specific = db_block_height - depth

    hyp.execute(
        "SELECT distinct(recipient) FROM transactions WHERE (block_height < ? AND block_height > ?) ORDER BY block_height;",
        (depth_specific, -depth_specific,))  # new addresses will be ignored until depth passed
    unique_addressess = hyp.fetchall()

    for x in set(unique_addressess):
        credit = Decimal("0")
        for entry in hyp.execute(
                "SELECT amount,reward FROM transactions WHERE recipient = ? AND (block_height < ? AND block_height > ?);",
                (x[0],) + (depth_specific, -depth_specific,)):
            try:
                credit = quantize_eight(credit) + quantize_eight(entry[0]) + quantize_eight(entry[1])
                credit = 0 if credit is None else credit
            except Exception:
                credit = 0

        debit = Decimal("0")
        for entry in hyp.execute(
                "SELECT amount,fee FROM transactions WHERE address = ? AND (block_height < ? AND block_height > ?);",
                (x[0],) + (depth_specific, -depth_specific,)):
            try:
                debit = quantize_eight(debit) + quantize_eight(entry[0]) + quantize_eight(entry[1])
                debit = 0 if debit is None else debit
            except Exception:
                debit = 0

        end_balance = quantize_eight(credit - debit)

        if end_balance > 0:
            timestamp = str(time.time())
            hyp.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                depth_specific - 1, timestamp, "Hyperblock", x[0], str(end_balance), "0", "0", "0", "0",
                "0", "0", "0"))
    hyper.commit()

    hyp.execute(
        "DELETE FROM transactions WHERE address != 'Hyperblock' AND (block_height < ? AND block_height > ?);",
        (depth_specific, -depth_specific,))
    hyper.commit()

    hyp.execute("DELETE FROM misc WHERE (block_height < ? AND block_height > ?);",
                (depth_specific, -depth_specific,))  # remove diff calc
    hyper.commit()

    hyp.execute("VACUUM")
    hyper.close()

    if os.path.exists(node.hyper_path):
        os.remove(node.hyper_path)  # remove the old hyperblocks to rebuild
        os.rename(node.ledger_path + '.temp', node.hyper_path)


def rollback(node, db_handler, block_height):
    node.logger.app_log.warning(f"Status: Rolling back below: {block_height}")

    db_handler.rollback_under(block_height)

    # rollback indices
    db_handler.tokens_rollback(node, block_height)
    db_handler.aliases_rollback(node, block_height)
    # rollback indices

    node.logger.app_log.warning(f"Status: Chain rolled back below {block_height} and will be resynchronized")


def just_int_from(s):
    # TODO: move to essentials.py
    return int(''.join(i for i in s if i.isdigit()))


def setup_net_type(node, regnet):
    """
    Adjust globals depending on mainnet, testnet or regnet
    """
    # TODO: only deals with 'node' structure, candidate for single user mode.
    # Defaults value, dup'd here for clarity sake.
    node.is_mainnet = True
    node.is_testnet = False
    node.is_regnet = False

    if "testnet" in node.version or node.is_testnet:
        node.is_testnet = True
        node.is_mainnet = False
        node.version_allow = "testnet"

    if "regnet" in node.version or node.is_regnet:
        node.is_regnet = True
        node.is_testnet = False
        node.is_mainnet = False

    node.logger.app_log.warning(f"Testnet: {node.is_testnet}")
    node.logger.app_log.warning(f"Regnet : {node.is_regnet}")

    # default mainnet config
    node.peerfile = "peers.txt"
    node.ledger_ram_file = "file:ledger?mode=memory&cache=shared"
    node.index_db = "static/index.db"

    if node.is_mainnet:
        # Allow only 21 and up
        if node.version != 'mainnet0022':
            node.version = 'mainnet0022'  # Force in code.
        if "mainnet0021" not in node.version_allow:
            node.version_allow = ['mainnet0021', 'mainnet0022', 'mainnet0023']
        # Do not allow bad configs.
        if not 'mainnet' in node.version:
            node.logger.app_log.error("Bad mainnet version, check config.txt")
            sys.exit()
        num_ver = just_int_from(node.version)
        if num_ver <21:
            node.logger.app_log.error("Too low mainnet version, check config.txt")
            sys.exit()
        for allowed in node.version_allow:
            num_ver = just_int_from(allowed)
            if num_ver < 20:
                node.logger.app_log.error("Too low allowed version, check config.txt")
                sys.exit()

    if "testnet" in node.version or node.is_testnet:
        node.port = 2829
        node.hyper_path = "static/hyper_test.db"
        node.ledger_path = "static/ledger_test.db"

        node.ledger_ram_file = "file:ledger_testnet?mode=memory&cache=shared"
        #node.hyper_recompress = False
        node.peerfile = "peers_test.txt"
        node.index_db = "static/index_test.db"
        if not 'testnet' in node.version:
            node.logger.app_log.error("Bad testnet version, check config.txt")
            sys.exit()

        redownload_test = input("Status: Welcome to the testnet. Redownload test ledger? y/n")
        if redownload_test == "y":
            types = ['static/ledger_test.db-wal', 'static/ledger_test.db-shm', 'static/index_test.db', 'static/hyper_test.db-wal', 'static/hyper_test.db-shm']
            for type in types:
                for file in glob.glob(type):
                    os.remove(file)
                    print(file, "deleted")
            download_file("https://bismuth.cz/test.tar.gz", "static/test.tar.gz")
            with tarfile.open("static/test.tar.gz") as tar:
                tar.extractall("static/")  # NOT COMPATIBLE WITH CUSTOM PATH CONFS
        else:
            print("Not redownloading test db")

    if "regnet" in node.version or node.is_regnet:
        node.port = regnet.REGNET_PORT
        node.hyper_path = regnet.REGNET_DB
        node.ledger_path = regnet.REGNET_DB
        node.ledger_ram_file = "file:ledger_regnet?mode=memory&cache=shared"
        node.hyper_recompress = False
        node.peerfile = regnet.REGNET_PEERS
        node.index_db = regnet.REGNET_INDEX
        if not 'regnet' in node.version:
            node.logger.app_log.error("Bad regnet version, check config.txt")
            sys.exit()
        if not node.heavy:
            node.logger.app_log.warning("Regnet with no heavy file...")
            mining_heavy3.heavy = False
        node.logger.app_log.warning("Regnet init...")
        regnet.init(node.logger.app_log)
        regnet.DIGEST_BLOCK = digest_block
        mining_heavy3.is_regnet = True
        """
        node.logger.app_log.warning("Regnet still is WIP atm.")
        sys.exit()
        """


def node_block_init(database, node, db_handler_initial):
    # TODO: candidate for single user mode
    node.hdd_block = database.block_height_max()
    node.difficulty = difficulty(node, db_handler_initial)  # check diff for miner

    node.last_block = node.hdd_block  # ram equals drive at this point

    node.last_block_hash = database.last_block_hash()
    node.hdd_hash = node.last_block_hash # ram equals drive at this point

    node.last_block_timestamp = database.last_block_timestamp()

    checkpoint_set(node)

    node.logger.app_log.warning("Status: Indexing aliases")

    aliases.aliases_update(node, database)


def ram_init(database, node):
    # TODO: candidate for single user mode
    try:
        if node.ram:
            node.logger.app_log.warning("Status: Moving database to RAM")

            if node.py_version >= 370:
                temp_target = sqlite3.connect(node.ledger_ram_file, uri=True, isolation_level=None, timeout=1)
                if node.trace_db_calls:
                    temp_target.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "TEMP-TARGET"))

                temp_source = sqlite3.connect(node.hyper_path, uri=True, isolation_level=None, timeout=1)
                if node.trace_db_calls:
                    temp_source.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "TEMP-SOURCE"))
                temp_source.backup(temp_target)
                temp_source.close()

            else:
                source_db = sqlite3.connect(node.hyper_path, timeout=1)
                if node.trace_db_calls:
                    source_db.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "SOURCE-DB"))
                database.to_ram = sqlite3.connect(node.ledger_ram_file, uri=True, timeout=1, isolation_level=None)
                if node.trace_db_calls:
                    database.to_ram.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "DATABASE-TO-RAM"))
                database.to_ram.text_factory = str
                database.tr = database.to_ram.cursor()

                query = "".join(line for line in source_db.iterdump())
                database.to_ram.executescript(query)
                source_db.close()

            node.logger.app_log.warning("Status: Hyperblock ledger moved to RAM")

            #source = sqlite3.connect('existing_db.db')
            #dest = sqlite3.connect(':memory:')
            #source.backup(dest)

    except Exception as e:
        node.logger.app_log.warning(e)
        raise


def initial_db_check(node):
    """
    Initial bootstrap check and chain validity control
    """
    # TODO: candidate for single user mode
    # force bootstrap via adding an empty "fresh_sync" file in the dir.
    if os.path.exists("fresh_sync") and node.is_mainnet:
        node.logger.app_log.warning("Status: Fresh sync required, bootstrapping from the website")
        os.remove("fresh_sync")
        bootstrap(node)
    # UPDATE mainnet DB if required
    if node.is_mainnet:
        upgrade = sqlite3.connect(node.ledger_path)
        if node.trace_db_calls:
            upgrade.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "INITIAL_DB_CHECK"))
        u = upgrade.cursor()
        try:
            u.execute("PRAGMA table_info(transactions);")
            result = u.fetchall()[10][2]
            if result != "TEXT":
                raise ValueError("Database column type outdated for Command field")
            upgrade.close()
        except Exception as e:
            print(e)
            upgrade.close()
            print("Database needs upgrading, bootstrapping...")
            bootstrap(node)


def load_keys(node, regnet=None):
    """Initial loading of crypto keys"""
    # TODO: candidate for single user mode
    essentials.keys_check(node.logger.app_log, "wallet.der")

    node.keys.key, node.keys.public_key_readable, node.keys.private_key_readable, _, _, node.keys.public_key_b64encoded, node.keys.address, node.keys.keyfile = essentials.keys_load(
        "privkey.der", "pubkey.der")

    if node.is_regnet:
        regnet.PRIVATE_KEY_READABLE = node.keys.private_key_readable
        regnet.PUBLIC_KEY_B64ENCODED = node.keys.public_key_b64encoded
        regnet.ADDRESS = node.keys.address
        regnet.KEY = node.keys.key

    node.logger.app_log.warning(f"Status: Local address: {node.keys.address}")
