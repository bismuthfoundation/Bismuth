"""
Blockchain node implementation - refactored for clarity while maintaining simplicity
"""

import functools
import glob
import os
import shutil
import sqlite3
import sys
import tarfile
import time
from decimal import Decimal

from Cryptodome.Hash import SHA
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


def sql_trace_callback(log, id, statement):
    """SQL query tracing for debugging"""
    log.warning(f"SQL[{id}] {statement}")


def add_indices(db_handler: dbhandler.DbHandler, node):
    """Add database indices for improved query performance"""
    TXID4_INDEX = "CREATE INDEX IF NOT EXISTS TXID4_Index ON transactions(substr(signature,1,4))"
    MISC_HEIGHT_INDEX = "CREATE INDEX IF NOT EXISTS 'Misc Block Height Index' on misc(block_height)"

    node.logger.app_log.warning("Creating indices")

    for db in [db_handler.h, db_handler.h2, db_handler.c]:
        if not node.old_sqlite:
            db_handler.execute(db, TXID4_INDEX)
        else:
            node.logger.app_log.warning("Setting old_sqlite is True, lookups will be slower.")
        db_handler.execute(db, MISC_HEIGHT_INDEX)

    node.logger.app_log.warning("Finished creating indices")


def initial_db_check(node):
    """Initial bootstrap check and chain validity control"""
    # Force bootstrap if fresh_sync file exists
    if os.path.exists("fresh_sync") and node.is_mainnet:
        node.logger.app_log.warning("Status: Fresh sync required, bootstrapping from the website")
        os.remove("fresh_sync")
        bootstrap(node)

    # Check if mainnet DB needs upgrade
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
        except Exception as e:
            print(f"Database needs upgrading: {e}")
            print("Bootstrapping...")
            bootstrap(node)
        finally:
            upgrade.close()


def load_keys(node, regnet=None):
    """Load cryptographic keys"""
    essentials.keys_check(node.logger.app_log, "wallet.der")

    (node.keys.key,
     node.keys.public_key_readable,
     node.keys.private_key_readable,
     _,
     _,
     node.keys.public_key_b64encoded,
     node.keys.address,
     node.keys.keyfile) = essentials.keys_load("privkey.der", "pubkey.der")

    if node.is_regnet and regnet:
        regnet.PRIVATE_KEY_READABLE = node.keys.private_key_readable
        regnet.PUBLIC_KEY_B64ENCODED = node.keys.public_key_b64encoded
        regnet.ADDRESS = node.keys.address
        regnet.KEY = node.keys.key

    node.logger.app_log.warning(f"Status: Local address: {node.keys.address}")

def verify(db_handler, node):
    """Verify blockchain integrity"""
    try:
        node.logger.app_log.warning("Blockchain verification started...")

        # Get total count
        db_handler.execute(db_handler.h, "SELECT Count(*) FROM transactions")
        db_rows = db_handler.h.fetchone()[0]
        node.logger.app_log.warning(f"Total steps: {db_rows}")

        # Verify genesis
        try:
            db_handler.execute(db_handler.h,
                               "SELECT block_height, recipient FROM transactions WHERE block_height = 1")
            result = db_handler.h.fetchall()[0]
            if str(result[1]) != node.genesis and int(result[0]) == 0:
                node.logger.app_log.warning("Invalid genesis address")
                sys.exit(1)
            node.logger.app_log.warning(f"Genesis: {result[1]}")
        except:
            node.logger.app_log.warning("Hyperblock mode in use")

        # Verify transactions
        invalid = 0
        query = 'SELECT * FROM transactions WHERE block_height > 0 and reward = 0 ORDER BY block_height'

        for row in db_handler.h.execute(query):
            db_block_height = str(row[0])
            db_timestamp = '%.2f' % quantize_two(row[1])
            db_address = str(row[2])[:56]
            db_recipient = str(row[3])[:56]
            db_amount = '%.8f' % quantize_eight(row[4])
            db_signature_enc = str(row[5])[:684]
            db_public_key_b64encoded = str(row[6])[:1068]
            db_operation = str(row[10])[:30]
            db_openfield = str(row[11])

            db_transaction = str((db_timestamp, db_address, db_recipient, db_amount,
                                  db_operation, db_openfield)).encode("utf-8")

            try:
                SignerFactory.verify_bis_signature(db_signature_enc, db_public_key_b64encoded,
                                                   db_transaction, db_address)
            except:
                sha_hash = SHA.new(db_transaction)
                try:
                    if sha_hash.hexdigest() != db_hashes[f"{db_block_height}-{db_timestamp}"]:
                        node.logger.app_log.warning(f"Signature validation problem: {db_block_height}")
                        invalid += 1
                except:
                    node.logger.app_log.warning(f"Signature validation problem: {db_block_height}")
                    invalid += 1

        if invalid == 0:
            node.logger.app_log.warning("All transactions in the local ledger are valid")

    except Exception as e:
        node.logger.app_log.warning(f"Error: {e}")
        raise


def blocknf(node, block_hash_delete, peer_ip, db_handler, hyperblocks=False, mp=None, tokens=None):
    """Roll back a single block, must be above checkpoint"""
    node.logger.app_log.info(f"Rollback operation on {block_hash_delete} initiated by {peer_ip}")
    my_time = time.time()

    if node.db_lock.locked():
        reason = "Skipping rollback, other ledger operation in progress"
        rollback = {"timestamp": my_time, "ip": peer_ip, "skipped": True, "reason": reason}
        node.plugin_manager.execute_action_hook('rollback', rollback)
        node.logger.app_log.info(reason)
        return

    node.db_lock.acquire()
    node.logger.app_log.warning("Database lock acquired")

    backup_data = None
    skip = False
    reason = ""

    try:
        block_max_ram = db_handler.block_max_ram()
        db_block_height = block_max_ram['block_height']
        db_block_hash = block_max_ram['block_hash']

        # Check if we should skip
        ip = {'ip': peer_ip}
        node.plugin_manager.execute_filter_hook('filter_rollback_ip', ip)

        if ip['ip'] == 'no':
            reason = "Filter blocked this rollback"
            skip = True
        elif db_block_height < node.checkpoint:
            reason = "Block is past checkpoint, will not be rolled back"
            skip = True
        elif db_block_hash != block_hash_delete:
            reason = "We moved away from the block to rollback, skipping"
            skip = True
        elif hyperblocks and node.last_block_ago > 30000:
            reason = f"{peer_ip} is running on hyperblocks and our last block is too old, skipping"
            skip = True
        else:
            # Perform rollback
            backup_data = db_handler.backup_higher(db_block_height)
            node.logger.app_log.warning(f"Node {peer_ip} didn't find block {db_block_height}({db_block_hash})")

            db_handler.rollback_under(db_block_height)
            db_handler.tokens_rollback(node, db_block_height)
            db_handler.aliases_rollback(node, db_block_height)

            # Update node state
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
        node.logger.app_log.warning("Database lock released")

        if skip:
            rollback = {"timestamp": my_time, "height": db_block_height, "ip": peer_ip,
                        "hash": db_block_hash, "skipped": True, "reason": reason}
            node.plugin_manager.execute_action_hook('rollback', rollback)
            node.logger.app_log.info(f"Skipping rollback: {reason}")
        else:
            # Return transactions to mempool
            try:
                nb_tx = 0
                miner = None
                height = db_block_height

                for tx in backup_data:
                    if tx[9] == 0:  # Regular transaction
                        try:
                            nb_tx += 1
                            node.logger.app_log.info(
                                mp.MEMPOOL.merge((tx[1], tx[2], tx[3], tx[4], tx[5], tx[6], tx[10], tx[11]),
                                                 peer_ip, db_handler.c, False, revert=True))
                            node.logger.app_log.warning(f"Moved tx back to mempool")
                        except Exception as e:
                            node.logger.app_log.warning(f"Error moving tx to mempool: {e}")
                    else:  # Coinbase
                        miner = tx[3]
                        height = tx[0]

                rollback = {"timestamp": my_time, "height": height, "ip": peer_ip, "miner": miner,
                            "hash": db_block_hash, "tx_count": nb_tx, "skipped": False, "reason": ""}
                node.plugin_manager.execute_action_hook('rollback', rollback)

            except Exception as e:
                node.logger.app_log.warning(f"Error during moving txs back to mempool: {e}")


def sequencing_check(db_handler, node):
    """Check and fix chain sequencing issues"""
    # Get last check position
    try:
        with open("sequencing_last", 'r') as f:
            sequencing_last = int(f.read())
    except:
        node.logger.app_log.warning("Sequencing anchor not found, going through the whole chain")
        sequencing_last = 0

    node.logger.app_log.warning(f"Status: Testing chain sequencing, starting with block {sequencing_last}")

    chains_to_check = [node.ledger_path, node.hyper_path]

    for chain in chains_to_check:
        conn = sqlite3.connect(chain)
        if node.trace_db_calls:
            conn.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "SEQUENCE-CHECK"))
        c = conn.cursor()

        # Check transactions table
        y = None
        for row in c.execute(
                "SELECT block_height FROM transactions WHERE reward != 0 AND block_height > 1 AND block_height >= ? ORDER BY block_height ASC",
                (sequencing_last,)):

            if y is None:
                y = row[0]

            if row[0] != y:
                _fix_sequencing_error(chains_to_check, chain, row[0], y, node, db_handler)
                break
            y += 1

        # Check misc table
        y = None
        for row in c.execute("SELECT block_height FROM misc WHERE block_height > ? ORDER BY block_height ASC",
                             (300000,)):
            if y is None:
                y = row[0]

            if row[0] != y:
                _fix_sequencing_error(chains_to_check, chain, row[0], y, node, db_handler)
                break
            y += 1

        node.logger.app_log.warning(f"Status: Chain sequencing test complete for {chain}")
        conn.close()

        # Save position
        if y:
            with open("sequencing_last", 'w') as f:
                f.write(str(y - 1000))  # Room for rollbacks


def _fix_sequencing_error(chains_to_check, chain, error_height, expected_height, node, db_handler):
    """Fix a sequencing error by rolling back"""
    node.logger.app_log.warning(
        f"Status: Chain {chain} sequencing error at: {error_height}. {error_height} instead of {expected_height}")

    for chain2 in chains_to_check:
        conn2 = sqlite3.connect(chain2)
        if node.trace_db_calls:
            conn2.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "SEQUENCE-FIX"))
        c2 = conn2.cursor()

        c2.execute("DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?",
                   (error_height, -error_height))
        conn2.commit()

        c2.execute("DELETE FROM misc WHERE block_height >= ?", (error_height,))
        conn2.commit()

        for address in ["Development Reward", "Hypernode Payouts"]:
            db_handler.execute_param(conn2,
                                     f'DELETE FROM transactions WHERE address = "{address}" AND block_height <= ?',
                                     (-error_height,))
            conn2.commit()

        conn2.close()

        db_handler.tokens_rollback(node, expected_height)
        db_handler.aliases_rollback(node, expected_height)

        node.logger.app_log.warning(f"Status: Chain {chain} rolled back due to sequencing issue")


def bootstrap(node):
    """Bootstrap blockchain from remote source"""
    try:
        # Clean up old files
        for pattern in ['static/*.db-wal', 'static/*.db-shm']:
            for f in glob.glob(pattern):
                os.remove(f)
                print(f"{f} deleted")

        # Download and extract
        archive_path = f"{node.ledger_path}.tar.gz"
        download_file("https://bismuth.cz/ledger.tar.gz", archive_path)

        with tarfile.open(archive_path) as tar:
            tar.extractall("static/")

    except:
        node.logger.app_log.warning("Something went wrong during bootstrapping, aborted")
        raise


def check_integrity(database, node):
    """Check database integrity and bootstrap if needed"""
    if not os.path.exists("static"):
        os.mkdir("static")

    redownload = False

    with sqlite3.connect(database) as ledger_check:
        if node.trace_db_calls:
            ledger_check.set_trace_callback(
                functools.partial(sql_trace_callback, node.logger.app_log, "CHECK_INTEGRITY"))

        ledger_check.text_factory = str
        l = ledger_check.cursor()

        try:
            l.execute("PRAGMA table_info('transactions')")
            if len(l.fetchall()) != 12:
                node.logger.app_log.warning(f"Status: Integrity check on database {database} failed")
                redownload = True
        except:
            redownload = True

    if redownload and node.is_mainnet:
        node.logger.app_log.warning("Bootstrapping from the website")
        bootstrap(node)


def balanceget(balance_address, db_handler, mp, node):
    """Get balance for an address including mempool"""
    # Get mempool balance
    base_mempool = mp.MEMPOOL.mp_get(balance_address)
    debit_mempool = Decimal("0")

    if base_mempool:
        for tx in base_mempool:
            debit_tx = Decimal(tx[0])
            fee = fee_calculate(tx[1], tx[2], node.last_block)
            debit_mempool += quantize_eight(debit_tx + fee)

    # Get ledger balances with single query
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
                                 (balance_address, balance_address, balance_address, balance_address, balance_address,
                                  balance_address))
        result = db_handler.h.fetchone()
        credit_ledger, debit_ledger, fees, rewards = map(Decimal, result)
    except:
        credit_ledger = debit_ledger = fees = rewards = Decimal("0")

    # Calculate final balances
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


def ledger_check_heights(node, db_handler, db_handler_initial):
    """Check and sync ledger heights between databases"""
    if not os.path.exists(node.hyper_path):
        node.logger.app_log.warning("Status: Compressing ledger to Hyperblocks")
        node.recompress = True
        return

    # Get all heights
    hdd_block_max = db_handler.block_height_max()
    hdd_block_max_diff = db_handler.block_height_max_diff()
    hdd2_block_last = db_handler.block_height_max_hyper()
    hdd2_block_last_misc = db_handler.block_height_max_diff_hyper()

    # Check integrity
    if hdd_block_max == hdd2_block_last == hdd2_block_last_misc == hdd_block_max_diff and node.hyper_recompress:
        node.logger.app_log.warning("Status: Recompressing hyperblocks (keeping full ledger)")
        node.recompress = True
    elif hdd_block_max == hdd2_block_last and not node.hyper_recompress:
        node.logger.app_log.warning("Status: Hyperblock recompression skipped")
        node.recompress = False
    else:
        lowest = min(hdd_block_max, hdd2_block_last, hdd_block_max_diff, hdd2_block_last_misc)
        highest = max(hdd_block_max, hdd2_block_last, hdd_block_max_diff, hdd2_block_last_misc)

        node.logger.app_log.warning(
            f"Status: Cross-integrity check failed, {highest} will be rolled back below {lowest}")
        rollback(node, db_handler_initial, lowest)
        node.recompress = False


def recompress_ledger(node, rebuild=False, depth=15000):
    """Recompress ledger to hyperblocks"""
    node.logger.app_log.warning("Status: Recompressing, please be patient")

    # Clean up old files
    for ext in ['', '-shm', '-wal']:
        file_path = f"{node.ledger_path}.temp{ext}"
        if os.path.exists(file_path):
            os.remove(file_path)
            node.logger.app_log.warning(f"Removed old {file_path}")

    # Prepare database
    if rebuild:
        node.logger.app_log.warning("Status: Hyperblocks will be rebuilt")
        shutil.copy(node.ledger_path, f"{node.ledger_path}.temp")
    else:
        shutil.copy(node.hyper_path, f"{node.ledger_path}.temp")

    hyper = sqlite3.connect(f"{node.ledger_path}.temp")
    if node.trace_db_calls:
        hyper.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "HYPER"))
    hyper.text_factory = str
    hyp = hyper.cursor()

    # Mark old hyperblocks
    hyp.execute("UPDATE transactions SET address = 'Hypoblock' WHERE address = 'Hyperblock'")

    # Get depth
    hyp.execute("SELECT max(block_height) FROM transactions")
    db_block_height = int(hyp.fetchone()[0])
    depth_specific = db_block_height - depth

    # Get unique addresses
    hyp.execute(
        "SELECT distinct(recipient) FROM transactions WHERE (block_height < ? AND block_height > ?) ORDER BY block_height",
        (depth_specific, -depth_specific))
    unique_addresses = hyp.fetchall()

    # Process each address
    for x in set(unique_addresses):
        # Calculate credit
        credit = Decimal("0")
        for entry in hyp.execute(
                "SELECT amount,reward FROM transactions WHERE recipient = ? AND (block_height < ? AND block_height > ?)",
                (x[0], depth_specific, -depth_specific)):
            try:
                credit = quantize_eight(credit) + quantize_eight(entry[0] or 0) + quantize_eight(entry[1] or 0)
            except:
                pass

        # Calculate debit
        debit = Decimal("0")
        for entry in hyp.execute(
                "SELECT amount,fee FROM transactions WHERE address = ? AND (block_height < ? AND block_height > ?)",
                (x[0], depth_specific, -depth_specific)):
            try:
                debit = quantize_eight(debit) + quantize_eight(entry[0] or 0) + quantize_eight(entry[1] or 0)
            except:
                pass

        # Create hyperblock entry if positive balance
        end_balance = quantize_eight(credit - debit)
        if end_balance > 0:
            timestamp = str(time.time())
            hyp.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (depth_specific - 1, timestamp, "Hyperblock", x[0], str(end_balance),
                         "0", "0", "0", "0", "0", "0", "0"))

    hyper.commit()

    # Clean up old transactions
    hyp.execute("DELETE FROM transactions WHERE address != 'Hyperblock' AND (block_height < ? AND block_height > ?)",
                (depth_specific, -depth_specific))
    hyper.commit()

    hyp.execute("DELETE FROM misc WHERE (block_height < ? AND block_height > ?)",
                (depth_specific, -depth_specific))
    hyper.commit()

    hyp.execute("VACUUM")
    hyper.close()

    # Replace old file
    if os.path.exists(node.hyper_path):
        os.remove(node.hyper_path)
    os.rename(f"{node.ledger_path}.temp", node.hyper_path)


def rollback(node, db_handler, block_height):
    """Roll back blockchain to specified height"""
    node.logger.app_log.warning(f"Status: Rolling back below: {block_height}")

    db_handler.rollback_under(block_height)
    db_handler.tokens_rollback(node, block_height)
    db_handler.aliases_rollback(node, block_height)

    node.logger.app_log.warning(f"Status: Chain rolled back below {block_height} and will be resynchronized")


def just_int_from(s):
    """Extract integer from string"""
    return int(''.join(i for i in s if i.isdigit()))


def bin_convert(string):
    """Convert string to binary representation"""
    return ''.join(format(ord(x), '8b').replace(' ', '0') for x in string)


def setup_net_type(node, regnet):
    """Configure node for mainnet, testnet, or regnet"""
    # Set defaults
    node.is_mainnet = True
    node.is_testnet = False
    node.is_regnet = False

    # Configure based on version
    if "testnet" in node.version or node.is_testnet:
        _setup_testnet(node)
    elif "regnet" in node.version or node.is_regnet:
        _setup_regnet(node, regnet)
    else:
        _setup_mainnet(node)

    node.logger.app_log.warning(f"Testnet: {node.is_testnet}")
    node.logger.app_log.warning(f"Regnet : {node.is_regnet}")


def _setup_mainnet(node):
    """Configure mainnet settings"""
    node.peerfile = "peers.txt"
    node.ledger_ram_file = "file:ledger?mode=memory&cache=shared"
    node.index_db = "static/index.db"

    # Force correct version
    if node.version != 'mainnet0022':
        node.version = 'mainnet0022'

    if "mainnet0021" not in node.version_allow:
        node.version_allow = ['mainnet0021', 'mainnet0022', 'mainnet0023']

    # Validate version
    if 'mainnet' not in node.version:
        node.logger.app_log.error("Bad mainnet version, check config.txt")
        sys.exit()

    num_ver = just_int_from(node.version)
    if num_ver < 21:
        node.logger.app_log.error("Too low mainnet version, check config.txt")
        sys.exit()

    for allowed in node.version_allow:
        if just_int_from(allowed) < 20:
            node.logger.app_log.error("Too low allowed version, check config.txt")
            sys.exit()


def _setup_testnet(node):
    """Configure testnet settings"""
    node.is_testnet = True
    node.is_mainnet = False
    node.version_allow = "testnet"

    node.port = 2829
    node.hyper_path = "static/hyper_test.db"
    node.ledger_path = "static/ledger_test.db"
    node.ledger_ram_file = "file:ledger_testnet?mode=memory&cache=shared"
    node.peerfile = "peers_test.txt"
    node.index_db = "static/index_test.db"

    if 'testnet' not in node.version:
        node.logger.app_log.error("Bad testnet version, check config.txt")
        sys.exit()

    # Offer redownload
    if input("Status: Welcome to the testnet. Redownload test ledger? y/n: ").lower() == "y":
        for pattern in ['static/ledger_test.db-wal', 'static/ledger_test.db-shm',
                        'static/index_test.db', 'static/hyper_test.db-wal', 'static/hyper_test.db-shm']:
            for f in glob.glob(pattern):
                os.remove(f)
                print(f"{f} deleted")

        download_file("https://bismuth.cz/test.tar.gz", "static/test.tar.gz")
        with tarfile.open("static/test.tar.gz") as tar:
            tar.extractall("static/")
    else:
        print("Not redownloading test db")


def _setup_regnet(node, regnet):
    """Configure regnet settings"""
    node.is_regnet = True
    node.is_testnet = False
    node.is_mainnet = False

    node.port = regnet.REGNET_PORT
    node.hyper_path = regnet.REGNET_DB
    node.ledger_path = regnet.REGNET_DB
    node.ledger_ram_file = "file:ledger_regnet?mode=memory&cache=shared"
    node.hyper_recompress = False
    node.peerfile = regnet.REGNET_PEERS
    node.index_db = regnet.REGNET_INDEX

    if 'regnet' not in node.version:
        node.logger.app_log.error("Bad regnet version, check config.txt")
        sys.exit()

    if not node.heavy:
        node.logger.app_log.warning("Regnet with no heavy file...")
        mining_heavy3.heavy = False

    node.logger.app_log.warning("Regnet init...")
    regnet.init(node.logger.app_log)
    regnet.DIGEST_BLOCK = digest_block
    mining_heavy3.is_regnet = True


def node_block_init(database, node, db_handler_initial):
    """Initialize node block-related variables"""
    node.hdd_block = database.block_height_max()
    node.difficulty = difficulty(node, db_handler_initial)
    node.last_block = node.hdd_block
    node.last_block_hash = database.last_block_hash()
    node.hdd_hash = node.last_block_hash
    node.last_block_timestamp = database.last_block_timestamp()

    checkpoint_set(node)

    node.logger.app_log.warning("Status: Indexing aliases")
    aliases.aliases_update(node, database)


def ram_init(database, node):
    """Initialize RAM database if configured"""
    if not node.ram:
        return

    try:
        node.logger.app_log.warning("Status: Moving database to RAM")

        if node.py_version >= 370:
            # Modern Python version
            temp_target = sqlite3.connect(node.ledger_ram_file, uri=True, isolation_level=None, timeout=1)
            if node.trace_db_calls:
                temp_target.set_trace_callback(
                    functools.partial(sql_trace_callback, node.logger.app_log, "TEMP-TARGET"))

            temp_source = sqlite3.connect(node.hyper_path, uri=True, isolation_level=None, timeout=1)
            if node.trace_db_calls:
                temp_source.set_trace_callback(
                    functools.partial(sql_trace_callback, node.logger.app_log, "TEMP-SOURCE"))

            temp_source.backup(temp_target)
            temp_source.close()
        else:
            # Legacy Python version
            source_db = sqlite3.connect(node.hyper_path, timeout=1)
            if node.trace_db_calls:
                source_db.set_trace_callback(functools.partial(sql_trace_callback, node.logger.app_log, "SOURCE-DB"))

            database.to_ram = sqlite3.connect(node.ledger_ram_file, uri=True, timeout=1, isolation_level=None)
            if node.trace_db_calls:
                database.to_ram.set_trace_callback(
                    functools.partial(sql_trace_callback, node.logger.app_log, "DATABASE-TO-RAM"))

            database.to_ram.text_factory = str
            database.tr = database.to_ram.cursor()

            query = "".join(line for line in source_db.iterdump())
            database.to_ram.executescript(query)
            source_db.close()

        node.logger.app_log.warning("Status: Hyperblock ledger moved to RAM")

    except Exception as e:
        node.logger.app_log.warning(f"RAM init error: {e}")
        raise