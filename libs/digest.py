"""
Exports digest_block, the main block digesting function.
def digest_block(node: "Node", data, sdef, peer_ip: str, db_handler: "DbHandler")
"""

import hashlib
import os
import sys
from time import time as ttime, sleep
from libs import mempool as mp, mining_heavy3, regnet
from libs.difficulty import difficulty
from libs.essentials import address_validate, address_is_rsa
from polysign.signerfactory import SignerFactory
from bismuthcore.compat import quantize_two, quantize_eight
from bismuthcore.helpers import fee_calculate
from libs.fork import Fork
from decimal import Decimal
from bismuthcore.transaction import Transaction

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from libs.node import Node  # for type hinting
    from libs.dbhandler import DbHandler

fork = Fork()


class TransactionLegacy:
    def __init__(self):
        self.start_time_tx = 0
        self.q_received_timestamp = 0
        self.received_timestamp = "0.00"
        self.received_address = None
        self.received_recipient = None
        self.received_amount = '0'
        self.received_signature_enc = None
        self.received_public_key_b64encoded = None
        self.received_operation = None
        self.received_openfield = None


class MinerTransactionLegacy:
    def __init__(self):
        self.q_block_timestamp = 0
        self.nonce = None
        self.miner_address = None


class Block:
    """array of transactions within a block"""

    def __init__(self):
        self.tx_count = 0
        self.block_height_new = None
        self.block_hash = 'N/A'
        self.failed_cause = ''
        self.block_count = 0
        self.transaction_list_converted = []
        self.transactions = []

        self.mining_reward = None
        self.mirror_hash = None
        self.start_time_block = ttime()
        self.tokens_operation_present = False


def fork_reward_check(node: "Node", db_handler: "DbHandler"):
    """Checks whether fork conditions apply"""
    if fork.config is None:
        fork.config = node.config
    if node.is_testnet:
        if node.last_block > fork.POW_FORK_TESTNET:
            if not fork.check_postfork_reward_testnet(db_handler):
                db_handler.rollback_under(fork.POW_FORK_TESTNET - 1)
                raise ValueError("Rolling back chain due to old fork data")
    else:
        if node.last_block > fork.POW_FORK:
            if not fork.check_postfork_reward(db_handler):
                print("Rolling back chain due to old fork data")
                db_handler.rollback_under(fork.POW_FORK - 1)
                raise ValueError("Rolling back chain due to old fork data")


def rewards(node: "Node", block_instance: Block, db_handler: "DbHandler", miner_tx: MinerTransactionLegacy):
    """Checks whether reward conditions apply, development rewards and hn contract rewards"""
    if int(block_instance.block_height_new) % 10 == 0 and block_instance.block_height_new < 4380000:  # every 10 blocks and only until 4380000
        db_handler.dev_reward(node, block_instance, miner_tx, block_instance.mining_reward, block_instance.mirror_hash)
        db_handler.hn_reward(node, block_instance, miner_tx, block_instance.mirror_hash)


def transaction_validate(node: "Node", tx: TransactionLegacy):
    """Validates all transaction elements. Raise a ValueError exception on error."""

    # Begin with costless checks first, so we can early exit. Time of tx
    if tx.start_time_tx < tx.q_received_timestamp:
        raise ValueError(f"Future transaction not allowed, timestamp "
                         f"{quantize_two((tx.q_received_timestamp - tx.start_time_tx) / 60)} minutes in the future")
    if node.last_block_timestamp - 86400 > tx.q_received_timestamp:
        raise ValueError("Transaction older than 24h not allowed.")
    # Amount
    if float(tx.received_amount) < 0:
        raise ValueError("Negative balance spend attempt")
    # Addresses validity
    if not address_validate(tx.received_address):
        raise ValueError("Not a valid sender address")
    if not address_validate(tx.received_recipient):
        raise ValueError("Not a valid recipient address")

    # Now we can process cpu heavier checks, decode and check sig itself
    buffer = str((tx.received_timestamp, tx.received_address, tx.received_recipient, tx.received_amount,
                  tx.received_operation, tx.received_openfield)).encode("utf-8")

    # EGG_EVO: Temp coherence control for db V2
    buffer2 = Transaction.from_legacy_params(timestamp=float(tx.received_timestamp),
                                             address=tx.received_address,
                                             recipient=tx.received_recipient,
                                             amount = tx.received_amount,
                                             operation=tx.received_operation,
                                             openfield=tx.received_openfield
                                             ).to_buffer_for_signing()
    if buffer != buffer2:
        node.logger.digest_log.error("Buffer mismatch")
        print(buffer)
        print(buffer2)
        sys.exit()
    # Will raise if error - also includes reconstruction of address from pubkey to make sure it matches
    SignerFactory.verify_bis_signature(tx.received_signature_enc, tx.received_public_key_b64encoded, buffer,
                                       tx.received_address)
    node.logger.digest_log.debug(f"Valid signature from {tx.received_address} "
                             f"to {tx.received_recipient} amount {tx.received_amount}")


def sort_transactions(block: list, tx: TransactionLegacy, block_instance: Block, miner_tx: MinerTransactionLegacy, node: "Node"):
    """
    Sanitizes transactions inside a block,
    checks whether coinbase transaction sends 0,
    defines coinbase transaction,
    appends transaction to a list of sanitized transactions (sanitized block)
    """

    for tx_index, transaction in enumerate(block):
        # print("tx_index", tx_index)
        tx.start_time_tx = quantize_two(ttime())
        tx.q_received_timestamp = quantize_two(transaction[0])
        tx.received_timestamp = '%.2f' % tx.q_received_timestamp
        tx.received_address = str(transaction[1])[:56]
        tx.received_recipient = str(transaction[2])[:56]
        tx.received_amount = '%.8f' % (quantize_eight(transaction[3]))
        tx.received_signature_enc = str(transaction[4])[:684]
        tx.received_public_key_b64encoded = str(transaction[5])[:1068]
        tx.received_operation = str(transaction[6])[:30]
        tx.received_openfield = str(transaction[7])[:100000]

        if tx.received_operation in ["token:issue", "token:transfer"]:
            block_instance.tokens_operation_present = True  # update on change

        # if transaction == block[-1]:
        if tx_index == block_instance.tx_count - 1:  # faster than comparing the whole tx
            if float(tx.received_amount) != 0:
                raise ValueError("Coinbase (Mining) transaction must have zero amount")
            if not address_is_rsa(tx.received_address):
                # Compare address rather than sig, as sig could be made up
                raise ValueError("Coinbase (Mining) transaction only supports legacy RSA Bismuth addresses")

            # recognize the last transaction as the mining reward transaction
            miner_tx.q_block_timestamp = tx.q_received_timestamp
            miner_tx.nonce = tx.received_openfield[:128]
            miner_tx.miner_address = tx.received_address
            # print("miner_tx1", miner_tx)

        block_instance.transaction_list_converted.append((tx.received_timestamp,
                                           tx.received_address,
                                           tx.received_recipient,
                                           tx.received_amount,
                                           tx.received_signature_enc,
                                           tx.received_public_key_b64encoded,
                                           tx.received_operation,
                                           tx.received_openfield))
        transaction_validate(node=node, tx=tx)


def process_transactions(node: "Node", db_handler: "DbHandler", block: list, block_instance: Block, miner_tx: MinerTransactionLegacy, block_transactions: list):
    """
    Checks transaction age and rejects it if it's too old,
    sanitizes transaction (again, needlessly, it was done in sort_transactions()),
    fee calculation with regards to the rest of the block,
    decides reward,
    appends to block_transactions variable (again, because checks are not in one place)
    """

    try:
        fees_block = []
        block_instance.mining_reward = 0  # avoid warning

        # Cache for multiple tx from same address
        balances = {}

        # TODO: remove condition after HF
        if block_instance.block_height_new >= 1450000:
            oldest_possible_tx = miner_tx.q_block_timestamp - 60 * 60 * 2
        else:
            # Was 24 h before
            oldest_possible_tx = miner_tx.q_block_timestamp - 60 * 60 * 24

        for tx_index, transaction in enumerate(block):

            if float(transaction[0]) < oldest_possible_tx:
                raise ValueError("txid {} from {} is older ({}) than oldest possible date ({})"
                                 .format(transaction[4][:56], transaction[1], transaction[0], oldest_possible_tx))

            db_timestamp = '%.2f' % quantize_two(transaction[0])
            db_address = str(transaction[1])[:56]
            db_recipient = str(transaction[2])[:56]
            db_amount = '%.8f' % quantize_eight(transaction[3])
            db_signature = str(transaction[4])[:684]
            db_public_key_b64encoded = str(transaction[5])[:1068]
            db_operation = str(transaction[6])[:30]
            db_openfield = str(transaction[7])[:100000]

            block_debit_address = 0
            block_fees_address = 0

            # this also is redundant on many tx per address block
            for x in block:
                if x[1] == db_address:  # make calculation relevant to a particular address in the block
                    block_debit_address = quantize_eight(Decimal(block_debit_address) + Decimal(x[3]))

                    if x != block[-1]:
                        block_fees_address = quantize_eight(Decimal(block_fees_address) + Decimal(
                            fee_calculate(db_openfield, db_operation,
                                          node.last_block)))  # exclude the mining tx from fees

            # decide reward
            if tx_index == block_instance.tx_count - 1:
                db_amount = 0  # prevent spending from another address, because mining txs allow delegation

                if node.is_testnet and node.last_block >= fork.POW_FORK_TESTNET:
                    block_instance.mining_reward = 15 - (block_instance.block_height_new - fork.POW_FORK_TESTNET) \
                                                   / 1100000 - 9.5
                elif node.is_mainnet and node.last_block >= fork.POW_FORK:
                    block_instance.mining_reward = 15 - (block_instance.block_height_new - fork.POW_FORK) / 1100000 - 9.5
                else:
                    block_instance.mining_reward = 15 - (quantize_eight(block_instance.block_height_new)
                                                         / quantize_eight(1000000 / 2)) - Decimal("2.4")

                if block_instance.mining_reward < 0.5:
                    block_instance.mining_reward = 0.5

                reward = '{:.8f}'.format(Decimal(block_instance.mining_reward) + sum(fees_block))

                # don't request a fee for mined block so new accounts can mine
                fee = 0
            else:
                reward = 0
                fee = fee_calculate(db_openfield, db_operation, node.last_block)
                fees_block.append(quantize_eight(fee))
                balance_pre = db_handler.ledger_balance3(db_address, balances)
                balance = quantize_eight(balance_pre - block_debit_address)

                if quantize_eight(balance_pre) < quantize_eight(db_amount):
                    raise ValueError(f"{db_address} sending more than owned: {db_amount}/{balance_pre}")

                if quantize_eight(balance) - quantize_eight(block_fees_address) < 0:
                    # exclude fee check for the mining/header tx
                    raise ValueError(f"{db_address} Cannot afford to pay fees (balance: {balance}, "
                                     f"block fees: {block_fees_address})")

            # append, but do not insert to ledger before whole block is validated,
            # note that it takes already validated values (decimals, length)
            node.logger.digest_log.info(f"Chain: Appending transaction back to block with "
                                        f"{len(block_transactions)} transactions in it")
            block_transactions.append((str(block_instance.block_height_new), str(db_timestamp), str(db_address),
                                       str(db_recipient), str(db_amount), str(db_signature),
                                       str(db_public_key_b64encoded), str(block_instance.block_hash), str(fee),
                                       str(reward), str(db_operation), str(db_openfield)))
            try:
                mp.MEMPOOL.delete_transaction(db_signature)
                node.logger.mempool_log.debug(f"Chain: Removed processed transaction {db_signature[:56]} "
                                          f"from the mempool while digesting")
            except:
                # tx was not or is no more in the local mempool
                pass

    except Exception as e:
        print("process_transactions: {}".format(e))
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        raise


def check_signature_on_block(block, node: "Node", db_handler: "DbHandler", peer_ip: str, block_instance):
    """
    Checks signature presence in the chain, raises an error if it is already present so it is not included twice
    """
    # TODO EGG: benchmark this loop vs a single "WHERE IN" SQL
    signature_list = []

    for entry in block:  # sig 4

        entry_signature = entry[4]
        if entry_signature:  # prevent empty signature database retry hack
            signature_list.append(entry_signature)
            # reject block with transactions which are already in the ledger ram
            if node.config.old_sqlite:
                db_handler._execute_param(db_handler.h, "SELECT block_height FROM transactions WHERE signature = ?1;",
                                          (entry_signature,))
            else:
                db_handler._execute_param(db_handler.h,
                                          "SELECT block_height FROM transactions WHERE substr(signature,1,4) = substr(?1,1,4) and signature = ?1;",
                                          (entry_signature,))

            tx_presence_check = db_handler.h.fetchone()
            if tx_presence_check:
                # print(node.last_block)
                raise ValueError(f"That transaction {entry_signature[:10]} is already in our ledger, "
                                 f"block_height {tx_presence_check[0]}")
            if node.config.old_sqlite:
                db_handler._execute_param(db_handler.c, "SELECT block_height FROM transactions WHERE signature = ?1;",
                                          (entry_signature,))
            else:
                db_handler._execute_param(db_handler.c,
                                          "SELECT block_height FROM transactions WHERE substr(signature,1,4) = substr(?1,1,4) and signature = ?1;",
                                          (entry_signature,))
            tx_presence_check = db_handler.c.fetchone()
            if tx_presence_check:
                # print(node.last_block)
                raise ValueError(f"That transaction {entry_signature[:10]} is already in our RAM ledger, "
                                 f"block_height {tx_presence_check[0]}")
        else:
            raise ValueError(f"Empty signature from {peer_ip}")

    if block_instance.tx_count != len(set(signature_list)):
        raise ValueError("There are duplicate transactions in this block, rejected")


def process_blocks(blocks: list, node: "Node", db_handler: "DbHandler", block_instance: Block, peer_ip: str):
    """blocks is a list of legacy unstructure tx, with floats and no bin."""
    """
    Checks age of the block and whether it is newer than the most recent one saved
    For every block in a block array, increases node.last_block, runs check_signature_on_block
    Updates node.difficulty
    Calculates block_hash, checks block_hash presence in the blockchain
    Runs process_transactions (necessary?)
    Updates both node.last_block and node.last_block_hash
    Calculates mirror hash
    Runs rewards()
    Updates tokens if update var triggered
    Updates node.difficulty and returns it
    """
    tx = TransactionLegacy()
    miner_tx = MinerTransactionLegacy()
    block_transactions = []
    try:
        block_instance.block_count = len(blocks)

        for block in blocks:  # "blocks" is either one block in a list or a list of blocks
            if node.IS_STOPPING:
                node.logger.app_log.warning("Process_blocks aborted, node is stopping")
                return
            # Reworked process: we exit as soon as we find an error, no need to process further tests.
            # Then the exception handler takes place.
            # EGG: Reminder: quick test first, **always**. Heavy tests only thereafter.

            # Here, block_instance seems relative to a single block
            block_instance.tx_count = len(block)

            for transaction in block:
                # but here, block_instance gets all tx from all the blocks...
                block_instance.transactions.append(Transaction.from_legacy_params(
                    timestamp=transaction[0],
                    address=transaction[1],
                    recipient=transaction[2],
                    amount=transaction[3],
                    signature=transaction[4],
                    public_key=transaction[5],
                    operation=transaction[6],
                    openfield=transaction[7]
                    ))

            block_instance.block_height_new = node.last_block + 1
            block_instance.start_time_block = ttime()

            fork_reward_check(node=node, db_handler=db_handler)  # This raises on rollback

            # sort_transactions also computes several hidden variables, like miner_tx.q_block_timestamp
            # So it has to be run before the check
            # TODO: rework to avoid hidden variables and make the sequence clear.
            # sort_transactions also validates all transactions and sigs,
            # and this is a waste of time if the block timestamp is wrong.

            sort_transactions(block=block, tx=tx, block_instance=block_instance, miner_tx=miner_tx, node=node)

            # reject blocks older than latest block
            if miner_tx.q_block_timestamp <= node.last_block_timestamp:
                # print("miner_tx2", miner_tx)
                raise ValueError(f"!Block is older {miner_tx.q_block_timestamp} "
                                 f"than the previous one {node.last_block_timestamp} , will be rejected")

            check_signature_on_block(block=block, node=node, db_handler=db_handler, peer_ip=peer_ip, block_instance=block_instance)

            # calculate current difficulty (is done for each block in block array, not super easy to isolate)
            diff = difficulty(node, db_handler)
            # print("difficulty 1", diff)
            # sleep(1)
            node.difficulty = diff

            node.logger.status_log.info(f"Time to generate block {node.last_block + 1}: {diff[2]:0.2f}s "
                                        f"- Blocktime {diff[4]:0.2f}s - Hashrate {(diff[5]/1e12):0.2f} TH/s ")
            node.logger.status_log.info(f"Current diff {diff[3]:0.2f} - New diff  {diff[0]:0.2f} {diff[1]:0.2f}")
            node.logger.status_log.debug(f"Current diff {diff[3]} - New diff  {diff[0]} {diff[1]} - Adj {diff[6]}")

            block_instance.block_hash = hashlib.sha224((str(block_instance.transaction_list_converted)
                                                        + node.last_block_hash).encode("utf-8")).hexdigest()
            del block_instance.transaction_list_converted[:]

            node.logger.digest_log.debug(f"Calculated block sha_hash: {block_instance.block_hash}")
            # node.logger.digest_log.info("Nonce: {}".format(nonce))

            # check if we already have the sha_hash
            dummy = db_handler.block_height_from_hash(block_instance.block_hash)

            # db_handler._execute_param(db_handler.h,
            # "SELECT block_height FROM transactions WHERE block_hash = ?", (block_instance.block_hash,))
            # dummy = db_handler.h.fetchone()

            if dummy:
                raise ValueError(
                    "Skipping digestion of block {} from {}, because we already have it on block_height {}"
                        .format(block_instance.block_hash[:10], peer_ip, dummy[0]))

            if node.is_mainnet:
                diff_save = mining_heavy3.check_block(block_instance.block_height_new,
                                                      miner_tx.miner_address,
                                                      miner_tx.nonce,
                                                      node.last_block_hash,
                                                      diff[0],
                                                      tx.received_timestamp,
                                                      tx.q_received_timestamp,
                                                      node.last_block_timestamp,
                                                      peer_ip=peer_ip,
                                                      app_log=node.logger.digest_log)
            elif node.is_testnet:
                diff_save = mining_heavy3.check_block(block_instance.block_height_new,
                                                      miner_tx.miner_address,
                                                      miner_tx.nonce,
                                                      node.last_block_hash,
                                                      diff[0],
                                                      tx.received_timestamp,
                                                      tx.q_received_timestamp,
                                                      node.last_block_timestamp,
                                                      peer_ip=peer_ip,
                                                      app_log=node.logger.digest_log)
            else:
                # it's regnet then, will use a specific fake method here.
                diff_save = mining_heavy3.check_block(block_instance.block_height_new,
                                                      miner_tx.miner_address,
                                                      miner_tx.nonce,
                                                      node.last_block_hash,
                                                      regnet.REGNET_DIFF,
                                                      tx.received_timestamp,
                                                      tx.q_received_timestamp,
                                                      node.last_block_timestamp,
                                                      peer_ip=peer_ip,
                                                      app_log=node.logger.digest_log)

            process_transactions(node=node, db_handler=db_handler, block=block, block_instance=block_instance,
                                 miner_tx=miner_tx, block_transactions=block_transactions)

            node.last_block = block_instance.block_height_new
            node.last_block_hash = block_instance.block_hash
            # end for block

            # save current diff (before the new block)

            # quantized vars have to be converted, since Decimal is not json serializable...
            node.plugin_manager.execute_action_hook('block',
                                                    {'height': block_instance.block_height_new,
                                                     'diff': diff_save,
                                                     'hash': block_instance.block_hash,
                                                     'timestamp': float(miner_tx.q_block_timestamp),
                                                     'miner': miner_tx.miner_address,
                                                     'ip': peer_ip})

            node.plugin_manager.execute_action_hook('fullblock',
                                                    {'height': block_instance.block_height_new,
                                                     'diff': diff_save,
                                                     'hash': block_instance.block_hash,
                                                     'timestamp': float(miner_tx.q_block_timestamp),
                                                     'miner': miner_tx.miner_address,
                                                     'ip': peer_ip,
                                                     'transactions': block_transactions})

            db_handler.to_db(block_instance, diff_save, block_transactions)
            # In regtest mode, at least, this saves the generated block to the regmod.db.

            if block_instance.block_height_new % 10 == 0:
                # new mirror sha_hash - only calc when needed, not every block
                db_handler._execute(db_handler.c, "SELECT * FROM transactions "
                                                  "WHERE block_height = (SELECT max(block_height) FROM transactions)")
                # Was trying to simplify, but it's the latest mirror sha_hash.
                # not the latest block, nor the mirror of the latest block.
                # c._execute("SELECT * FROM transactions WHERE block_height = ?", (block_instance.block_height_new -1,))
                tx_list_to_hash = db_handler.c.fetchall()
                # TODO EGG_EVO: This is a mistake. Uses a specific low level and proprietary encoding format (str of a tuple from a db with non specified numeric format)
                # To Simplify. Like, only hash the - bin - tx signatures, ensures untamper just the same, faster and no question on the format.
                # Since mirror hash are not part of consensus, no incidence.
                block_instance.mirror_hash = hashlib.blake2b(str(tx_list_to_hash).encode(), digest_size=20).hexdigest()
                # /new mirror sha_hash
                rewards(node=node, block_instance=block_instance, db_handler=db_handler, miner_tx=miner_tx)

            # node.logger.app_log.warning("Block: {}: {} valid and saved from {}"
            # .format(block_instance.block_height_new, block_hash[:10], peer_ip))
            node.logger.digest_log.info(f"Valid block: {block_instance.block_height_new}: "
                                        f"{block_instance.block_hash[:10]} with {len(block)} txs, "
                                        f"digestion from {peer_ip} completed in "
                                        f"{(ttime() - block_instance.start_time_block):0.2f}s.")

            if block_instance.tokens_operation_present:
                db_handler.tokens_update()

            del block_transactions[:]
            node.peers.unban(peer_ip)

            # This new block may change the int(diff). Trigger the hook whether it changed or not.
            diff = difficulty(node, db_handler)
            # print("difficulty 2 ", diff)
            # sleep(1)
            node.difficulty = diff
            node.plugin_manager.execute_action_hook('diff', diff[0])
            # We could recalc diff after inserting block, and then only trigger the block hook,
            # but I fear this would delay the new block event.

            # /whole block validation
            # NEW: returns new block sha_hash
    except Exception as e:
        # Left for edge cases debug
        print("process_blocks: {}".format(e))
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        raise


def digest_block(node: "Node", block_data: list, sdef, peer_ip: str, db_handler: "DbHandler"):
    """This function is the only one to be exported from this module.
    It's mostly a wrapper around the actual block digestion.
    block_data is legacy unstructured data, with floats and no bin.
    block_data may contain more than one block.
    """
    if not node.config.legacy_db:
        raise ValueError("V2 DB but calling digest_block!!")
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
    if node.peers.is_banned(peer_ip):
        # no need to loose any time with banned peers
        raise ValueError("Cannot accept blocks from a banned peer")
        # since we raise, it will also drop the connection, it's fine since he's banned.

    block_instance = Block()
    block_instance.block_height_new = node.last_block + 1

    if not node.db_lock.locked():

        node.db_lock.acquire()
        node.logger.app_log.debug(f"Database lock acquired")

        while mp.MEMPOOL.lock.locked():
            sleep(0.1)
            node.logger.app_log.info(f"Chain: Waiting for mempool to unlock {peer_ip}")

        block_size = len(str(block_data)) / 1000000
        node.logger.digest_log.info(f"Chain: Digesting started from {peer_ip} - {len(block_data)} Blocks - {block_size} MB")

        try:
            # print(block_data)  # Temp debug
            process_blocks(blocks=block_data, node=node, db_handler=db_handler, block_instance=block_instance,
                          peer_ip=peer_ip)
            # This saves the block to the db when in regnet mode. what in other modes?

            node.checkpoint_set()
            return node.last_block_hash

        except Exception as e:
            node.logger.digest_log.warning(f"Chain processing failed: {e}")
            node.logger.digest_log.debug(f"Received data dump: {block_data}")
            block_instance.failed_cause = str(e)
            # get actual data from database on exception
            node.last_block = db_handler.last_mining_transaction().to_dict(legacy=True)['block_height']
            node.last_block_hash = db_handler.last_block_hash()

            # Temp
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

            if node.peers.warning(sdef, peer_ip, "Rejected block", 2):
                raise ValueError(f"{peer_ip} banned")
            raise ValueError("Chain: digestion aborted")

        finally:
            # in regnet, this copies again the last block...
            db_handler.db_to_drive(node)

            node.db_lock.release()
            node.logger.app_log.debug(f"Database lock released")

            delta_t = ttime() - block_instance.start_time_block
            # node.logger.app_log.warning("Block: {}: {} digestion completed in {}s."
            # .format(block_instance.block_height_new,  block_hash[:10], delta_t))
            node.plugin_manager.execute_action_hook('digestblock',
                                                    {'failed': block_instance.failed_cause,
                                                     'ip': peer_ip,
                                                     'deltat': delta_t,
                                                     "blocks": block_instance.block_count,
                                                     "txs": block_instance.tx_count})

    else:
        node.logger.digest_log.warning(f"Chain: Skipping processing from {peer_ip}, someone delivered data faster")
        node.plugin_manager.execute_action_hook('digestblock', {'failed': "skipped", 'ip': peer_ip})
