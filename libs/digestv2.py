"""
Exports digest_block, the main block digesting function.
def digest_block(node: "Node", data, sdef, peer_ip: str, db_handler: "DbHandler")

EGG_EVO: This is a WIP.
"""

import hashlib
import os
import sys
from time import time as ttime, sleep
from typing import TYPE_CHECKING

from bismuthcore.block import Block
from bismuthcore.blocks import Blocks
from bismuthcore.compat import quantize_two
from bismuthcore.helpers import fee_calculate_int
from bismuthcore.transaction import Transaction
from libs import mempool as mp, mining_heavy3, regnet
from libs.difficulty import difficulty
from libs.fork import Fork

# from bismuthcore.transactionslist import TransactionsList
# from libs.essentials import address_validate, address_is_rsa
# from polysign.signerfactory import SignerFactory
# from decimal import Decimal

K1E8 = 100000000

if TYPE_CHECKING:
    from libs.node import Node  # for type hinting
    from libs.dbhandler import DbHandler

fork = Fork()


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


def rewards(node: "Node", block: Block, mirror_hash: bytes, db_handler: "DbHandler"):
    """Checks whether reward conditions apply, development rewards and hn contract rewards"""
    if block.height % 10 == 0:  # every 10 blocks
        # miner_tx is only needed for the block timestamp
        db_handler.dev_reward_v2(node, block, mirror_hash)
        db_handler.hn_reward_v2(node, block, mirror_hash)


def process_transactions(node: "Node", db_handler: "DbHandler", block: Block):
    """
    Checks transaction age and rejects it if it's too old,
    sanitizes transaction (again, needlessly, it was done in sort_transactions()),
    fee calculation with regards to the rest of the block,
    decides reward,
    appends to block_transactions variable (again, because checks are not in one place)
    """

    try:
        fees_block = []
        # Cache for multiple tx from same address
        balances = {}

        # TODO: remove condition after HF
        if block.height >= 1450000:
            oldest_possible_tx = block.miner_tx.timestamp - 60 * 60 * 2
        else:
            # Was 24 h before
            oldest_possible_tx = block.miner_tx.timestamp - 60 * 60 * 24

        for tx_index, transaction in enumerate(block.transactions):
            if transaction.timestamp < oldest_possible_tx:
                raise ValueError("txid {} from {} is older ({}) than oldest possible date ({})"
                                 .format(transaction.signature[:56], transaction.address,
                                         transaction.timestamp, oldest_possible_tx))

            block_debit_address = 0
            block_fees_address = 0

            # this also is redundant on many tx per address block
            for x in block.transactions:
                if x.address == transaction.address:  # make calculation relevant to a particular address in the block
                    block_debit_address = block_debit_address + x.amount

                    if x != block.transactions[-1]:
                        block_fees_address += fee_calculate_int(x.openfield,  x.operation, node.last_block)
                        # exclude the mining tx from fees

            # node.logger.app_log.info("Fee: " + str(fee))

            # decide reward
            if tx_index == len(block.transactions) - 1:
                transaction.amount = 0
                # db_amount: int = 0  # prevent spending from another address, because mining txs allow delegation
                # TODO benchmark: significant perf gain by using more constants?
                # TODO: This is "Block" relative. Should this be moved over to BismuthCore? What about forks?
                if node.is_testnet and node.last_block >= fork.POW_FORK_TESTNET:
                    mining_reward = 15 * K1E8 * 1100000 - (block.height - fork.POW_FORK_TESTNET) * K1E8 \
                                    - int(9.5 * K1E8 * 1100000)
                elif node.is_mainnet and node.last_block >= fork.POW_FORK:
                    mining_reward = 15 * K1E8 * 1100000 - (block.height - fork.POW_FORK) * K1E8 \
                                    - int(9.5 * K1E8 * 1100000)
                else:
                    mining_reward = 15 * K1E8 * 1100000 - block.height * K1E8 * 1100000 // (1000000 // 2) \
                                    - int(2.4 * K1E8 * 1100000)

                mining_reward = round(mining_reward / 1100000)

                if mining_reward < K1E8 // 2:  # 0.5 * K1E8:
                    mining_reward = K1E8 // 2

                block.mining_reward = mining_reward  # This is needed for dev funds mirror blocks
                reward = mining_reward + sum(fees_block)
                # Reward is not sent with data, just update
                block.set_reward(reward)
                # don't request a fee for mined block so new accounts can mine
                transaction.fee = 0
            else:
                fee = fee_calculate_int(transaction.openfield, transaction.operation, node.last_block)
                if fee != transaction.fee:
                    node.logger.digest_log.debug(f"{block.height}:{transaction.address} Tx fee do not match calc: "
                                                 f"{Transaction.int_to_f8(transaction.fee)}/"
                                                 f"{Transaction.int_to_f8(fee)}")
                    transaction.fee = fee
                    # raise ValueError("TempRE1")

                    # Fee is not part of signature
                fees_block.append(fee)
                balance_pre = db_handler.ledger_balance3_int(transaction.address, balances)
                balance = balance_pre - block_debit_address

                if balance_pre < transaction.amount:
                    raise ValueError(f"{transaction.address} sending more than owned: "
                                     f"{Transaction.int_to_f8(transaction.amount)}"
                                     f"/{Transaction.int_to_f8(balance_pre)}")

                if balance < block_fees_address:
                    # exclude fee check for the mining/header tx
                    raise ValueError(f"{transaction.address} Cannot afford to pay fees "
                                     f"(balance: {Transaction.int_to_f8(balance)}, "
                                     f"block fees: {Transaction.int_to_f8(block_fees_address)})")

            # append, but do not insert to ledger before whole block is validated,
            # note that it takes already validated values (decimals, length)
            """
            node.logger.digest_log.info(f"Chain: Appending transaction back to block with "
                                     f"{len(block_transactions)} transactions in it")
            block_transactions.append((str(block_instance.block_height_new), str(db_timestamp), str(db_address),
                                       str(db_recipient), str(db_amount), str(db_signature),
                                       str(db_public_key_b64encoded), str(block_instance.block_hash), str(fee),
                                       str(reward), str(db_operation), str(db_openfield)))
            """
            try:
                mp.MEMPOOL.delete_transaction(transaction.signature_encoded)
                node.logger.mempool_log.debug(f"Chain: Removed processed transaction "
                                              f"{transaction.signature_encoded[:56]} from the mempool while digesting")
            except Exception:
                # tx was not or is no more in the local mempool, not an issue.
                pass
        # No need to delete and re-insert. just update fee and reward

    except Exception as e:
        node.logger.digest_log.warning("Process_transactions: {}".format(e))
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
                db_handler._execute_param(db_handler.h, "SELECT block_height FROM transactions WHERE signature = ?1",
                                          (entry_signature, ))
            else:
                db_handler._execute_param(db_handler.h,
                                          "SELECT block_height FROM transactions "
                                          "WHERE substr(signature,1,4) = substr(?1,1,4) and signature = ?1",
                                          (entry_signature, ))

            tx_presence_check = db_handler.h.fetchone()
            if tx_presence_check:
                # print(node.last_block)
                raise ValueError(f"That transaction {entry_signature[:10]} is already in our ledger, "
                                 f"block_height {tx_presence_check[0]}")
            if node.config.old_sqlite:
                db_handler._execute_param(db_handler.c, "SELECT block_height FROM transactions WHERE signature = ?1",
                                          (entry_signature, ))
            else:
                db_handler._execute_param(db_handler.c,
                                          "SELECT block_height FROM transactions "
                                          "WHERE substr(signature,1,4) = substr(?1,1,4) and signature = ?1",
                                          (entry_signature, ))
            tx_presence_check = db_handler.c.fetchone()
            if tx_presence_check:
                # print(node.last_block)
                raise ValueError(f"That transaction {entry_signature[:10]} is already in our RAM ledger, "
                                 f"block_height {tx_presence_check[0]}")
        else:
            raise ValueError(f"Empty signature from {peer_ip}")

    if block_instance.tx_count != len(set(signature_list)):
        raise ValueError("There are duplicate transactions in this block, rejected")


def process_blocks(blocks: Blocks, node: "Node", db_handler: "DbHandler", peer_ip: str):
    """blocks is now a list of "Block objects"""
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
    # tx = TransactionLegacy()
    # miner_tx = MinerTransactionLegacy()
    # block_transactions = []
    # tx_count = 0
    try:
        fork_reward_check(node=node, db_handler=db_handler)  # This raises on rollback
        # makes sure post fork reward is ok. Likely unnecessary atm: means we add a query for all blocks, every time.
        # Should only be done once at node start.
        # TODO: recheck and move to solo mode.

        # block_count = len(blocks.blocks)
        # Mid and heavy checks, one by one
        for block in blocks.blocks:  # "blocks" is either one block in a list or a list of blocks
            if node.IS_STOPPING:
                node.logger.app_log.warning("Process_blocks aborted, node is stopping", exc_info=node.config.debug)
                return
            # Reworked process: we exit as soon as we find an error, no need to process further tests.
            # Then the exception handler takes place.
            # EGG: Reminder: quick test first, **always**. Heavy tests only thereafter.

            block_height_new = node.last_block + 1
            block.set_height(block_height_new)
            start_time_block = ttime()

            block.validate_mid()
            block.validate_heavy()

            # calculate current difficulty (is done for each block in block array, not super easy to isolate)
            diff = difficulty(node, db_handler)
            # print("difficulty 1", diff)
            # sleep(1)
            node.difficulty = diff

            node.logger.status_log.info(f"Time to generate block {node.last_block + 1}: {diff[2]:0.2f}s "
                                        f"- Blocktime {diff[4]:0.2f}s - Hashrate {(diff[5]/1e12):0.2f} TH/s ")
            node.logger.status_log.info(f"Current diff {diff[3]:0.2f} - New diff  {diff[0]:0.2f} {diff[1]:0.2f}")
            node.logger.status_log.debug(f"Current diff {diff[3]} - New diff  {diff[0]} {diff[1]} - Adj {diff[6]}")

            block_hash_bin = hashlib.sha224((str(block.tx_list_for_hash())
                                             + node.last_block_hash).encode("utf-8")).digest()
            block_hash = block_hash_bin.hex()
            # del block_instance.transaction_list_converted[:]

            # node.logger.app_log.info("Last block sha_hash: {}".format(block_hash))
            node.logger.digest_log.info(f"Calculated block sha_hash for expected {block_height_new} "
                                        f"with {len(block.transactions)} tx: {block_hash}")
            # node.logger.app_log.info("Nonce: {}".format(nonce))

            # check if we already have that sha_hash
            dummy = db_handler.block_height_from_binhash(block_hash_bin)

            # db_handler._execute_param(db_handler.h,
            # "SELECT block_height FROM transactions WHERE block_hash = ?", (block_instance.block_hash,))
            # dummy = db_handler.h.fetchone()

            if dummy:
                raise ValueError(
                    f"Skipping digestion of block {block_hash.hex()[:10]} from {peer_ip}, "
                    f"because we already have it on block_height {dummy[0]}")

            if node.is_mainnet:
                diff_save = mining_heavy3.check_block(block_height_new,
                                                      block.miner_tx.address,
                                                      block.miner_tx.openfield,
                                                      node.last_block_hash,
                                                      diff[0],
                                                      block.miner_tx.timestamp,
                                                      quantize_two(block.miner_tx.timestamp),
                                                      node.last_block_timestamp,
                                                      peer_ip=peer_ip,
                                                      app_log=node.logger.digest_log)
            elif node.is_testnet:
                diff_save = mining_heavy3.check_block(block_height_new,
                                                      block.miner_tx.address,
                                                      block.miner_tx.openfield,
                                                      node.last_block_hash,
                                                      diff[0],
                                                      block.miner_tx.timestamp,
                                                      quantize_two(block.miner_tx.timestamp),
                                                      node.last_block_timestamp,
                                                      peer_ip=peer_ip,
                                                      app_log=node.logger.digest_log)
            else:
                # it's regnet then, will use a specific fake method here.
                diff_save = mining_heavy3.check_block(block_height_new,
                                                      block.miner_tx.address,
                                                      block.miner_tx.openfield,
                                                      node.last_block_hash,
                                                      regnet.REGNET_DIFF,
                                                      block.miner_tx.timestamp,
                                                      quantize_two(block.miner_tx.timestamp),
                                                      node.last_block_timestamp,
                                                      peer_ip=peer_ip,
                                                      app_log=node.logger.digest_log)

            process_transactions(node=node, db_handler=db_handler, block=block)

            node.last_block = block_height_new
            node.last_block_hash = block_hash
            # end for block

            # At that point, block is valid and will be saved. set its hash in all transactions before saving
            block.set_hash(block_hash_bin)

            # save current diff (before the new block)

            # quantized vars have to be converted, since Decimal is not json serializable...
            node.plugin_manager.execute_action_hook('block',
                                                    {'height': block_height_new,
                                                     'diff': diff_save,
                                                     'hash': block_hash,
                                                     'timestamp': block.miner_tx.timestamp,
                                                     'miner': block.miner_tx.address,
                                                     'ip': peer_ip})

            # TODO: add fullblockv2 so we can avoid one more convert if no hook is bound to this call.
            node.plugin_manager.execute_action_hook('fullblock',
                                                    {'height': block_height_new,
                                                     'diff': diff_save,
                                                     'hash': block_hash,
                                                     'timestamp': block.miner_tx.timestamp,
                                                     'miner': block.miner_tx.address,
                                                     'ip': peer_ip,
                                                     'transactions': [transaction.to_tuple()
                                                                      for transaction in block.transactions]})

            db_handler.to_db_v2(block, diff_save)
            # In regtest mode, at least, this saves the generated block to the regmod.db.

            if block_height_new % 10 == 0:  # every 10 blocks
                # new mirror sha_hash
                db_handler._execute(db_handler.c, "SELECT * FROM transactions "
                                                  "WHERE block_height = (SELECT max(block_height) FROM transactions)")
                # Was trying to simplify, but it's the latest mirror sha_hash.
                # not the latest block, nor the mirror of the latest block.
                # c._execute("SELECT * FROM transactions WHERE block_height = ?", (block_instance.block_height_new -1,))
                tx_list_to_hash = db_handler.c.fetchall()
                # TODO EGG_EVO: This is a mistake. Uses a specific low level and proprietary encoding format
                # (str of a tuple from a db with non specified numeric format)
                # To Simplify. Like, only hash the - bin - tx signatures or just block hash
                # that already is a hash of tx list, ensures untamper just the same,
                # faster and no question on the format.
                # Since mirror hash are not part of consensus, no incidence.
                # /new mirror sha_hash
                mirror_hash = hashlib.blake2b(str(tx_list_to_hash).encode(), digest_size=20).digest()
                # Is that used somewhere or just recorded??
                rewards(node=node, block=block, mirror_hash=mirror_hash, db_handler=db_handler)

            # node.logger.app_log.warning("Block: {}: {} valid and saved from {}"
            # .format(block_instance.block_height_new, block_hash[:10], peer_ip))
            node.logger.digest_log.info(f"Valid block: {block_height_new}: "
                                        f"{block_hash[:10]} with {len(block.transactions)} txs, "
                                        f"digestion from {peer_ip} completed in "
                                        f"{(ttime() - start_time_block):0.2f}s.")

            if block.tokens_operation_present:
                db_handler.tokens_update()

            # accepted block, reset ban on that peer
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
    except Exception as e:
        # Left for edge cases debug
        node.logger.digest_log.warning("process_blocks (v2): {}".format(e), exc_info=1)
        raise


def digest_block_v2(node: "Node", block_data: list, sdef, peer_ip: str, db_handler: "DbHandler"):
    """This function is the only one to be exported from this module.
    It's mostly a wrapper around the actual block digestion.
    block_data is legacy unstructured data, with floats and no bin.
    block_data may contain more than one block.
    """
    if node.IS_STOPPING:
        node.logger.app_log.warning("digest_block_v2 aborted, node is stopping", exc_info=node.config.debug)
        return
    if node.config.legacy_db:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        raise ValueError("Legacy DB but calling digest_block_v2!!")
    failed_cause = "N/A"
    start_time_block = ttime()
    if node.peers.is_banned(peer_ip):
        # no need to loose any time with banned peers
        raise ValueError("Cannot accept blocks from a banned peer")
        # since we raise, it will also drop the connection, it's fine since he's banned.
    if not node.db_lock.locked():
        node.db_lock.acquire()
        node.logger.app_log.debug(f"Database lock acquired")
        while mp.MEMPOOL.lock.locked():
            sleep(0.1)
            node.logger.digest_log.warning(f"Chain: Waiting for mempool to unlock {peer_ip}")
            # We wait for mempool to unlock, but don't lock it...
        block_size = len(str(block_data)) / 1000000
        node.logger.digest_log.info(f"Chain: Digesting started from {peer_ip} - "
                                    f"{len(block_data)} Blocks - {block_size} MB")
        blocks = None
        try:
            node.logger.app_log.info(f"Chain: Digesting V2")
            # raise ValueError("WIP")
            """
            with open("blocks.log", "a+") as fp:
                fp.write(f"{node.last_block + 1}\n")
                fp.write(str(block_data))
                fp.write("\n")
            # print(block_data)
            """
            blocks = Blocks.from_legacy_block_data(block_data, first_level_checks=True,
                                                   last_block_timestamp=node.last_block_timestamp)
            # actual block control and digestion takes place in there
            process_blocks(blocks, node=node, db_handler=db_handler, peer_ip=peer_ip)
            # This saves the block to the db when in regnet mode. what in other modes?
            node.checkpoint_set()  # sets node.checkpoint, no db interaction.
            node.logger.digest_log.info(f"Chain: Digesting from {peer_ip}")
            return node.last_block_hash
        except Exception as e:
            # get actual data from database on exception
            node.last_block = db_handler.last_mining_transaction().block_height
            node.last_block_hash = db_handler.last_block_hash()
            node.logger.digest_log.warning(f"Chain processing failed {node.last_block+1}: {e}")
            # node.logger.digest_log.info(f"Received data dump 0: {block_data[0]}")
            node.logger.digest_log.debug(f"Received data dump: {block_data}")
            failed_cause = str(e)
            """
            # Temp debug
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            """
            if node.peers.warning(sdef, peer_ip, "Rejected block", 2):
                raise ValueError(f"{peer_ip} banned")
            raise ValueError("Chain: digestion aborted")
        finally:
            # in regnet, this copies again the last block...
            db_handler.db_to_drive_v2(node)
            node.db_lock.release()
            node.logger.app_log.debug(f"Database lock released")
            delta_t = ttime() - start_time_block
            tx_count = blocks.tx_count if blocks is not None else 'N/A'
            node.plugin_manager.execute_action_hook('digestblock',
                                                    {'failed': failed_cause,
                                                     'ip': peer_ip,
                                                     'deltat': delta_t,
                                                     "blocks": len(block_data),
                                                     "txs": tx_count})
    else:
        node.logger.digest_log.warning(f"Chain: Skipping processing from {peer_ip}, someone delivered data faster")
        node.plugin_manager.execute_action_hook('digestblock', {'failed': "skipped", 'ip': peer_ip})
