import hashlib
import os
import sys

import essentials
import mempool as mp
import mining
import mining_heavy3
import staking
from difficulty import *
from essentials import address_is_rsa, checkpoint_set, ledger_balance3
from polysign.signerfactory import SignerFactory
from fork import Fork
import tokensv2 as tokens

fork = Fork()


def digest_block(node, data, sdef, peer_ip, db_handler):
    """node param for imports"""

    tokens_operation_present = False

    class Transaction:
        def __init__(self):
            self.start_time_tx = 0
            self.q_received_timestamp = 0
            self.received_timestamp = "0.00"
            self.received_address = None
            self.received_recipient = None
            self.received_amount = 0
            self.received_signature_enc = None
            self.received_public_key_b64encoded = None
            self.received_operation = None
            self.received_openfield = None

    class MinerTransaction:
        def __init__(self):
            self.q_block_timestamp = 0
            self.nonce = None
            self.miner_address = None

    class Block:
        """array of transactions within a block"""
        def __init__(self):
            self.tx_count = 0
            self.block_height_new = node.last_block + 1
            self.block_hash = 'N/A'
            self.failed_cause = ''
            self.block_count = 0
            self.transaction_list_converted = []

            self.mining_reward = None
            self.mirror_hash = None
            self.start_time_block = quantize_two(time.time())

    def fork_reward_check():
        # fork handling
        if node.is_testnet:
            if node.last_block > fork.POW_FORK_TESTNET:
                if not fork.check_postfork_reward_testnet(db_handler):
                    db_handler.rollback_under(fork.POW_FORK_TESTNET - 1)
                    raise ValueError("Rolling back chain due to old fork data")
        else:
            if node.last_block > fork.POW_FORK:
                if not fork.check_postfork_reward(db_handler):
                    print("Rolling back")
                    db_handler.rollback_under(fork.POW_FORK - 1)
                    raise ValueError("Rolling back chain due to old fork data")
        # fork handling

    def transaction_validate():
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
        if not essentials.address_validate(tx.received_address):
            raise ValueError("Not a valid sender address")
        if not essentials.address_validate(tx.received_recipient):
            raise ValueError("Not a valid recipient address")

        # Now we can process cpu heavier checks, decode and check sig itself
        buffer = str((tx.received_timestamp, tx.received_address, tx.received_recipient, tx.received_amount,
                      tx.received_operation, tx.received_openfield)).encode("utf-8")
        # Will raise if error - also includes reconstruction of address from pubkey to make sure it matches
        SignerFactory.verify_bis_signature(tx.received_signature_enc, tx.received_public_key_b64encoded, buffer,
                                           tx.received_address)
        node.logger.app_log.info(f"Valid signature from {tx.received_address} "
                                 f"to {tx.received_recipient} amount {tx.received_amount}")

    def rewards():
        if int(block_instance.block_height_new) % 10 == 0:  # every 10 blocks
            db_handler.dev_reward(node, block_instance, miner_tx, block_instance.mining_reward, block_instance.mirror_hash)
            db_handler.hn_reward(node,block_instance,miner_tx,block_instance.mirror_hash)

    def check_signature(block):
        # TODO EGG: benchmark this loop vs a single "WHERE IN" SQL
        for entry in block:  # sig 4
            block_instance.tx_count += 1
            entry_signature = entry[4]
            if entry_signature:  # prevent empty signature database retry hack
                signature_list.append(entry_signature)
                # reject block with transactions which are already in the ledger ram

                db_handler.execute_param(db_handler.h, "SELECT block_height FROM transactions WHERE signature = ?;",
                                         (entry_signature,))
                tx_presence_check = db_handler.h.fetchone()
                if tx_presence_check:
                    # print(node.last_block)
                    raise ValueError(f"That transaction {entry_signature[:10]} is already in our ledger, "
                                     f"block_height {tx_presence_check[0]}")

                db_handler.execute_param(db_handler.c, "SELECT block_height FROM transactions WHERE signature = ?;",
                                         (entry_signature,))
                tx_presence_check = db_handler.c.fetchone()
                if tx_presence_check:
                    # print(node.last_block)
                    raise ValueError(f"That transaction {entry_signature[:10]} is already in our RAM ledger, "
                                     f"block_height {tx_presence_check[0]}")
            else:
                raise ValueError(f"Empty signature from {peer_ip}")

    def sort_transactions(block):
        # print("sort_transactions")
        # print("block_instance.tx_count", block_instance.tx_count)
        for tx_index, transaction in enumerate(block):
            # print("tx_index", tx_index)
            tx.start_time_tx = quantize_two(time.time())
            tx.q_received_timestamp = quantize_two(transaction[0])
            tx.received_timestamp = '%.2f' % tx.q_received_timestamp
            tx.received_address = str(transaction[1])[:56]
            tx.received_recipient = str(transaction[2])[:56]
            tx.received_amount = '%.8f' % (quantize_eight(transaction[3]))
            tx.received_signature_enc = str(transaction[4])[:684]
            tx.received_public_key_b64encoded = str(transaction[5])[:1068]
            tx.received_operation = str(transaction[6])[:30]
            tx.received_openfield = str(transaction[7])[:100000]

            if tx.received_operation in ["token:issue","token:transfer"]:
                tokens_operation_present = True  # update on change

            # if transaction == block[-1]:
            if tx_index == block_instance.tx_count - 1:  # faster than comparing the whole tx
                if not address_is_rsa(tx.received_recipient):
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
            transaction_validate()

    def process_transactions(block):
        fees_block = []
        block_instance.mining_reward = 0  # avoid warning

        # Cache for multiple tx from same address
        balances = {}

        for tx_index, transaction in enumerate(block):
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
                            essentials.fee_calculate(db_openfield, db_operation,
                                                     node.last_block)))  # exclude the mining tx from fees

            balance_pre = ledger_balance3(db_address, balances, db_handler)  # keep this as c (ram hyperblock access)
            balance = quantize_eight(balance_pre - block_debit_address)

            fee = essentials.fee_calculate(db_openfield, db_operation, node.last_block)

            fees_block.append(quantize_eight(fee))
            # node.logger.app_log.info("Fee: " + str(fee))

            # decide reward
            if tx_index == block_instance.tx_count - 1:
                db_amount = 0  # prevent spending from another address, because mining txs allow delegation
                if node.last_block <= 10000000:

                    if node.last_block >= fork.POW_FORK or (node.is_testnet and node.last_block >= fork.POW_FORK_TESTNET):
                        block_instance.mining_reward = 15 - (quantize_eight(block_instance.block_height_new) / quantize_eight(1000000 / 2)) - Decimal("2.4")
                    else:
                        block_instance.mining_reward = 15 - (quantize_eight(block_instance.block_height_new) / quantize_eight(1000000 / 2)) - Decimal("0.8")

                    if block_instance.mining_reward < 0:
                        block_instance.mining_reward = 0
                else:
                    block_instance.mining_reward = 0

                reward = quantize_eight(block_instance.mining_reward + sum(fees_block[:-1]))
                # don't request a fee for mined block so new accounts can mine
                fee = 0
            else:
                reward = 0

            if quantize_eight(balance_pre) < quantize_eight(db_amount):
                raise ValueError(f"{db_address} sending more than owned: {db_amount}/{balance_pre}")

            if quantize_eight(balance) - quantize_eight(block_fees_address) < 0:
                # exclude fee check for the mining/header tx
                raise ValueError(f"{db_address} Cannot afford to pay fees (balance: {balance}, "
                                 f"block fees: {block_fees_address})")

            # append, but do not insert to ledger before whole block is validated,
            # note that it takes already validated values (decimals, length)
            node.logger.app_log.info(f"Chain: Appending transaction back to block with "
                                     f"{len(block_transactions)} transactions in it")
            block_transactions.append((str(block_instance.block_height_new), str(db_timestamp), str(db_address),
                                       str(db_recipient), str(db_amount), str(db_signature),
                                       str(db_public_key_b64encoded), str(block_instance.block_hash), str(fee),
                                       str(reward), str(db_operation), str(db_openfield)))
            try:
                mp.MEMPOOL.delete_transaction(db_signature)
                node.logger.app_log.info(f"Chain: Removed processed transaction {db_signature[:56]}"
                                         f" from the mempool while digesting")
            except:
                # tx was not or is no more in the local mempool
                pass

    def process_blocks(block_data):
        if node.IS_STOPPING:
            node.logger.app_log.warning("Process_blocks aborted, node is stopping")
            return
        try:
            for block in block_data:

                block_instance.block_count += 1
                # Reworked process: we exit as soon as we find an error, no need to process further tests.
                # Then the exception handler takes place.
                # EGG: Reminder: quick test first, **always**. Heavy tests only thereafter.

                # TODO: this updates block_instance.tx_count, so all breaks if you move that.
                # Hidden variables are bug prone.
                check_signature(block)

                block_instance.tx_count = len(signature_list)
                if block_instance.tx_count != len(set(signature_list)):
                    raise ValueError("There are duplicate transactions in this block, rejected")

                del signature_list[:]

                block_instance.block_height_new = node.last_block + 1
                block_instance.start_time_block = quantize_two(time.time())

                fork_reward_check()

                # sort_transactions also computes several hidden variables, like miner_tx.q_block_timestamp
                # So it has to be run before the check
                # TODO: rework to avoid hidden variables and make the sequence clear.
                # sort_transactions also validates all transactions and sigs, and this is a waste of time if the block timestamp is wrong.
                sort_transactions(block)
                # reject blocks older than latest block
                if miner_tx.q_block_timestamp <= node.last_block_timestamp:
                    # print("miner_tx2", miner_tx)
                    raise ValueError(f"!Block is older {miner_tx.q_block_timestamp} "
                                     f"than the previous one {node.last_block_timestamp} , will be rejected")


                # calculate current difficulty (is done for each block in block array, not super easy to isolate)
                diff = difficulty(node, db_handler)
                node.difficulty = diff

                node.logger.app_log.warning(f"Time to generate block {node.last_block + 1}: {'%.2f' % diff[2]}")
                node.logger.app_log.warning(f"Current difficulty: {diff[3]}")
                node.logger.app_log.warning(f"Current blocktime: {diff[4]}")
                node.logger.app_log.warning(f"Current hashrate: {diff[5]}")
                node.logger.app_log.warning(f"Difficulty adjustment: {diff[6]}")
                node.logger.app_log.warning(f"Difficulty: {diff[0]} {diff[1]}")

                block_instance.block_hash = hashlib.sha224((str(block_instance.transaction_list_converted) + node.last_block_hash).encode("utf-8")).hexdigest()
                del block_instance.transaction_list_converted[:]

                # node.logger.app_log.info("Last block sha_hash: {}".format(block_hash))
                node.logger.app_log.info(f"Calculated block sha_hash: {block_instance.block_hash}")
                # node.logger.app_log.info("Nonce: {}".format(nonce))

                # check if we already have the sha_hash
                db_handler.execute_param(db_handler.h, "SELECT block_height FROM transactions WHERE block_hash = ?",
                                         (block_instance.block_hash,))
                dummy = db_handler.h.fetchone()
                if dummy:
                    raise ValueError(
                        "Skipping digestion of block {} from {}, because we already have it on block_height {}".
                            format(block_instance.block_hash[:10], peer_ip, dummy[0]))

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
                                                          app_log=node.logger.app_log)
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
                                                          app_log=node.logger.app_log)
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
                                                          app_log=node.logger.app_log)

                process_transactions(block)

                node.last_block = block_instance.block_height_new
                node.last_block_hash = block_instance.block_hash
                # end for block

                # save current diff (before the new block)

                # quantized vars have to be converted, since Decimal is not json serializable...
                node.plugin_manager.execute_action_hook('block',
                                                        {'height': block_instance.block_height_new, 'diff': diff_save,
                                                         'hash': block_instance.block_hash,
                                                         'timestamp': float(miner_tx.q_block_timestamp),
                                                         'miner': miner_tx.miner_address, 'ip': peer_ip})

                node.plugin_manager.execute_action_hook('fullblock',
                                                        {'height': block_instance.block_height_new, 'diff': diff_save,
                                                         'hash': block_instance.block_hash,
                                                         'timestamp': float(miner_tx.q_block_timestamp),
                                                         'miner': miner_tx.miner_address, 'ip': peer_ip,
                                                         'transactions': block_transactions})

                db_handler.to_db(block_instance, diff_save, block_transactions)

                # savings
                if node.is_testnet or block_instance.block_height_new >= 843000:
                    # no savings for regnet
                    if int(block_instance.block_height_new) % 10000 == 0:  # every x blocks

                        staking.staking_update(db_handler.conn, db_handler.c, db_handler.index, db_handler.index_cursor,
                                               "normal", block_instance.block_height_new, node.logger.app_log)
                        staking.staking_payout(db_handler.conn, db_handler.c, db_handler.index, db_handler.index_cursor,
                                               block_instance.block_height_new, float(miner_tx.q_block_timestamp),
                                               node.logger.app_log)
                        staking.staking_revalidate(db_handler.conn, db_handler.c, db_handler.index,
                                                   db_handler.index_cursor, block_instance.block_height_new,
                                                   node.logger.app_log)

                # new sha_hash
                db_handler.execute(db_handler.c, "SELECT * FROM transactions "
                                                 "WHERE block_height = (SELECT max(block_height) FROM transactions)")
                # Was trying to simplify, but it's the latest mirror sha_hash.
                # not the latest block, nor the mirror of the latest block.
                # c.execute("SELECT * FROM transactions WHERE block_height = ?", (block_instance.block_height_new -1,))
                tx_list_to_hash = db_handler.c.fetchall()
                block_instance.mirror_hash = hashlib.blake2b(str(tx_list_to_hash).encode(), digest_size=20).hexdigest()
                # /new sha_hash

                rewards()

                # node.logger.app_log.warning("Block: {}: {} valid and saved from {}"
                # .format(block_instance.block_height_new, block_hash[:10], peer_ip))
                node.logger.app_log.warning(f"Valid block: {block_instance.block_height_new}: "
                                            f"{block_instance.block_hash[:10]} with {len(block)} txs, "
                                            f"digestion from {peer_ip} completed in "
                                            f"{str(time.time() - float(block_instance.start_time_block))[:5]}s.")
                del block_transactions[:]
                node.peers.unban(peer_ip)

                # This new block may change the int(diff). Trigger the hook whether it changed or not.
                diff = difficulty(node, db_handler)
                node.difficulty = diff
                node.plugin_manager.execute_action_hook('diff', diff[0])
                # We could recalc diff after inserting block, and then only trigger the block hook,
                # but I fear this would delay the new block event.

                # /whole block validation
                # NEW: returns new block sha_hash
        except Exception as e:
            # Left for edge cases debug
            """
            print(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            """
            raise


    # TODO: no def in def, unreadable. we are 10 screens down the prototype of that function.
    # digestion begins here
    if node.peers.is_banned(peer_ip):
        # no need to loose any time with banned peers
        raise ValueError("Cannot accept blocks from a banned peer")
        # since we raise, it will also drop the connection, it's fine since he's banned.

    tx = Transaction()
    miner_tx = MinerTransaction()
    block_instance = Block()

    if not node.db_lock.locked():

        node.db_lock.acquire()
        node.logger.app_log.warning(f"Database lock acquired")

        while mp.MEMPOOL.lock.locked():
            time.sleep(0.1)
            node.logger.app_log.info(f"Chain: Waiting for mempool to unlock {peer_ip}")

        node.logger.app_log.warning(f"Chain: Digesting started from {peer_ip}")
        # variables that have been quantized are prefixed by q_ So we can avoid any unnecessary quantize again later.
        # Takes time. Variables that are only used as quantized decimal are quantized once and for all.

        block_size = Decimal(sys.getsizeof(str(data))) / Decimal(1000000)
        node.logger.app_log.warning(f"Chain: Block size: {block_size} MB")

        try:
            block_data = data
            # reject block with duplicate transactions
            signature_list = []
            block_transactions = []

            process_blocks(block_data)

            checkpoint_set(node)
            return node.last_block_hash

        except Exception as e:
            node.logger.app_log.warning(f"Chain processing failed: {e}")
            node.logger.app_log.info(f"Received data dump: {data}")
            block_instance.failed_cause = str(e)

            node.last_block = db_handler.block_max_ram()['block_height'] #get actual data from database on exception
            node.last_block_hash = db_handler.last_block_hash() #get actual data from database on exception

            # Temp
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

            if node.peers.warning(sdef, peer_ip, "Rejected block", 2):
                raise ValueError(f"{peer_ip} banned")
            raise ValueError("Chain: digestion aborted")

        finally:

            db_handler.db_to_drive(node)

            node.db_lock.release()
            node.logger.app_log.warning(f"Database lock released")

            delta_t = time.time() - float(block_instance.start_time_block)
            # node.logger.app_log.warning("Block: {}: {} digestion completed in {}s."
            # .format(block_instance.block_height_new,  block_hash[:10], delta_t))
            node.plugin_manager.execute_action_hook('digestblock',
                                                    {'failed': block_instance.failed_cause,
                                                     'ip': peer_ip,
                                                     'deltat': delta_t,
                                                     "blocks": block_instance.block_count,
                                                     "txs": block_instance.tx_count})

            if tokens_operation_present:
                tokens.tokens_update(node, db_handler)

    else:
        node.logger.app_log.warning(f"Chain: Skipping processing from {peer_ip}, someone delivered data faster")
        node.plugin_manager.execute_action_hook('digestblock', {'failed': "skipped", 'ip': peer_ip})