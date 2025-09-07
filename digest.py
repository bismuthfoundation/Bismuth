import hashlib
import os
import sys
import time
from decimal import Decimal
from typing import List, Dict, Any, Optional, Tuple

import essentials
import mempool as mp
import mining_heavy3
from difficulty import difficulty
from essentials import address_is_rsa, checkpoint_set, ledger_balance3
from polysign.signerfactory import SignerFactory
from fork import Fork
import tokensv2 as tokens

fork = Fork()


class Transaction:
    """Represents a single transaction within a block."""

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

    def from_raw_transaction(self, transaction: tuple, index: int, tx_count: int) -> 'MinerTransaction':
        """Parse raw transaction data and populate fields."""
        self.start_time_tx = quantize_two(time.time())
        self.q_received_timestamp = quantize_two(transaction[0])
        self.received_timestamp = '%.2f' % self.q_received_timestamp
        self.received_address = str(transaction[1])[:56]
        self.received_recipient = str(transaction[2])[:56]
        self.received_amount = '%.8f' % (quantize_eight(transaction[3]))
        self.received_signature_enc = str(transaction[4])[:684]
        self.received_public_key_b64encoded = str(transaction[5])[:1068]
        self.received_operation = str(transaction[6])[:30]
        self.received_openfield = str(transaction[7])[:100000]

        # Check if this is the mining transaction (last in block)
        if index == tx_count - 1:
            if float(self.received_amount) != 0:
                raise ValueError("Coinbase (Mining) transaction must have zero amount")
            if not address_is_rsa(self.received_address):
                raise ValueError("Coinbase (Mining) transaction only supports legacy RSA Bismuth addresses")

            # Return miner transaction data
            miner_tx = MinerTransaction()
            miner_tx.q_block_timestamp = self.q_received_timestamp
            miner_tx.nonce = self.received_openfield[:128]
            miner_tx.miner_address = self.received_address
            return miner_tx

        return None

    def validate(self, node, last_block_timestamp: float) -> None:
        """Validate transaction elements. Raises ValueError on invalid transaction."""
        # Timestamp checks (cheap operations first)
        if self.start_time_tx < self.q_received_timestamp:
            minutes_future = quantize_two((self.q_received_timestamp - self.start_time_tx) / 60)
            raise ValueError(f"Future transaction not allowed, timestamp {minutes_future} minutes in the future")

        if last_block_timestamp - 86400 > self.q_received_timestamp:
            raise ValueError("Transaction older than 24h not allowed.")

        # Amount validation
        if float(self.received_amount) < 0:
            raise ValueError("Negative balance spend attempt")

        # Address validation
        if not essentials.address_validate(self.received_address):
            raise ValueError("Not a valid sender address")
        if not essentials.address_validate(self.received_recipient):
            raise ValueError("Not a valid recipient address")

        # Signature verification (expensive operation last)
        buffer = str((
            self.received_timestamp,
            self.received_address,
            self.received_recipient,
            self.received_amount,
            self.received_operation,
            self.received_openfield
        )).encode("utf-8")

        SignerFactory.verify_bis_signature(
            self.received_signature_enc,
            self.received_public_key_b64encoded,
            buffer,
            self.received_address
        )

    def to_tuple(self) -> tuple:
        """Convert transaction to tuple format for storage."""
        return (
            self.received_timestamp,
            self.received_address,
            self.received_recipient,
            self.received_amount,
            self.received_signature_enc,
            self.received_public_key_b64encoded,
            self.received_operation,
            self.received_openfield
        )


class MinerTransaction:
    """Represents the mining transaction (coinbase) of a block."""

    def __init__(self):
        self.q_block_timestamp = 0
        self.nonce = None
        self.miner_address = None


class Block:
    """Represents a block being processed."""

    def __init__(self, node):
        self.tx_count = 0
        self.block_height_new = node.last_block + 1
        self.block_hash = 'N/A'
        self.failed_cause = ''
        self.block_count = 0
        self.transaction_list_converted = []
        self.mining_reward = None
        self.mirror_hash = None
        self.start_time_block = quantize_two(time.time())
        self.tokens_operation_present = False


class BlockProcessor:
    """Handles the processing and validation of blocks."""

    def __init__(self, node, db_handler, peer_ip):
        self.node = node
        self.db_handler = db_handler
        self.peer_ip = peer_ip
        self.block_transactions = []

    def check_fork_reward(self, block_instance: Block) -> None:
        """Check and handle fork reward validation."""
        if self.node.is_testnet:
            if self.node.last_block > fork.POW_FORK_TESTNET:
                if not fork.check_postfork_reward_testnet(self.db_handler):
                    self.db_handler.rollback_under(fork.POW_FORK_TESTNET - 1)
                    raise ValueError("Rolling back chain due to old fork data")
        else:
            if self.node.last_block > fork.POW_FORK:
                if not fork.check_postfork_reward(self.db_handler):
                    print("Rolling back")
                    self.db_handler.rollback_under(fork.POW_FORK - 1)
                    raise ValueError("Rolling back chain due to old fork data")

    def check_duplicate_signatures(self, block: list, block_instance: Block) -> None:
        """Check for duplicate transactions in block and ledger."""
        signature_list = []

        for entry in block:
            entry_signature = entry[4]

            if not entry_signature:
                raise ValueError(f"Empty signature from {self.peer_ip}")

            signature_list.append(entry_signature)

            # Check if signature exists in main ledger
            if self._signature_exists_in_ledger(entry_signature, self.db_handler.h):
                raise ValueError(f"Transaction {entry_signature[:10]} already in ledger")

            # Check if signature exists in RAM ledger
            if self._signature_exists_in_ledger(entry_signature, self.db_handler.c):
                raise ValueError(f"Transaction {entry_signature[:10]} already in RAM ledger")

        # Check for duplicates within the block
        if block_instance.tx_count != len(set(signature_list)):
            raise ValueError("There are duplicate transactions in this block, rejected")

    def _signature_exists_in_ledger(self, signature: str, cursor) -> bool:
        """Check if a signature exists in the specified ledger."""
        if self.node.old_sqlite:
            self.db_handler.execute_param(
                cursor,
                "SELECT block_height FROM transactions WHERE signature = ?1;",
                (signature,)
            )
        else:
            self.db_handler.execute_param(
                cursor,
                "SELECT block_height FROM transactions WHERE substr(signature,1,4) = substr(?1,1,4) and signature = ?1;",
                (signature,)
            )
        return cursor.fetchone() is not None

    def sort_and_validate_transactions(self, block: list, block_instance: Block) -> MinerTransaction:
        """Sort and validate all transactions in a block."""
        miner_tx = None

        for tx_index, raw_transaction in enumerate(block):
            tx = Transaction()
            potential_miner_tx = tx.from_raw_transaction(raw_transaction, tx_index, block_instance.tx_count)

            if potential_miner_tx:
                miner_tx = potential_miner_tx

            # Check for token operations
            if tx.received_operation in ["token:issue", "token:transfer"]:
                block_instance.tokens_operation_present = True

            # Validate transaction
            tx.validate(self.node, self.node.last_block_timestamp)

            # Add to converted list
            block_instance.transaction_list_converted.append(tx.to_tuple())

            # Log validation success
            self.node.logger.app_log.info(
                f"Valid signature from {tx.received_address} to {tx.received_recipient} "
                f"amount {tx.received_amount}"
            )

        return miner_tx

    def calculate_mining_reward(self, block_instance: Block) -> Decimal:
        """Calculate the mining reward for the current block."""
        if self.node.is_testnet and self.node.last_block >= fork.POW_FORK_TESTNET:
            reward = 15 - (block_instance.block_height_new - fork.POW_FORK_TESTNET) / 1100000 - 9.5
        elif self.node.is_mainnet and self.node.last_block >= fork.POW_FORK:
            reward = 15 - (block_instance.block_height_new - fork.POW_FORK) / 1100000 - 9.5
        else:
            reward = 15 - (quantize_eight(block_instance.block_height_new) / quantize_eight(1000000 / 2)) - Decimal(
                "2.4")

        return max(reward, 0.5)

    def process_transaction_balances(self, block: list, block_instance: Block, miner_tx: MinerTransaction) -> List[
        Decimal]:
        """Process transactions and validate balances."""
        fees_block = []
        balances = {}  # Cache for multiple tx from same address

        # Calculate oldest possible transaction time
        if block_instance.block_height_new >= 1450000:
            oldest_possible_tx = miner_tx.q_block_timestamp - 60 * 60 * 2
        else:
            oldest_possible_tx = miner_tx.q_block_timestamp - 60 * 60 * 24

        for tx_index, transaction in enumerate(block):
            # Validate transaction age
            if float(transaction[0]) < oldest_possible_tx:
                raise ValueError(
                    f"txid {transaction[4][:56]} from {transaction[1]} is older ({transaction[0]}) "
                    f"than oldest possible date ({oldest_possible_tx})"
                )

            # Parse transaction fields
            db_timestamp = '%.2f' % quantize_two(transaction[0])
            db_address = str(transaction[1])[:56]
            db_recipient = str(transaction[2])[:56]
            db_amount = '%.8f' % quantize_eight(transaction[3])
            db_signature = str(transaction[4])[:684]
            db_public_key_b64encoded = str(transaction[5])[:1068]
            db_operation = str(transaction[6])[:30]
            db_openfield = str(transaction[7])[:100000]

            # Calculate block debits and fees for address
            block_debit_address, block_fees_address = self._calculate_address_totals(
                block, db_address, db_operation, db_openfield
            )

            # Process mining transaction
            if tx_index == block_instance.tx_count - 1:
                db_amount = 0  # Prevent spending from another address
                block_instance.mining_reward = self.calculate_mining_reward(block_instance)
                reward = '{:.8f}'.format(Decimal(block_instance.mining_reward) + sum(fees_block))
                fee = 0
            else:
                # Regular transaction
                reward = 0
                fee = essentials.fee_calculate(db_openfield, db_operation, self.node.last_block)
                fees_block.append(quantize_eight(fee))

                # Validate balance
                self._validate_balance(
                    db_address, db_amount, block_debit_address,
                    block_fees_address, balances
                )

            # Append to block transactions
            self.block_transactions.append((
                str(block_instance.block_height_new), str(db_timestamp), str(db_address),
                str(db_recipient), str(db_amount), str(db_signature),
                str(db_public_key_b64encoded), str(block_instance.block_hash), str(fee),
                str(reward), str(db_operation), str(db_openfield)
            ))

            # Remove from mempool if present
            self._remove_from_mempool(db_signature)

        return fees_block

    def _calculate_address_totals(self, block: list, address: str, operation: str, openfield: str) -> Tuple[
        Decimal, Decimal]:
        """Calculate total debits and fees for an address in the block."""
        block_debit_address = Decimal(0)
        block_fees_address = Decimal(0)

        for x in block:
            if x[1] == address:
                block_debit_address = quantize_eight(block_debit_address + Decimal(x[3]))

                # Exclude mining tx from fees
                if x != block[-1]:
                    fee = essentials.fee_calculate(x[7], x[6], self.node.last_block)
                    block_fees_address = quantize_eight(block_fees_address + Decimal(fee))

        return block_debit_address, block_fees_address

    def _validate_balance(self, address: str, amount: str, debit: Decimal, fees: Decimal, balances: dict) -> None:
        """Validate that an address has sufficient balance."""
        balance_pre = ledger_balance3(address, balances, self.db_handler)
        balance = quantize_eight(balance_pre - debit)

        if quantize_eight(balance_pre) < quantize_eight(amount):
            raise ValueError(f"{address} sending more than owned: {amount}/{balance_pre}")

        if quantize_eight(balance) - quantize_eight(fees) < 0:
            raise ValueError(f"{address} Cannot afford to pay fees (balance: {balance}, block fees: {fees})")

    def _remove_from_mempool(self, signature: str) -> None:
        """Remove processed transaction from mempool."""
        try:
            mp.MEMPOOL.delete_transaction(signature)
            self.node.logger.app_log.info(
                f"Chain: Removed processed transaction {signature[:56]} from the mempool while digesting"
            )
        except:
            pass  # Transaction not in local mempool

    def apply_rewards(self, block_instance: Block, miner_tx: MinerTransaction) -> None:
        """Apply dev and HN rewards if applicable."""
        if block_instance.block_height_new % 10 == 0 and block_instance.block_height_new < 4380000:
            self.db_handler.dev_reward(
                self.node, block_instance, miner_tx,
                block_instance.mining_reward, block_instance.mirror_hash
            )
            self.db_handler.hn_reward(
                self.node, block_instance, miner_tx,
                block_instance.mirror_hash
            )

    def verify_proof_of_work(self, block_instance: Block, miner_tx: MinerTransaction,
                             tx: Transaction, diff: tuple) -> Any:
        """Verify the proof of work for the block."""
        if self.node.is_mainnet or self.node.is_testnet:
            return mining_heavy3.check_block(
                block_instance.block_height_new,
                miner_tx.miner_address,
                miner_tx.nonce,
                self.node.last_block_hash,
                diff[0],
                tx.received_timestamp,
                tx.q_received_timestamp,
                self.node.last_block_timestamp,
                peer_ip=self.peer_ip,
                app_log=self.node.logger.app_log
            )
        else:
            # Regnet
            import regnet
            return mining_heavy3.check_block(
                block_instance.block_height_new,
                miner_tx.miner_address,
                miner_tx.nonce,
                self.node.last_block_hash,
                regnet.REGNET_DIFF,
                tx.received_timestamp,
                tx.q_received_timestamp,
                self.node.last_block_timestamp,
                peer_ip=self.peer_ip,
                app_log=self.node.logger.app_log
            )


def quantize_two(value: float) -> Decimal:
    """Quantize to 2 decimal places."""
    return Decimal(value).quantize(Decimal('0.01'))


def quantize_eight(value: Any) -> Decimal:
    """Quantize to 8 decimal places."""
    return Decimal(value).quantize(Decimal('0.00000001'))


def digest_block(node, data, sdef, peer_ip, db_handler):
    """
    Main function to digest and validate incoming blocks.

    Args:
        node: Node instance containing blockchain state
        data: Block data to process
        sdef: Socket definition
        peer_ip: IP address of the peer sending the block
        db_handler: Database handler instance

    Returns:
        Last block hash on success

    Raises:
        ValueError: On validation failure
    """
    # Check if peer is banned
    if node.peers.is_banned(peer_ip):
        raise ValueError("Cannot accept blocks from a banned peer")

    # Acquire database lock
    if not node.db_lock.locked():
        node.db_lock.acquire()
        node.logger.app_log.warning("Database lock acquired")

        # Wait for mempool to unlock
        while mp.MEMPOOL.lock.locked():
            time.sleep(0.1)
            node.logger.app_log.info(f"Chain: Waiting for mempool to unlock {peer_ip}")

        node.logger.app_log.warning(f"Chain: Digesting started from {peer_ip}")

        # Log block size
        block_size = Decimal(sys.getsizeof(str(data))) / Decimal(1000000)
        node.logger.app_log.warning(f"Chain: Block size: {block_size} MB")

        try:
            # Process all blocks in the data
            processor = BlockProcessor(node, db_handler, peer_ip)
            last_block_hash = process_block_data(node, data, processor, db_handler, peer_ip)

            checkpoint_set(node)
            return last_block_hash

        except Exception as e:
            handle_processing_error(node, db_handler, sdef, peer_ip, e)

        finally:
            cleanup_after_processing(node, db_handler, peer_ip)

    else:
        node.logger.app_log.warning(f"Chain: Skipping processing from {peer_ip}, someone delivered data faster")
        node.plugin_manager.execute_action_hook('digestblock', {'failed': "skipped", 'ip': peer_ip})


def process_block_data(node, data, processor, db_handler, peer_ip) -> str:
    """Process the block data and return the last block hash."""
    block_count = len(data)

    for block in data:
        if node.IS_STOPPING:
            node.logger.app_log.warning("Process_blocks aborted, node is stopping")
            return node.last_block_hash

        # Create block instance
        block_instance = Block(node)
        block_instance.tx_count = len(block)
        block_instance.block_count = block_count

        # Check fork reward
        processor.check_fork_reward(block_instance)

        # Sort and validate transactions
        miner_tx = processor.sort_and_validate_transactions(block, block_instance)

        # Validate block timestamp
        if miner_tx.q_block_timestamp <= node.last_block_timestamp:
            raise ValueError(
                f"Block is older {miner_tx.q_block_timestamp} than the previous one "
                f"{node.last_block_timestamp}, will be rejected"
            )

        # Check for duplicate signatures
        processor.check_duplicate_signatures(block, block_instance)

        # Calculate difficulty
        diff = difficulty(node, db_handler)
        node.difficulty = diff
        log_difficulty_info(node, diff)

        # Calculate block hash
        block_instance.block_hash = hashlib.sha224(
            (str(block_instance.transaction_list_converted) + node.last_block_hash).encode("utf-8")
        ).hexdigest()

        # Check if we already have this block
        if block_already_exists(db_handler, block_instance.block_hash, peer_ip):
            continue

        # Verify proof of work
        # Get last transaction for PoW verification
        last_tx = Transaction()
        last_tx.from_raw_transaction(block[-1], len(block) - 1, len(block))
        diff_save = processor.verify_proof_of_work(block_instance, miner_tx, last_tx, diff)

        # Process transaction balances
        processor.process_transaction_balances(block, block_instance, miner_tx)

        # Update node state
        node.last_block = block_instance.block_height_new
        node.last_block_hash = block_instance.block_hash

        # Execute plugin hooks
        execute_block_hooks(node, block_instance, miner_tx, diff_save, peer_ip, processor.block_transactions)

        # Save to database
        db_handler.to_db(block_instance, diff_save, processor.block_transactions)

        # Calculate mirror hash
        block_instance.mirror_hash = calculate_mirror_hash(db_handler)

        # Apply rewards
        processor.apply_rewards(block_instance, miner_tx)

        # Log success
        node.logger.app_log.warning(
            f"Valid block: {block_instance.block_height_new}: {block_instance.block_hash[:10]} "
            f"with {len(block)} txs, digestion from {peer_ip} completed in "
            f"{str(time.time() - float(block_instance.start_time_block))[:5]}s."
        )

        # Update tokens if necessary
        if block_instance.tokens_operation_present:
            tokens.tokens_update(node, db_handler)

        # Clear transactions and unban peer
        processor.block_transactions.clear()
        node.peers.unban(peer_ip)

        # Recalculate difficulty and trigger hook
        diff = difficulty(node, db_handler)
        node.difficulty = diff
        node.plugin_manager.execute_action_hook('diff', diff[0])

    return node.last_block_hash


def log_difficulty_info(node, diff: tuple) -> None:
    """Log difficulty-related information."""
    node.logger.app_log.warning(f"Time to generate block {node.last_block + 1}: {'%.2f' % diff[2]}")
    node.logger.app_log.warning(f"Current difficulty: {diff[3]}")
    node.logger.app_log.warning(f"Current blocktime: {diff[4]}")
    node.logger.app_log.warning(f"Current hashrate: {diff[5]}")
    node.logger.app_log.warning(f"Difficulty adjustment: {diff[6]}")
    node.logger.app_log.warning(f"Difficulty: {diff[0]} {diff[1]}")


def block_already_exists(db_handler, block_hash: str, peer_ip: str) -> bool:
    """Check if a block with the given hash already exists."""
    db_handler.execute_param(
        db_handler.h,
        "SELECT block_height FROM transactions WHERE block_hash = ?",
        (block_hash,)
    )
    existing = db_handler.h.fetchone()

    if existing:
        raise ValueError(
            f"Skipping digestion of block {block_hash[:10]} from {peer_ip}, "
            f"already have it on block_height {existing[0]}"
        )
    return False


def calculate_mirror_hash(db_handler) -> str:
    """Calculate the mirror hash for the latest block."""
    db_handler.execute(
        db_handler.c,
        "SELECT * FROM transactions WHERE block_height = (SELECT max(block_height) FROM transactions)"
    )
    tx_list_to_hash = db_handler.c.fetchall()
    return hashlib.blake2b(str(tx_list_to_hash).encode(), digest_size=20).hexdigest()


def execute_block_hooks(node, block_instance, miner_tx, diff_save, peer_ip, block_transactions):
    """Execute plugin hooks for the processed block."""
    node.plugin_manager.execute_action_hook('block', {
        'height': block_instance.block_height_new,
        'diff': diff_save,
        'hash': block_instance.block_hash,
        'timestamp': float(miner_tx.q_block_timestamp),
        'miner': miner_tx.miner_address,
        'ip': peer_ip
    })

    node.plugin_manager.execute_action_hook('fullblock', {
        'height': block_instance.block_height_new,
        'diff': diff_save,
        'hash': block_instance.block_hash,
        'timestamp': float(miner_tx.q_block_timestamp),
        'miner': miner_tx.miner_address,
        'ip': peer_ip,
        'transactions': block_transactions
    })


def handle_processing_error(node, db_handler, sdef, peer_ip, error):
    """Handle errors during block processing."""
    node.logger.app_log.warning(f"Chain processing failed: {error}")

    # Restore actual data from database
    node.last_block = db_handler.block_max_ram()['block_height']
    node.last_block_hash = db_handler.last_block_hash()

    # Log error details
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    print(exc_type, fname, exc_tb.tb_lineno)

    # Ban peer if necessary
    if node.peers.warning(sdef, peer_ip, "Rejected block", 2):
        raise ValueError(f"{peer_ip} banned")

    raise ValueError("Chain: digestion aborted")


def cleanup_after_processing(node, db_handler, peer_ip):
    """Clean up after block processing."""
    db_handler.db_to_drive(node)
    node.db_lock.release()
    node.logger.app_log.warning("Database lock released")

    # Execute cleanup hook
    block_instance = Block(node)  # Create temporary instance for timing
    delta_t = time.time() - float(block_instance.start_time_block)

    node.plugin_manager.execute_action_hook('digestblock', {
        'failed': '',
        'ip': peer_ip,
        'deltat': delta_t,
        'blocks': 0,
        'txs': 0
    })