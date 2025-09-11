from node_utils import (blocknf, sequencing_check, check_integrity, balanceget,
                        ledger_check_heights, recompress_ledger, setup_net_type,
                        node_block_init, ram_init, initial_db_check, load_keys,
                        add_indices, verify)

VERSION = "4.5.0.1"

import platform
import shutil
import socketserver
import threading
from sys import version_info
import time
import signal
import base64
import hashlib
from decimal import Decimal
from typing import Dict, Callable, Optional, Any, Tuple

import aliases
import apihandler
import connectionmanager
import dbhandler
import log
import options
import peershandler
import plugins
import wallet_keys
from connections import send, receive
from digest import *
from libs import node, logger, keys, client
from fork import Fork

from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5

fork = Fork()
appname = "Bismuth"
appauthor = "Bismuth Foundation"
regnet = None


class ResponseBuilder:
    """Utility class for building standardized responses"""

    @staticmethod
    def transaction_dict(tx: tuple) -> dict:
        """Convert transaction tuple to dictionary"""
        return {
            "block_height": tx[0],
            "timestamp": tx[1],
            "address": tx[2],
            "recipient": tx[3],
            "amount": tx[4],
            "signature": tx[5],
            "public_key": tx[6],
            "block_hash": tx[7],
            "fee": tx[8],
            "reward": tx[9],
            "operation": tx[10],
            "openfield": tx[11] if len(tx) > 11 else ""
        }

    @staticmethod
    def transaction_list(transactions: list) -> list:
        """Convert list of transactions to list of dicts"""
        return [ResponseBuilder.transaction_dict(tx) for tx in transactions]

    @staticmethod
    def balance_dict(balance_result: tuple) -> dict:
        """Convert balance tuple to dictionary"""
        return {
            "balance": balance_result[0],
            "credit": balance_result[1],
            "debit": balance_result[2],
            "fees": balance_result[3],
            "rewards": balance_result[4],
            "balance_no_mempool": balance_result[5]
        }


class CommandHandler:
    """Handles individual commands with extracted logic"""

    def __init__(self, node_instance, db_handler, client_instance, peer_ip: str, request):
        self.node = node_instance
        self.db = db_handler
        self.client = client_instance
        self.peer_ip = peer_ip
        self.request = request
        self.logger = node_instance.logger.app_log

    def is_allowed(self, command: str) -> bool:
        """Check if peer is allowed to execute command"""
        if not self.node.peers.is_allowed(self.peer_ip, command):
            self.logger.info(f"{self.peer_ip} not whitelisted for {command} command")
            return False
        return True

    # Version/Protocol Commands
    def handle_version(self) -> None:
        """Handle version negotiation"""
        data = receive(self.request)
        if data not in self.node.version_allow:
            self.logger.warning(f"Protocol version mismatch: {data}, should be {self.node.version_allow}")
            send(self.request, "notok")
            raise ValueError("Version mismatch")
        else:
            self.logger.warning(f"Inbound: Protocol version matched with {self.peer_ip}: {data}")
            send(self.request, "ok")
            self.node.peers.store_mainnet(self.peer_ip, data)

    def handle_getversion(self) -> None:
        """Send node version"""
        send(self.request, self.node.version)

    # Mempool Commands
    def handle_mempool(self) -> None:
        """Handle mempool synchronization"""
        segments = receive(self.request)
        self.logger.info(mp.MEMPOOL.merge(segments, self.peer_ip, self.db.c, False))

        if mp.MEMPOOL.sendable(self.peer_ip):
            mempool_txs = mp.MEMPOOL.tx_to_send(self.peer_ip, segments)
            mp.MEMPOOL.sent(self.peer_ip)
        else:
            mempool_txs = []

        send(self.request, mempool_txs)

    def handle_mpget(self) -> None:
        """Get mempool transactions"""
        if not self.is_allowed("mpget"):
            return
        mempool_txs = mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)
        send(self.request, mempool_txs)

    def handle_mpgetjson(self) -> None:
        """Get mempool transactions as JSON"""
        if not self.is_allowed("mpgetjson"):
            return
        mempool_txs = mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)
        response_list = ResponseBuilder.transaction_list(mempool_txs)
        send(self.request, response_list)

    def handle_mpinsert(self) -> None:
        """Insert transaction to mempool"""
        if not self.is_allowed("mpinsert"):
            return
        mempool_insert = receive(self.request)
        self.logger.warning("mpinsert command")
        mpinsert_result = mp.MEMPOOL.merge(mempool_insert, self.peer_ip, self.db.c, True, True)
        self.logger.warning(f"mpinsert result: {mpinsert_result}")
        send(self.request, mpinsert_result)

    def handle_mpclear(self) -> None:
        """Clear mempool (localhost only)"""
        if self.peer_ip == "127.0.0.1":
            mp.MEMPOOL.clear()

    # Sync Commands
    def handle_hello(self) -> None:
        """Handle initial connection greeting"""
        if self.node.is_regnet:
            self.logger.info("Inbound: Got hello but I'm in regtest mode, closing.")
            raise ValueError("Regnet mode")

        send(self.request, "peers")
        peers_send = self.node.peers.peer_list_disk_format()
        send(self.request, peers_send)

        while self.node.db_lock.locked():
            time.sleep(quantize_two(self.node.pause))

        self.logger.info("Inbound: Sending sync request")
        send(self.request, "sync")

    def handle_sendsync(self) -> None:
        """Handle sync request"""
        while self.node.db_lock.locked():
            time.sleep(quantize_two(self.node.pause))

        while len(self.node.syncing) >= 3:
            time.sleep(int(self.node.pause))

        send(self.request, "sync")

    def handle_blockheight(self) -> None:
        """Handle block height exchange"""
        received_block_height = receive(self.request)
        self.logger.info(f"Inbound: Received block height {received_block_height} from {self.peer_ip}")

        consensus_blockheight = int(received_block_height)
        self.node.peers.consensus_add(self.peer_ip, consensus_blockheight, self.request, self.node.hdd_block)

        send(self.request, self.node.hdd_block)

        if int(received_block_height) > self.node.hdd_block:
            self._handle_higher_block()
        else:
            self._handle_same_or_lower_block(received_block_height)

    def _handle_higher_block(self) -> None:
        """Handle case where peer has higher block"""
        self.logger.warning("Inbound: Client has higher block")
        self.logger.info(f"Inbound: block_hash to send: {self.node.hdd_hash}")
        send(self.request, self.node.hdd_hash)

    def _handle_same_or_lower_block(self, received_block_height: str) -> None:
        """Handle case where peer has same or lower block"""
        if int(received_block_height) == self.node.hdd_block:
            self.logger.info(f"Inbound: We have the same height as {self.peer_ip} ({received_block_height})")
        else:
            self.logger.warning(
                f"Inbound: We have higher ({self.node.hdd_block}) block height than {self.peer_ip} ({received_block_height})")

        data = receive(self.request)
        if data == "*":
            self.logger.warning(f"Inbound: {self.peer_ip} dropped connection")
            raise ValueError("Connection dropped")

        self.logger.info(f"Inbound: Will seek the following block: {data}")

        client_block = self.db.block_height_from_hash(data)
        if client_block is None:
            self._handle_block_not_found(data)
        else:
            self._handle_block_found(client_block, data)

    def _handle_block_not_found(self, data: str) -> None:
        """Handle case where block hash is not found"""
        self.logger.warning(f"Inbound: Block {data[:8]} of {self.peer_ip} not found")
        if self.node.full_ledger:
            send(self.request, "blocknf")
        else:
            send(self.request, "blocknfhb")
        send(self.request, data)

        if self.node.peers.warning(self.request, self.peer_ip, "Forked", 2):
            self.logger.info(f"{self.peer_ip} banned")
            raise ValueError("Peer banned")

    def _handle_block_found(self, client_block: int, data: str) -> None:
        """Handle case where block is found"""
        self.logger.info(f"Inbound: Client is at block {client_block}")

        if self.node.hdd_hash == data or not self.node.egress:
            if not self.node.egress:
                self.logger.warning(f"Inbound: Egress disabled for {self.peer_ip}")
            else:
                self.logger.info(f"Inbound: Client {self.peer_ip} has the latest block")
            time.sleep(int(self.node.pause))
            send(self.request, "nonewblk")
        else:
            blocks_fetched = self.db.blocksync(client_block)
            self.logger.info(f"Inbound: Selected {blocks_fetched}")
            send(self.request, "blocksfnd")

            confirmation = receive(self.request)
            if confirmation == "blockscf":
                self.logger.info("Inbound: Client confirmed they want to sync from us")
                send(self.request, blocks_fetched)
            elif confirmation == "blocksrj":
                self.logger.info("Inbound: Client rejected to sync from us")

    # Block Commands
    def handle_block(self) -> None:
        """Handle incoming mined block"""
        if not self.is_allowed("block"):
            receive(self.request)  # consume the block data
            return

        self.logger.info(f"Inbound: Received a block from miner {self.peer_ip}")
        segments = receive(self.request)

        mined = {
            "timestamp": time.time(),
            "last": self.node.last_block,
            "ip": self.peer_ip,
            "miner": "",
            "result": False,
            "reason": ''
        }

        try:
            mined['miner'] = segments[0][-1][1]
        except:
            return  # missing info

        if self.node.is_mainnet:
            self._process_mainnet_block(segments, mined)
        else:
            self._process_non_mainnet_block(segments)

    def _process_mainnet_block(self, segments: list, mined: dict) -> None:
        """Process block on mainnet"""
        if len(self.node.peers.connection_pool) < 5 and not self.node.peers.is_whitelisted(self.peer_ip):
            mined['reason'] = "Inbound: Mined block ignored, insufficient connections"
            self.node.plugin_manager.execute_action_hook('mined', mined)
            self.logger.info(mined['reason'])
            return

        if self.node.db_lock.locked():
            mined['reason'] = "Inbound: Block from miner skipped, already digesting"
            self.node.plugin_manager.execute_action_hook('mined', mined)
            self.logger.warning(mined['reason'])
            return

        if self.node.last_block >= self.node.peers.consensus_max - 3:
            mined['result'] = True
            self.node.plugin_manager.execute_action_hook('mined', mined)
            self.logger.info("Inbound: Processing block from miner")
            try:
                digest_block(self.node, segments, self.request, self.peer_ip, self.db)
            except (ValueError, Exception) as e:
                self.logger.warning(f"Inbound: Processing block error: {e}")
                raise
        else:
            mined['reason'] = f"Inbound: Mined block orphaned, not synced"
            self.node.plugin_manager.execute_action_hook('mined', mined)
            self.logger.warning(mined['reason'])

    def _process_non_mainnet_block(self, segments: list) -> None:
        """Process block on non-mainnet"""
        try:
            digest_block(self.node, segments, self.request, self.peer_ip, self.db)
        except (ValueError, Exception) as e:
            self.logger.error(f"Inbound: Processing block error: {e}")
            raise

    def handle_blocklast(self) -> None:
        """Get last block"""
        if not self.is_allowed("blocklast"):
            return
        self.db.execute(self.db.c, "SELECT * FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")
        block_last = self.db.c.fetchall()[0]
        send(self.request, block_last)

    def handle_blocklastjson(self) -> None:
        """Get last block as JSON"""
        if not self.is_allowed("blocklastjson"):
            return
        self.db.execute(self.db.c, "SELECT * FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")
        block_last = self.db.c.fetchall()[0]
        response = ResponseBuilder.transaction_dict(block_last)
        response["nonce"] = block_last[11] if len(block_last) > 11 else ""
        send(self.request, response)

    def handle_blockget(self) -> None:
        """Get specific block"""
        if not self.is_allowed("blockget"):
            return
        block_desired = receive(self.request)
        self.db.execute_param(self.db.h, "SELECT * FROM transactions WHERE block_height = ?;", (block_desired,))
        block_desired_result = self.db.h.fetchall()
        send(self.request, block_desired_result)

    def handle_blockgetjson(self) -> None:
        """Get specific block as JSON"""
        if not self.is_allowed("blockgetjson"):
            return
        block_desired = receive(self.request)
        self.db.execute_param(self.db.h, "SELECT * FROM transactions WHERE block_height = ?;", (block_desired,))
        block_desired_result = self.db.h.fetchall()
        response_list = ResponseBuilder.transaction_list(block_desired_result)
        send(self.request, response_list)

    # Balance Commands
    def handle_balanceget(self) -> None:
        """Get address balance"""
        if not self.is_allowed("balanceget"):
            return
        balance_address = receive(self.request)
        balanceget_result = balanceget(balance_address, self.db, mp, self.node)
        send(self.request, balanceget_result)

    def handle_balancegetjson(self) -> None:
        """Get address balance as JSON"""
        if not self.is_allowed("balancegetjson"):
            return
        balance_address = receive(self.request)
        balanceget_result = balanceget(balance_address, self.db, mp, self.node)
        response = ResponseBuilder.balance_dict(balanceget_result)
        send(self.request, response)

    def handle_balancegethyper(self) -> None:
        """Get hyperblock balance"""
        if not self.is_allowed("balancegethyper"):
            return
        balance_address = receive(self.request)
        balanceget_result = balanceget(balance_address, self.db, mp, self.node)[0]
        send(self.request, balanceget_result)

    def handle_balancegethyperjson(self) -> None:
        """Get hyperblock balance as JSON"""
        if not self.is_allowed("balancegethyperjson"):
            return
        balance_address = receive(self.request)
        balanceget_result = balanceget(balance_address, self.db, mp, self.node)
        response = {"balance": balanceget_result[0]}
        send(self.request, response)

    # Address List Commands
    def handle_addlist(self) -> None:
        """Get address transaction list"""
        if not self.is_allowed("addlist"):
            return
        address_tx_list = receive(self.request)
        self.db.execute_param(self.db.h,
                              "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC",
                              (address_tx_list, address_tx_list))
        result = self.db.h.fetchall()
        send(self.request, result)

    def handle_addlistlim(self) -> None:
        """Get limited address transaction list"""
        if not self.is_allowed("addlistlim"):
            return
        address_tx_list = receive(self.request)
        address_tx_list_limit = receive(self.request)
        self.db.execute_param(self.db.h,
                              "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC LIMIT ?",
                              (address_tx_list, address_tx_list, address_tx_list_limit))
        result = self.db.h.fetchall()
        send(self.request, result)

    def handle_addlistlimjson(self) -> None:
        """Get limited address transaction list as JSON"""
        if not self.is_allowed("addlistlimjson"):
            return
        address_tx_list = receive(self.request)
        address_tx_list_limit = receive(self.request)
        self.db.execute_param(self.db.h,
                              "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC LIMIT ?",
                              (address_tx_list, address_tx_list, address_tx_list_limit))
        result = self.db.h.fetchall()
        response_list = ResponseBuilder.transaction_list(result)
        send(self.request, response_list)

    # List Commands
    def handle_listlim(self) -> None:
        """Get limited transaction list"""
        if not self.is_allowed("listlim"):
            return
        list_limit = receive(self.request)
        self.db.execute_param(self.db.h, "SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?", (list_limit,))
        result = self.db.h.fetchall()
        send(self.request, result)

    def handle_listlimjson(self) -> None:
        """Get limited transaction list as JSON"""
        if not self.is_allowed("listlimjson"):
            return
        list_limit = receive(self.request)
        self.db.execute_param(self.db.h, "SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?", (list_limit,))
        result = self.db.h.fetchall()
        response_list = ResponseBuilder.transaction_list(result)
        send(self.request, response_list)

    # Key Management Commands
    def handle_keygen(self) -> None:
        """Generate new keypair"""
        if not self.is_allowed("keygen"):
            return
        (gen_private_key_readable, gen_public_key_readable, gen_address) = wallet_keys.generate()
        send(self.request, (gen_private_key_readable, gen_public_key_readable, gen_address))

    def handle_keygenjson(self) -> None:
        """Generate new keypair as JSON"""
        if not self.is_allowed("keygenjson"):
            return
        (gen_private_key_readable, gen_public_key_readable, gen_address) = wallet_keys.generate()
        response = {
            "private_key": gen_private_key_readable,
            "public_key": gen_public_key_readable,
            "address": gen_address
        }
        send(self.request, response)

    def handle_pubkeyget(self) -> None:
        """Get public key for address"""
        if not self.is_allowed("pubkeyget"):
            return
        pub_key_address = receive(self.request)
        target_public_key_b64encoded = self.db.pubkeyget(pub_key_address)
        send(self.request, target_public_key_b64encoded)

    # Alias Commands
    def handle_aliasget(self) -> None:
        """Get alias for address"""
        if not self.is_allowed("aliasget"):
            return
        aliases.aliases_update(self.node, self.db)
        alias_address = receive(self.request)
        result = self.db.aliasget(alias_address)
        send(self.request, result)

    def handle_aliasesget(self) -> None:
        """Get aliases for multiple addresses"""
        if not self.is_allowed("aliasesget"):
            return
        aliases.aliases_update(self.node, self.db)
        aliases_request = receive(self.request)
        results = self.db.aliasesget(aliases_request)
        send(self.request, results)

    def handle_aliascheck(self) -> None:
        """Check if alias is available"""
        if not self.is_allowed("aliascheck"):
            return
        reg_string = receive(self.request)

        registered_pending = mp.MEMPOOL.fetchone(
            "SELECT timestamp FROM transactions WHERE openfield = ?;",
            ("alias=" + reg_string,))

        self.db.execute_param(self.db.h,
                              "SELECT timestamp FROM transactions WHERE openfield = ?;",
                              ("alias=" + reg_string,))
        registered_already = self.db.h.fetchone()

        if registered_already is None and registered_pending is None:
            send(self.request, "Alias free")
        else:
            send(self.request, "Alias registered")

    def handle_addfromalias(self) -> None:
        """Get address from alias"""
        if not self.is_allowed("addfromalias"):
            return
        aliases.aliases_update(self.node, self.db)
        alias_address = receive(self.request)
        address_fetch = self.db.addfromalias(alias_address)
        self.logger.warning(f"Fetched the following alias address: {address_fetch}")
        send(self.request, address_fetch)

    # Token Commands
    def handle_tokensget(self) -> None:
        """Get tokens for address"""
        if not self.is_allowed("tokensget"):
            return
        tokens_address = receive(self.request)
        tokens_user = self.db.tokens_user(tokens_address)

        tokens_list = []
        for token in tokens_user:
            token = token[0]
            self.db.execute_param(self.db.index_cursor,
                                  "SELECT sum(amount) FROM tokens WHERE recipient = ? AND token = ?;",
                                  (tokens_address, token))
            credit = self.db.index_cursor.fetchone()[0]

            self.db.execute_param(self.db.index_cursor,
                                  "SELECT sum(amount) FROM tokens WHERE address = ? AND token = ?;",
                                  (tokens_address, token))
            debit = self.db.index_cursor.fetchone()[0]

            debit = 0 if debit is None else debit
            credit = 0 if credit is None else credit
            balance = str(Decimal(credit) - Decimal(debit))
            tokens_list.append((token, balance))

        send(self.request, tokens_list)

    # Status Commands
    def handle_statusget(self) -> None:
        """Get node status"""
        if not self.is_allowed("statusget"):
            return

        nodes_count = self.node.peers.consensus_size
        nodes_list = self.node.peers.peer_opinion_dict
        threads_count = threading.active_count()
        uptime = int(time.time() - self.node.startup_time)
        diff = self.node.difficulty
        server_timestamp = '%.2f' % time.time()
        revealed_address = self.node.keys.address if self.node.reveal_address else "private"

        send(self.request, (
            revealed_address, nodes_count, nodes_list, threads_count, uptime,
            self.node.peers.consensus, self.node.peers.consensus_percentage,
            VERSION, diff, server_timestamp
        ))

    def handle_statusjson(self) -> None:
        """Get node status as JSON"""
        if not self.is_allowed("statusjson"):
            return

        uptime = int(time.time() - self.node.startup_time)
        tempdiff = self.node.difficulty
        revealed_address = self.node.keys.address if self.node.reveal_address else "private"

        status = {
            "protocolversion": self.node.version,
            "address": revealed_address,
            "walletversion": VERSION,
            "testnet": self.node.is_testnet,
            "blocks": self.node.hdd_block,
            "timeoffset": 0,
            "connections": self.node.peers.consensus_size,
            "connections_list": self.node.peers.peer_opinion_dict,
            "difficulty": tempdiff[0],
            "threads": threading.active_count(),
            "uptime": uptime,
            "consensus": self.node.peers.consensus,
            "consensus_percent": self.node.peers.consensus_percentage,
            "python_version": str(version_info[:3]),
            "last_block_ago": self.node.last_block_ago,
            "server_timestamp": '%.2f' % time.time()
        }

        if self.node.is_regnet:
            status['regnet'] = True

        send(self.request, status)

    # Difficulty Commands
    def handle_diffget(self) -> None:
        """Get difficulty"""
        if not self.is_allowed("diffget"):
            return
        send(self.request, self.node.difficulty)

    def handle_diffgetjson(self) -> None:
        """Get difficulty as JSON"""
        if not self.is_allowed("diffgetjson"):
            return
        diff = self.node.difficulty
        response = {
            "difficulty": diff[0],
            "diff_dropped": diff[1],
            "time_to_generate": diff[2],
            "diff_block_previous": diff[3],
            "block_time": diff[4],
            "hashrate": diff[5],
            "diff_adjustment": diff[6],
            "block_height": diff[7]
        }
        send(self.request, response)

    def handle_difflast(self) -> None:
        """Get last difficulty"""
        if not self.is_allowed("difflast"):
            return
        difflast = self.db.difflast()
        send(self.request, difflast)

    def handle_difflastjson(self) -> None:
        """Get last difficulty as JSON"""
        if not self.is_allowed("difflastjson"):
            return
        difflast = self.db.difflast()
        response = {"block": difflast[0], "difficulty": difflast[1]}
        send(self.request, response)

    # Utility Commands
    def handle_addvalidate(self) -> None:
        """Validate address format"""
        if not self.is_allowed("addvalidate"):
            return
        address_to_validate = receive(self.request)
        result = "valid" if essentials.address_validate(address_to_validate) else "invalid"
        send(self.request, result)

    def handle_annget(self) -> None:
        """Get announcements"""
        if not self.is_allowed("annget"):
            return
        result = self.db.annget(self.node)
        send(self.request, result)

    def handle_annverget(self) -> None:
        """Get announcement version"""
        if not self.is_allowed("annverget"):
            return
        result = self.db.annverget(self.node)
        send(self.request, result)

    def handle_peersget(self) -> None:
        """Get peers list"""
        if not self.is_allowed("peersget"):
            return
        send(self.request, self.node.peers.peer_list_disk_format())

    def handle_portget(self) -> None:
        """Get node port"""
        if not self.is_allowed("portget"):
            return
        send(self.request, {"port": self.node.port})

    def handle_block_height_from_hash(self) -> None:
        """Get block height from hash"""
        if not self.is_allowed("block_height_from_hash"):
            return
        hash_val = receive(self.request)
        response = self.db.block_height_from_hash(hash_val)
        send(self.request, response)

    def handle_addpeers(self) -> None:
        """Add peers to node"""
        if not self.is_allowed("addpeers"):
            return
        data = receive(self.request)
        try:
            res = self.node.peers.peersync(data)
        except:
            self.logger.warning(f"{self.peer_ip} sent invalid peers list")
            raise
        send(self.request, {"added": res})
        self.logger.warning(f"{res} peers added")

    def handle_stop(self) -> None:
        """Stop node (authorized peers only)"""
        if not self.is_allowed("stop"):
            return
        self.logger.warning(f"Received stop from {self.peer_ip}")
        self.node.IS_STOPPING = True

    # Block sync error handlers
    def handle_nonewblk(self) -> None:
        """Handle no new blocks"""
        send(self.request, "sync")

    def handle_blocknf(self) -> None:
        """Handle block not found"""
        block_hash_delete = receive(self.request)
        consensus_blockheight = self.node.peers.consensus_max  # Needs to be set from context
        if consensus_blockheight == self.node.peers.consensus_max:
            blocknf(self.node, block_hash_delete, self.peer_ip, self.db, mp=mp, tokens=tokens)
            if self.node.peers.warning(self.request, self.peer_ip, "Rollback", 2):
                self.logger.info(f"{self.peer_ip} banned")
                raise ValueError("Peer banned")
        self.logger.info("Inbound: Deletion complete, sending sync request")
        while self.node.db_lock.locked():
            time.sleep(self.node.pause)
        send(self.request, "sync")

    def handle_blocknfhb(self) -> None:
        """Handle hyperblock not found"""
        block_hash_delete = receive(self.request)
        consensus_blockheight = self.node.peers.consensus_max
        if consensus_blockheight == self.node.peers.consensus_max:
            blocknf(self.node, block_hash_delete, self.peer_ip, self.db,
                    hyperblocks=True, mp=mp, tokens=tokens)
            if self.node.peers.warning(self.request, self.peer_ip, "Rollback", 2):
                self.logger.info(f"{self.peer_ip} banned")
                raise ValueError("Peer banned")
        self.logger.info("Inbound: Deletion complete, sending sync request")
        while self.node.db_lock.locked():
            time.sleep(self.node.pause)
        send(self.request, "sync")

    def handle_blocksfnd(self) -> None:
        """Handle blocks found for sync"""
        self.logger.info(f"Inbound: Client {self.peer_ip} has the block(s)")

        if self.node.db_lock.locked():
            self.logger.info(f"Skipping sync from {self.peer_ip}, syncing already in progress")
            send(self.request, "sync")
            return

        self.node.last_block_timestamp = self.db.last_block_timestamp()

        # Determine block requirement rule
        if self.node.last_block_timestamp < time.time() - 600:
            block_req = self.node.peers.consensus_most_common
            self.logger.warning("Most common block rule triggered")
        else:
            block_req = self.node.peers.consensus_max
            self.logger.warning("Longest chain rule triggered")

        # Get received block height from context
        received_block_height = self.node.peers.peer_opinion_dict.get(self.peer_ip, 0)

        if int(received_block_height) >= block_req and int(received_block_height) > self.node.last_block:
            try:
                self.logger.warning(f"Confirming to sync from {self.peer_ip}")
                self.node.plugin_manager.execute_action_hook('sync', {'what': 'syncing_from', 'ip': self.peer_ip})
                send(self.request, "blockscf")
                segments = receive(self.request)
                digest_block(self.node, segments, self.request, self.peer_ip, self.db)
            except:
                if self.node.peers.warning(self.request, self.peer_ip, "Failed to deliver the longest chain"):
                    self.logger.info(f"{self.peer_ip} banned")
                    raise
        else:
            self.logger.warning(f"Rejecting to sync from {self.peer_ip}")
            send(self.request, "blocksrj")
            self.logger.info(f"Inbound: Distant peer {self.peer_ip} is at {received_block_height}, "
                             f"should be at least {max(block_req, self.node.last_block + 1)}")

        send(self.request, "sync")


class CommandDispatcher:
    """Dispatch commands to appropriate handlers"""

    def __init__(self, handler: CommandHandler):
        self.handler = handler
        self.commands = {
            # Version/Protocol
            'version': handler.handle_version,
            'getversion': handler.handle_getversion,

            # Mempool
            'mempool': handler.handle_mempool,
            'mpget': handler.handle_mpget,
            'mpgetjson': handler.handle_mpgetjson,
            'mpinsert': handler.handle_mpinsert,
            'mpclear': handler.handle_mpclear,

            # Sync
            'hello': handler.handle_hello,
            'sendsync': handler.handle_sendsync,
            'blockheight': handler.handle_blockheight,
            'blocksfnd': handler.handle_blocksfnd,
            'nonewblk': handler.handle_nonewblk,
            'blocknf': handler.handle_blocknf,
            'blocknfhb': handler.handle_blocknfhb,

            # Blocks
            'block': handler.handle_block,
            'blocklast': handler.handle_blocklast,
            'blocklastjson': handler.handle_blocklastjson,
            'blockget': handler.handle_blockget,
            'blockgetjson': handler.handle_blockgetjson,
            'block_height_from_hash': handler.handle_block_height_from_hash,

            # Balance
            'balanceget': handler.handle_balanceget,
            'balancegetjson': handler.handle_balancegetjson,
            'balancegethyper': handler.handle_balancegethyper,
            'balancegethyperjson': handler.handle_balancegethyperjson,

            # Address Lists
            'addlist': handler.handle_addlist,
            'addlistlim': handler.handle_addlistlim,
            'addlistlimjson': handler.handle_addlistlimjson,
            'addlistlimmir': handler.handle_addlistlimmir,
            'addlistlimmirjson': handler.handle_addlistlimmirjson,

            # Lists
            'listlim': handler.handle_listlim,
            'listlimjson': handler.handle_listlimjson,

            # Keys
            'keygen': handler.handle_keygen,
            'keygenjson': handler.handle_keygenjson,
            'pubkeyget': handler.handle_pubkeyget,

            # Aliases
            'aliasget': handler.handle_aliasget,
            'aliasesget': handler.handle_aliasesget,
            'aliascheck': handler.handle_aliascheck,
            'addfromalias': handler.handle_addfromalias,

            # Tokens
            'tokensget': handler.handle_tokensget,

            # Status
            'statusget': handler.handle_statusget,
            'statusjson': handler.handle_statusjson,

            # Difficulty
            'diffget': handler.handle_diffget,
            'diffgetjson': handler.handle_diffgetjson,
            'difflast': handler.handle_difflast,
            'difflastjson': handler.handle_difflastjson,

            # Utility
            'addvalidate': handler.handle_addvalidate,
            'annget': handler.handle_annget,
            'annverget': handler.handle_annverget,
            'peersget': handler.handle_peersget,
            'portget': handler.handle_portget,
            'addpeers': handler.handle_addpeers,
            'stop': handler.handle_stop,
        }

    def handle_addlistlimmir(self) -> None:
        """Get mirrored limited address transaction list"""
        if not self.handler.is_allowed("addlistlimmir"):
            return
        address_tx_list = receive(self.handler.request)
        address_tx_list_limit = receive(self.handler.request)
        self.handler.db.execute_param(self.handler.db.h,
                                      "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) AND block_height < 1 ORDER BY block_height ASC LIMIT ?",
                                      (address_tx_list, address_tx_list, address_tx_list_limit))
        result = self.handler.db.h.fetchall()
        send(self.handler.request, result)

    def handle_addlistlimmirjson(self) -> None:
        """Get mirrored limited address transaction list as JSON"""
        if not self.handler.is_allowed("addlistlimmirjson"):
            return
        address_tx_list = receive(self.handler.request)
        address_tx_list_limit = receive(self.handler.request)
        self.handler.db.execute_param(self.handler.db.h,
                                      "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) AND block_height < 1 ORDER BY block_height ASC LIMIT ?",
                                      (address_tx_list, address_tx_list, address_tx_list_limit))
        result = self.handler.db.h.fetchall()
        response_list = ResponseBuilder.transaction_list(result)
        send(self.handler.request, response_list)

    def dispatch(self, command: str) -> bool:
        """
        Dispatch command to handler
        Returns True if command was handled, False otherwise
        """
        # Add mirror handlers
        if command == 'addlistlimmir':
            self.handle_addlistlimmir()
            return True
        elif command == 'addlistlimmirjson':
            self.handle_addlistlimmirjson()
            return True

        # Check regular commands
        handler_func = self.commands.get(command)
        if handler_func:
            handler_func()
            return True

        # Check special command prefixes
        if command.startswith('regtest_'):
            return self._handle_regtest(command)
        elif command.startswith('api_'):
            return self._handle_api(command)
        elif command == 'txsend':
            return self._handle_txsend()

        return False

    def _handle_regtest(self, command: str) -> bool:
        """Handle regtest commands"""
        if not self.handler.node.is_regnet:
            send(self.handler.request, "notok")
            return True

        self.handler.db.execute(self.handler.db.c,
                                "SELECT block_hash FROM transactions WHERE block_height = (SELECT max(block_height) FROM transactions)")
        block_hash = self.handler.db.c.fetchone()[0]

        # Feed regnet with current thread db handle
        regnet.conn = self.handler.db.conn
        regnet.c = self.handler.db.c
        regnet.hdd = self.handler.db.hdd
        regnet.h = self.handler.db.h
        regnet.hdd2 = self.handler.db.hdd2
        regnet.h2 = self.handler.db.h2

        regnet.command(self.handler.request, command, block_hash, self.handler.node, self.handler.db)
        return True

    def _handle_api(self, command: str) -> bool:
        """Handle API commands"""
        if not self.handler.is_allowed(command):
            return True

        try:
            self.handler.node.apihandler.dispatch(command, self.handler.request,
                                                  self.handler.db, self.handler.node.peers)
        except Exception as e:
            if self.handler.node.debug:
                raise
            else:
                self.handler.logger.warning(e)
        return True

    def _handle_txsend(self) -> bool:
        """Handle deprecated txsend command"""
        if not self.handler.is_allowed("txsend"):
            return True

        self.handler.logger.warning("txsend is unsafe and deprecated, please don't use.")
        tx_remote = receive(self.handler.request)

        # Extract transaction components
        remote_tx_timestamp = tx_remote[0]
        remote_tx_privkey = tx_remote[1]
        remote_tx_recipient = tx_remote[2]
        remote_tx_amount = tx_remote[3]
        remote_tx_operation = tx_remote[4]
        remote_tx_openfield = tx_remote[5]

        # Derive remaining data
        tx_remote_key = RSA.importKey(remote_tx_privkey)
        remote_tx_pubkey = tx_remote_key.publickey().exportKey().decode("utf-8")
        remote_tx_pubkey_b64encoded = base64.b64encode(remote_tx_pubkey.encode('utf-8')).decode("utf-8")
        remote_tx_address = hashlib.sha224(remote_tx_pubkey.encode("utf-8")).hexdigest()

        # Construct transaction
        remote_tx = (str(remote_tx_timestamp), str(remote_tx_address), str(remote_tx_recipient),
                     '%.8f' % quantize_eight(remote_tx_amount), str(remote_tx_operation),
                     str(remote_tx_openfield))

        # Sign transaction
        remote_hash = SHA.new(str(remote_tx).encode("utf-8"))
        remote_signer = PKCS1_v1_5.new(tx_remote_key)
        remote_signature = remote_signer.sign(remote_hash)
        remote_signature_enc = base64.b64encode(remote_signature).decode("utf-8")

        # Insert to mempool
        mempool_data = ((str(remote_tx_timestamp), str(remote_tx_address), str(remote_tx_recipient),
                         '%.8f' % quantize_eight(remote_tx_amount), str(remote_signature_enc),
                         str(remote_tx_pubkey_b64encoded), str(remote_tx_operation),
                         str(remote_tx_openfield)))

        self.handler.logger.info(mp.MEMPOOL.merge(mempool_data, self.handler.peer_ip,
                                                  self.handler.db.c, True, True))
        send(self.handler.request, str(remote_signature_enc))
        return True


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    """TCP request handler with improved structure"""

    def handle(self):
        """Main handler entry point"""
        if not self._pre_connection_checks():
            return

        db_handler_instance = self._create_db_handler()
        client_instance = client.Client()
        peer_ip = self._get_peer_ip()

        if not peer_ip:
            return

        if not self._setup_connection(peer_ip, client_instance):
            return

        if self._is_banned_or_filtered(peer_ip):
            return

        self._process_commands(peer_ip, client_instance, db_handler_instance)

    def _pre_connection_checks(self) -> bool:
        """Check if node is ready to accept connections"""
        if node.IS_STOPPING:
            node.logger.app_log.warning("Inbound: Rejected incoming cnx, node is stopping")
            return False
        return True

    def _create_db_handler(self):
        """Create database handler instance"""
        return dbhandler.DbHandler(
            node.index_db, node.ledger_path, node.hyper_path,
            node.ram, node.ledger_ram_file, node.logger,
            trace_db_calls=node.trace_db_calls
        )

    def _get_peer_ip(self) -> Optional[str]:
        """Get peer IP address"""
        try:
            return self.request.getpeername()[0]
        except:
            node.logger.app_log.warning("Inbound: Transport endpoint was not connected")
            return None

    def _setup_connection(self, peer_ip: str, client_instance) -> bool:
        """Setup connection and check capacity"""
        threading.current_thread().name = f"in_{peer_ip}"

        # Check capacity
        if threading.active_count() < node.thread_limit / 3 * 2 or node.peers.is_whitelisted(peer_ip):
            client_instance.connected = True
            return True
        else:
            try:
                node.logger.app_log.info(f"Free capacity for {peer_ip} unavailable, disconnected")
                self.request.close()
            except Exception as e:
                node.logger.app_log.warning(f"{e}")
            return False

    def _is_banned_or_filtered(self, peer_ip: str) -> bool:
        """Check if peer is banned or filtered"""
        dict_ip = {'ip': peer_ip}
        node.plugin_manager.execute_filter_hook('peer_ip', dict_ip)

        if node.peers.is_banned(peer_ip) or dict_ip['ip'] == 'banned':
            self.request.close()
            node.logger.app_log.info(f"IP {peer_ip} banned, disconnected")
            return True
        return False

    def _process_commands(self, peer_ip: str, client_instance, db_handler_instance):
        """Process commands from peer"""
        timeout_operation = 120
        timer_operation = time.time()

        # Create command handler and dispatcher
        handler = CommandHandler(node, db_handler_instance, client_instance, peer_ip, self.request)
        dispatcher = CommandDispatcher(handler)

        while (not node.peers.is_banned(peer_ip) and
               node.peers.version_allowed(peer_ip, node.version_allow) and
               client_instance.connected):
            try:
                if not self._check_timeout(timer_operation, timeout_operation, peer_ip):
                    break

                data = receive(self.request)
                node.logger.app_log.info(f"Inbound: Received: {data} from {peer_ip}")

                # Handle special case for broken pipe
                if data == '*':
                    raise ValueError("Broken pipe")

                # Try to dispatch command
                if not dispatcher.dispatch(data):
                    # Try plugin commands
                    if not self._try_plugin_command(data):
                        raise ValueError(f"Unexpected error, received: {str(data)[:32]} ...")

                # Reset timer after successful command
                timer_operation = time.time()
                node.logger.app_log.info(f"Server loop finished for {peer_ip}")

            except Exception as e:
                node.logger.app_log.info(f"Inbound: Lost connection to {peer_ip}")
                node.logger.app_log.info(f"Inbound: {e}")
                node.peers.consensus_remove(peer_ip)
                self.request.close()

                if node.debug:
                    raise
                else:
                    return

        if not node.peers.version_allowed(peer_ip, node.version_allow):
            node.logger.app_log.warning(
                f"Inbound: Closing connection to old {peer_ip} node: {node.peers.ip_to_mainnet[peer_ip]}")

    def _check_timeout(self, timer_operation: float, timeout_operation: int, peer_ip: str) -> bool:
        """Check if operation has timed out"""
        if self.request == -1:
            raise ValueError(f"Inbound: Closed socket from {peer_ip}")

        if time.time() > timer_operation + timeout_operation:
            if node.peers.warning(self.request, peer_ip, "Operation timeout", 2):
                node.logger.app_log.info(f"{peer_ip} banned")
                return False
            raise ValueError(f"Inbound: Operation timeout from {peer_ip}")

        return True

    def _try_plugin_command(self, data: str) -> bool:
        """Try to handle command via plugin"""
        for prefix, callback in extra_commands.items():
            if data.startswith(prefix):
                callback(data, self.request)
                return True
        return False


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server"""
    pass


def signal_handler(sig, frame):
    """Handle shutdown signals"""
    node.logger.app_log.warning("Status: Received interrupt signal, shutting down...")
    node.IS_STOPPING = True


def initialize_node():
    """Initialize node configuration and components"""
    global node, extra_commands

    # Create core components
    node = node.Node()
    node.logger = logger.Logger()
    node.keys = keys.Keys()

    # Set network type
    node.is_testnet = False
    node.is_regnet = False
    node.is_mainnet = True

    # Load configuration
    config = options.Get()
    config.read()

    # Copy config to node
    node.app_version = VERSION
    node.config = config  # Store full config object

    # Copy individual settings for compatibility
    for attr in ['version', 'debug_level', 'port', 'verify', 'thread_limit',
                 'rebuild_db', 'debug', 'pause', 'ledger_path', 'hyper_path',
                 'hyper_recompress', 'tor', 'ram', 'version_allow', 'reveal_address',
                 'terminal_output', 'egress', 'genesis', 'accept_peers', 'full_ledger',
                 'trace_db_calls', 'heavy3_path', 'old_sqlite', 'heavy']:
        setattr(node, attr, getattr(config, attr))

    # Setup logging
    node.logger.app_log = log.log("node.log", node.debug_level, node.terminal_output)
    node.logger.app_log.warning("Configuration settings loaded")
    node.logger.app_log.warning(f"Python version: {node.py_version}")

    # Handle wallet upgrade for Windows
    if os.path.exists("../wallet.der") and not os.path.exists("wallet.der") and "Windows" in platform.system():
        print("Upgrading wallet location")
        os.rename("../wallet.der", "wallet.der")

    # Handle hyperblock mode
    if not node.full_ledger and os.path.exists(node.ledger_path) and node.is_mainnet:
        os.remove(node.ledger_path)
        node.logger.app_log.warning("Removed full ledger for hyperblock mode")

    if not node.full_ledger:
        node.logger.app_log.warning("Cloning hyperblocks to ledger file")
        shutil.copy(node.hyper_path, node.ledger_path)

    # Initialize plugin manager
    node.plugin_manager = plugins.PluginManager(app_log=node.logger.app_log, config=config, init=True)
    extra_commands = node.plugin_manager.execute_filter_hook('extra_commands_prefixes', {})
    print("Extra prefixes: ", ",".join(extra_commands.keys()))

    return config


def initialize_database():
    """Initialize database and perform checks"""
    db_handler_initial = dbhandler.DbHandler(
        node.index_db, node.ledger_path, node.hyper_path,
        node.ram, node.ledger_ram_file, node.logger,
        trace_db_calls=node.trace_db_calls
    )

    ledger_check_heights(node, db_handler_initial, db_handler_initial)

    if node.recompress:
        db_handler_initial.close()
        recompress_ledger(node)
        db_handler_initial = dbhandler.DbHandler(
            node.index_db, node.ledger_path, node.hyper_path,
            node.ram, node.ledger_ram_file, node.logger,
            trace_db_calls=node.trace_db_calls
        )

    ram_init(db_handler_initial, node)
    node_block_init(db_handler_initial, node, db_handler_initial)
    initial_db_check(node)

    if not node.is_regnet:
        sequencing_check(db_handler_initial, node=node)

    if node.verify:
        verify(db_handler_initial, node=node)

    add_indices(db_handler_initial, node=node)

    return db_handler_initial


def start_server():
    """Start the TCP server"""
    if not node.tor:
        host, port = "0.0.0.0", int(node.port)

        ThreadedTCPServer.allow_reuse_address = True
        ThreadedTCPServer.daemon_threads = True
        ThreadedTCPServer.timeout = 60
        ThreadedTCPServer.request_queue_size = 100

        server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
        ip, node.port = server.server_address

        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        node.logger.app_log.warning("Status: Server loop running.")
    else:
        node.logger.app_log.warning("Status: Not starting a local server to conceal identity on Tor network")


def main_loop():
    """Main event loop"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    node.logger.app_log.warning("Status: Bismuth loop running.")

    try:
        while True:
            if node.IS_STOPPING:
                if node.db_lock.locked():
                    time.sleep(0.5)
                else:
                    mining_heavy3.mining_close()
                    node.logger.app_log.warning(
                        "Status: Securely disconnected main processes, subprocess termination in progress.")
                    break
            time.sleep(0.1)
    except KeyboardInterrupt:
        node.logger.app_log.warning("Status: Interrupted by user")
        node.IS_STOPPING = True
        while node.db_lock.locked():
            time.sleep(0.5)
        mining_heavy3.mining_close()

    node.logger.app_log.warning("Status: Clean Stop")


if __name__ == "__main__":
    try:
        # Initialize components
        config = initialize_node()
        setup_net_type(node, regnet=False)
        load_keys(node)

        # Check Heavy3 file
        node.logger.app_log.warning("Checking Heavy3 file, can take up to 5 minutes...")
        mining_heavy3.mining_open(node.heavy3_path)
        node.logger.app_log.warning("Heavy3 file Ok!")

        node.logger.app_log.warning(f"Status: Starting node version {VERSION}")
        node.startup_time = time.time()

        # Initialize core services
        node.peers = peershandler.Peers(node.logger.app_log, config=config, node=node)
        node.apihandler = apihandler.ApiHandler(node.logger.app_log, config)
        mp.MEMPOOL = mp.Mempool(node.logger.app_log, config, node.db_lock,
                                node.is_testnet, trace_db_calls=node.trace_db_calls)

        # Check integrity and initialize database
        check_integrity(node.hyper_path, node)
        db_handler_initial = initialize_database()

        # Start server
        start_server()

        # Start connection manager
        connection_manager = connectionmanager.ConnectionManager(node, mp)
        connection_manager.start()

        # Run main loop
        main_loop()

    except Exception as e:
        node.logger.app_log.info(e)
        raise