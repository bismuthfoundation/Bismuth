from node import digest_block
from node_utils import blocknf
import sys
import threading
from libs import node, logger, keys, client
import time
import dbhandler
import socks
from connections import send, receive
from decimal import Decimal
from quantizer import quantize_two, quantize_eight, quantize_ten
import mempool as mp
from difficulty import *
from libs import client


class PeerConnection:
    """Handles peer connection and protocol handshake"""

    def __init__(self, host, port, node):
        self.host = host
        self.port = port
        self.node = node
        self.client_id = f"{host}:{port}"
        self.socket = None
        self.peer_ip = None
        self.peer_version = None

    def establish(self):
        """Establish connection with peer and perform handshake"""
        self.socket = socks.socksocket()

        if self.node.tor:
            self.socket.setproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)

        self.socket.connect((self.host, self.port))
        self.node.logger.app_log.info(f"Outbound: Connected to {self.client_id}")

        # Protocol version handshake
        self._verify_protocol()
        self._verify_peer_version()

        send(self.socket, "hello")

        try:
            self.peer_ip = self.socket.getpeername()[0]
        except:
            self.node.logger.app_log.warning("Outbound: Transport endpoint was not connected")
            raise ConnectionError("Failed to get peer IP")

        return self.socket

    def _verify_protocol(self):
        """Verify protocol compatibility"""
        send(self.socket, "version")
        send(self.socket, self.node.version)

        data = receive(self.socket)
        if data != "ok":
            raise ValueError(f"Outbound: Node protocol version of {self.client_id} mismatch")

        self.node.logger.app_log.info(f"Outbound: Node protocol version of {self.client_id} matches our client")

    def _verify_peer_version(self):
        """Get and verify peer version"""
        send(self.socket, "getversion")
        self.peer_version = receive(self.socket)

        if self.peer_version not in self.node.version_allow:
            raise ValueError(f"Outbound: Incompatible peer version {self.peer_version} from {self.client_id}")


class SyncHandler:
    """Handles blockchain synchronization logic"""

    def __init__(self, node, socket, peer_ip, db_handler):
        self.node = node
        self.socket = socket
        self.peer_ip = peer_ip
        self.db = db_handler

    def handle_sync(self):
        """Main sync coordination"""
        self._wait_for_sync_slot()

        try:
            self.node.syncing.append(self.peer_ip)

            local_height = self._exchange_heights()
            remote_height = int(receive(self.socket))

            self.node.logger.app_log.info(
                f"Outbound: Node {self.peer_ip} is at block height: {remote_height}")

            if remote_height < local_height:
                self._handle_lower_peer(remote_height)
            else:
                self._handle_higher_or_equal_peer(remote_height)

        finally:
            if self.peer_ip in self.node.syncing:
                self.node.syncing.remove(self.peer_ip)

    def _wait_for_sync_slot(self):
        """Wait for available sync slot"""
        while len(self.node.syncing) >= 3:
            if self.node.IS_STOPPING:
                raise InterruptedError("Node is stopping")
            time.sleep(int(self.node.pause))

    def _exchange_heights(self):
        """Exchange block heights with peer"""
        send(self.socket, "blockheight")
        local_height = self.node.hdd_block

        self.node.logger.app_log.info(
            f"Outbound: Sending block height to compare: {local_height}")
        send(self.socket, local_height)

        return local_height

    def _handle_lower_peer(self, remote_height):
        """Handle case where peer has lower block height"""
        self.node.logger.app_log.warning(
            f"Outbound: We have a higher block ({self.node.hdd_block}) than {self.peer_ip} ({remote_height}), sending")

        client_hash = receive(self.socket)
        self.node.logger.app_log.info(f"Outbound: Will seek the following block: {client_hash}")

        # Update consensus
        self.node.peers.consensus_add(self.peer_ip, remote_height, self.socket, self.node.hdd_block)

        client_block = self.db.block_height_from_hash(client_hash)

        if not client_block:
            self._handle_block_not_found(client_hash)
        else:
            self._send_blocks(client_block, client_hash)

    def _handle_block_not_found(self, block_hash):
        """Handle case where peer's block is not found"""
        self.node.logger.app_log.warning(f"Outbound: Block {block_hash[:8]} of {self.peer_ip} not found")

        if self.node.full_ledger:
            send(self.socket, "blocknf")
        else:
            send(self.socket, "blocknfhb")
        send(self.socket, block_hash)

        if self.node.peers.warning(self.socket, self.peer_ip, "Forked", 1):
            raise ValueError(f"{self.peer_ip} is banned")

    def _send_blocks(self, client_block, client_hash):
        """Send blocks to peer"""
        self.node.logger.app_log.warning(f"Outbound: Node is at block {client_block}")

        if self.node.hdd_hash == client_hash or not self.node.egress:
            if not self.node.egress:
                self.node.logger.app_log.warning(f"Outbound: Egress disabled for {self.peer_ip}")
                time.sleep(int(self.node.pause))
            else:
                self.node.logger.app_log.info(f"Outbound: Node {self.peer_ip} has the latest block")
            send(self.socket, "nonewblk")
        else:
            blocks_fetched = self.db.blocksync(client_block)
            self.node.logger.app_log.info(f"Outbound: Selected {blocks_fetched}")

            send(self.socket, "blocksfnd")
            confirmation = receive(self.socket)

            if confirmation == "blockscf":
                self.node.logger.app_log.info("Outbound: Client confirmed they want to sync from us")
                send(self.socket, blocks_fetched)
            elif confirmation == "blocksrj":
                self.node.logger.app_log.info(
                    "Outbound: Client rejected to sync from us because we don't have the latest block")

    def _handle_higher_or_equal_peer(self, remote_height):
        """Handle case where peer has higher or equal block height"""
        if remote_height == self.node.hdd_block:
            self.node.logger.app_log.info(
                f"Outbound: We have the same block as {self.peer_ip} ({remote_height}), hash will be verified")
        else:
            self.node.logger.app_log.warning(
                f"Outbound: We have a lower block ({self.node.hdd_block}) than {self.peer_ip} ({remote_height}), hash will be verified")

        self.node.logger.app_log.info(f"Outbound: block_hash to send: {self.node.hdd_hash}")
        send(self.socket, self.node.hdd_hash)

        # Update consensus
        self.node.peers.consensus_add(self.peer_ip, remote_height, self.socket, self.node.hdd_block)


class MessageHandler:
    """Handles incoming messages from peer"""

    def __init__(self, node, socket, peer_ip, db_handler):
        self.node = node
        self.socket = socket
        self.peer_ip = peer_ip
        self.db = db_handler
        self.sync_handler = SyncHandler(node, socket, peer_ip, db_handler)

    def process_message(self, data):
        """Route message to appropriate handler"""
        handlers = {
            "peers": self._handle_peers,
            "sync": self._handle_sync,
            "blocknfhb": self._handle_block_not_found_hb,
            "blocknf": self._handle_block_not_found,
            "blocksfnd": self._handle_blocks_found,
            "nonewblk": self._handle_no_new_block,
            "hyperlane": self._handle_hyperlane,
        }

        handler = handlers.get(data)
        if handler:
            return handler()
        elif data == '*':
            raise ValueError("Broken pipe")
        else:
            raise ValueError(f"Unexpected error, received: {str(data)[:32]}")

    def _handle_peers(self):
        """Handle peers message"""
        subdata = receive(self.socket)
        self.node.peers.peersync(subdata)

    def _handle_sync(self):
        """Handle sync request"""
        self.sync_handler.handle_sync()

    def _handle_block_not_found_hb(self):
        """Handle hyperblock not found"""
        block_hash_delete = receive(self.socket)

        if self._should_process_blocknf():
            blocknf(self.node, block_hash_delete, self.peer_ip, self.db, hyperblocks=True, mp=mp)

            if self.node.peers.warning(self.socket, self.peer_ip, "Rollback", 2):
                raise ValueError(f"{self.peer_ip} is banned")

        sendsync(self.socket, self.peer_ip, "Block not found", self.node)

    def _handle_block_not_found(self):
        """Handle regular block not found"""
        block_hash_delete = receive(self.socket)

        if self._should_process_blocknf():
            blocknf(self.node, block_hash_delete, self.peer_ip, self.db)

            if self.node.peers.warning(self.socket, self.peer_ip, "Rollback", 2):
                raise ValueError(f"{self.peer_ip} is banned")

        sendsync(self.socket, self.peer_ip, "Block not found", self.node)

    def _should_process_blocknf(self):
        """Check if blocknf should be processed based on consensus"""
        # This needs the received_block_height from sync context
        # You might want to store this in the handler state
        return True  # Simplified - implement proper logic

    def _handle_blocks_found(self):
        """Handle blocks found message"""
        self.node.logger.app_log.info(f"Outbound: Node {self.peer_ip} has the block(s)")

        if self.node.db_lock.locked():
            self.node.logger.app_log.warning(f"Skipping sync from {self.peer_ip}, syncing already in progress")
        else:
            self._process_blocks_found()

        sendsync(self.socket, self.peer_ip, "Block found", self.node)

    def _process_blocks_found(self):
        """Process blocks found logic"""
        block_req = self._determine_block_requirement()

        # This needs received_block_height from sync context
        # Simplified version:
        received_block_height = 0  # Should be stored from sync

        if received_block_height >= block_req and received_block_height > self.node.last_block:
            try:
                self.node.logger.app_log.warning(f"Confirming to sync from {self.peer_ip}")
                send(self.socket, "blockscf")
                segments = receive(self.socket)
            except:
                if self.node.peers.warning(self.socket, self.peer_ip, "Failed to deliver the longest chain", 2):
                    raise ValueError(f"{self.peer_ip} is banned")
            else:
                digest_block(self.node, segments, self.socket, self.peer_ip, self.db)
        else:
            send(self.socket, "blocksrj")
            self.node.logger.app_log.warning(
                f"Inbound: Distant peer {self.peer_ip} is at {received_block_height}, "
                f"should be at least {max(block_req, self.node.last_block + 1)}")

    def _determine_block_requirement(self):
        """Determine which block requirement rule to use"""
        if int(self.node.last_block_timestamp) < (time.time() - 600):
            self.node.logger.app_log.warning("Most common block rule triggered")
            return self.node.peers.consensus_most_common
        else:
            self.node.logger.app_log.warning("Longest chain rule triggered")
            return self.node.peers.consensus_max

    def _handle_no_new_block(self):
        """Handle no new block - sync mempool"""
        if mp.MEMPOOL.sendable(self.peer_ip):
            self._sync_mempool()
        sendsync(self.socket, self.peer_ip, "No new block", self.node)

    def _sync_mempool(self):
        """Synchronize mempool with peer"""
        mempool_txs = mp.MEMPOOL.tx_to_send(self.peer_ip)

        # Send our mempool
        send(self.socket, "mempool")
        send(self.socket, mempool_txs)

        # Receive theirs
        segments = receive(self.socket)
        self.node.logger.app_log.info(
            mp.MEMPOOL.merge(segments, self.peer_ip, self.db.c, True))

        # Mark as sent
        mp.MEMPOOL.sent(self.peer_ip)

    def _handle_hyperlane(self):
        """Handle hyperlane message"""
        pass  # Placeholder for hyperlane logic


def sendsync(sdef, peer_ip, status, node):
    """Save peer_ip to peerlist and send `sendsync`

    :param sdef: socket object
    :param peer_ip: IP of peer synchronization has been completed with
    :param status: Status synchronization was completed in/as

    Log the synchronization status
    Wait for database to unlock
    Send `sendsync` command via socket `sdef`

    returns None
    """
    node.logger.app_log.info(
        f"Outbound: Synchronization with {peer_ip} finished after: {status}, sending new sync request")

    time.sleep(node.pause)

    while node.db_lock.locked():
        if node.IS_STOPPING:
            return
        time.sleep(node.pause)

    send(sdef, "sendsync")


def check_peer_eligibility(host, node):
    """Check if peer is eligible for connection"""
    dict_ip = {'ip': host}
    node.plugin_manager.execute_filter_hook('peer_ip', dict_ip)

    if node.peers.is_banned(host) or dict_ip['ip'] == 'banned':
        node.logger.app_log.warning(f"IP {host} is banned, won't connect")
        return False
    return True


def cleanup_connection(node, peer_ip, client_id, socket, error=None):
    """Clean up connection and remove from pools"""
    if error:
        node.logger.app_log.warning(f"Outbound: Disconnected from {client_id}: {error}")
        node.logger.app_log.info(f"Connection to {client_id} terminated due to {error}")

    # Remove from pools
    node.peers.remove_client(client_id)
    node.peers.consensus_remove(peer_ip)

    node.logger.app_log.info(f"---thread {threading.currentThread()} ended---")

    try:
        socket.close()
    except:
        pass


def worker(host, port, node):
    """Main worker thread for peer connection"""
    logger = node.logger
    client_id = f"{host}:{port}"

    if node.IS_STOPPING:
        return

    if not check_peer_eligibility(host, node):
        return

    client_instance_worker = client.Client()
    timeout_operation = 60
    timer_operation = time.time()

    # Establish connection
    try:
        conn = PeerConnection(host, port, node)
        s = conn.establish()
        peer_ip = conn.peer_ip
        peer_version = conn.peer_version
        client_instance_worker.connected = True

    except Exception as e:
        node.logger.app_log.info(f"Could not connect to {client_id}: {e}")
        return

    # Store peer info
    node.peers.store_mainnet(host, peer_version)

    if client_id not in node.peers.connection_pool:
        node.peers.append_client(client_id)
        node.logger.app_log.info(f"Connected to {client_id}")
        node.logger.app_log.info(f"Current active pool: {node.peers.connection_pool}")

    # Check if we should continue
    if (node.peers.is_banned(host) or
            not node.peers.version_allowed(host, node.version_allow) or
            node.IS_STOPPING):
        cleanup_connection(node, peer_ip, client_id, s)
        return

    # Initialize database handler
    db_handler_instance = dbhandler.DbHandler(
        node.index_db, node.ledger_path, node.hyper_path,
        node.ram, node.ledger_ram_file, logger)

    # Message handler
    msg_handler = MessageHandler(node, s, peer_ip, db_handler_instance)

    # Main message loop
    try:
        while (not node.peers.is_banned(host) and
               node.peers.version_allowed(host, node.version_allow) and
               not node.IS_STOPPING):

            # Check timeout
            if time.time() > timer_operation + timeout_operation:
                timer_operation = time.time()

            # Receive and process message
            data = receive(s)
            msg_handler.process_message(data)

    except Exception as e:
        db_handler_instance.close()
        cleanup_connection(node, peer_ip, client_id, s, e)

        if node.debug:
            raise
        else:
            node.logger.app_log.info(f"Ending thread, because {e}")
            return

    # Check version after loop
    if not node.peers.version_allowed(host, node.version_allow):
        node.logger.app_log.warning(
            f"Outbound: Ending thread, because {host} has too old a version: "
            f"{node.peers.ip_to_mainnet[host]}")
        cleanup_connection(node, peer_ip, client_id, s)