# c = hyperblock in ram OR hyperblock file when running only hyperblocks without ram mode on
# h = ledger file or hyperblock clone in hyperblock mode
# h2 = hyperblock file

# never remove the str() conversion in data evaluation or database inserts or you will debug for 14 days as signed types mismatch
# if you raise in the server thread, the server will die and node will stop
# never use codecs, they are bugged and do not provide proper serialization
# must unify node and client now that connections parameters are function parameters
# if you have a block of data and want to insert it into sqlite, you must use a single "commit" for the whole batch, it's 100x faster
# do not isolation_level=None/WAL hdd levels, it makes saving slow
# issues with db? perhaps you missed a commit() or two


# import functools
# import glob
# import shutil
# import sqlite3
# import tarfile
import platform
import socketserver
import threading
from sys import version_info, exc_info
from time import time as ttime, sleep

# moved to DbHandler
# import aliases  # PREFORK_ALIASES
# import aliasesv2 as aliases # POSTFORK_ALIASES

# Bis specific modules
import connectionmanager
import log
import wallet_keys
from connections import send, receive
from digest import *
from bismuthcore.helpers import sanitize_address
from libs import keys, client, mempool as mp
from libs.logger import Logger
from libs.node import Node
from libs.config import Config
from libs.fork import Fork
from libs.dbhandler import DbHandler

import essentials


VERSION = "5.0.7-evo"  # Experimental db-evolution branch

fork = Fork()

appname = "Bismuth"
appauthor = "Bismuth Foundation"


def sql_trace_callback(log, id, statement):
    line = f"SQL[{id}] {statement}"
    log.warning(line)

""" no more needed - see DbHandler.rollback(height)"""
"""
def rollback(node: "Node", db_handler: "DbHandler", block_height: str) -> None:
    node.logger.app_log.warning(f"Status: Rolling back below: {block_height}")
    db_handler.rollback_under(block_height)
    # rollback indices
    db_handler.tokens_rollback(block_height)
    db_handler.aliases_rollback(block_height)
    # rollback indices
    node.logger.app_log.warning(f"Status: Chain rolled back below {block_height} and will be resynchronized")
"""

"""
def balanceget(balance_address, db_handler):
    # EGG_EVO: Multi step refactoring
    # Returns full detailled balance info
    # return str(balance), str(credit_ledger), str(debit), str(fees), str(rewards), str(balance_no_mempool)
    node.logger.app_log.warning("balanceget(balance_address, db_handler) is deprecated, use db_handler.balance_get_full(balance_address, mp.MEMPOOL) instead")
    return db_handler.balance_get_full(balance_address, mp.MEMPOOL)
"""

# TODO: kept for notice, will disappear in a later clean up
"""
def old_balanceget(balance_address, db_handler):
    # TODO: To move in db_handler, call by db_handler.balance_get(address, mp)
    # verify balance

    # node.logger.app_log.info("Mempool: Verifying balance")
    # node.logger.app_log.info("Mempool: Received address: " + str(balance_address))

    base_mempool = mp.MEMPOOL.mp_get(balance_address)

    # include mempool fees

    debit_mempool = 0
    if base_mempool:
        for x in base_mempool:
            debit_tx = Decimal(x[0])
            fee = fee_calculate(x[1], x[2], node.last_block)
            debit_mempool = quantize_eight(debit_mempool + debit_tx + fee)
    else:
        debit_mempool = 0
    # include mempool fees

    credit_ledger = Decimal("0")

    try:
        db_handler._execute_param(db_handler.h, "SELECT amount FROM transactions WHERE recipient = ?;", (balance_address,))
        entries = db_handler.h.fetchall()
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
        db_handler._execute_param(db_handler.h, "SELECT fee, amount FROM transactions WHERE address = ?;", (balance_address,))
        entries = db_handler.h.fetchall()
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
        db_handler._execute_param(db_handler.h, "SELECT reward FROM transactions WHERE recipient = ?;", (balance_address,))
        entries = db_handler.h.fetchall()
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
    # node.logger.app_log.info("Mempool: Projected transction address balance: " + str(balance))
    return str(balance), str(credit_ledger), str(debit), str(fees), str(rewards), str(balance_no_mempool)
"""


def blocknf(node: "Node", block_hash_delete: str, peer_ip: str, db_handler: "DbHandler", hyperblocks: bool=False) -> None:
    # EGG_EVO: To be merged into libs/Node
    """
    Rolls back a single block, updates node object variables.
    Rollback target must be above checkpoint.
    Hash to rollback must match in case our ledger moved.
    Not trusting hyperblock nodes for old blocks because of trimming,
    they wouldn't find the hash and cause rollback.
    """
    node.logger.app_log.info(f"Rollback operation on {block_hash_delete} initiated by {peer_ip}")
    my_time = ttime()
    if not node.db_lock.locked():
        node.db_lock.acquire()
        node.logger.app_log.warning(f"Database lock acquired")
        backup_data = None  # used in "finally" section
        skip = False
        reason = ""

        try:
            block_max_ram = db_handler.last_mining_transaction().to_dict(legacy=True)
            db_block_height = block_max_ram['block_height']
            db_block_hash = block_max_ram['block_hash']

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

                node.logger.app_log.warning(f"Node {peer_ip} didn't find block {db_block_height} ({db_block_hash})")

                # roll back hdd too
                db_handler.rollback_under(db_block_height)
                # /roll back hdd too

                # rollback indices
                db_handler.tokens_rollback(db_block_height)
                db_handler.aliases_rollback(db_block_height)
                # /rollback indices

                node.last_block_timestamp = db_handler.last_block_timestamp()
                node.last_block_hash = db_handler.last_block_hash()
                node.last_block = db_block_height - 1
                node.hdd_hash = db_handler.last_block_hash()
                node.hdd_block = db_block_height - 1
                tokens.tokens_update(node, db_handler)

        except Exception as e:
            if node.config.debug:
                exc_type, exc_obj, exc_tb = exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                node.logger.app_log.warning("{} {} {}".format(exc_type, fname, exc_tb.tb_lineno))
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
                                                     peer_ip, db_handler, size_bypass=False, revert=True))
                                # will get stuck if you change it to respect node.db_lock
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

# TODO: this requestHandler to be renamed and moved into a mfile of its own.
# Then check what can be factorized between it and worker.py
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        # this is a dedicated thread for each client (not ip)
        if node.IS_STOPPING:
            node.logger.app_log.warning("Inbound: Rejected incoming cnx, node is stopping")
            return
        try:
            peer_ip = self.request.getpeername()[0]
        except:
            node.logger.app_log.warning("Inbound: Transport endpoint was not connected")
            return

        # Always keep a slot for whitelisted (wallet could be there)
        if threading.active_count() < node.config.thread_limit / 3 * 2 or node.peers.is_whitelisted(peer_ip):  # inbound
            # Avoid writing hard to read negative condition
            pass
        else:
            try:
                node.logger.app_log.info(f"Free capacity for {peer_ip} unavailable, disconnected")
                self.request.close()
                # if you raise here, you kill the whole server
            except Exception as e:
                node.logger.app_log.warning(f"{e}")
                pass
            finally:
                return

        dict_ip = {'ip': peer_ip}
        node.plugin_manager.execute_filter_hook('peer_ip', dict_ip)
        if node.peers.is_banned(peer_ip) or dict_ip['ip'] == 'banned':
            self.request.close()
            node.logger.app_log.info(f"IP {peer_ip} banned, disconnected")

        # Only now that we handled the exclusions, we can allocate ressources.

        threading.current_thread().name = f"in_{peer_ip}"
        db_handler = DbHandler.from_node(node)
        client_instance = client.Client()
        client_instance.connected = True

        # TODO: I'd like to call
        """
        node.peers.peersync({peer_ip: node.config.port})
        so we can save the peers that connected to us. 
        But not ok in current architecture: would delay the command, and we're not even sure it would be saved.
        TODO: Workaround: make sure our external ip and port is present in the peers we announce, or new nodes are likely never to be announced. 
        Warning: needs public ip/port, not local ones!
        """
        timeout_operation = 120  # timeout
        timer_operation = ttime()  # start counting
        while not node.peers.is_banned(peer_ip) and node.peers.version_allowed(peer_ip, node.config.version_allow) and client_instance.connected:
            try:
                # Failsafe
                if self.request == -1:
                    raise ValueError(f"Inbound: Closed socket from {peer_ip}")

                if not ttime() <= timer_operation + timeout_operation:  # return on timeout
                    if node.peers.warning(self.request, peer_ip, "Operation timeout", 2):
                        node.logger.app_log.info(f"{peer_ip} banned")
                        break

                    raise ValueError(f"Inbound: Operation timeout from {peer_ip}")

                data = receive(self.request)

                node.logger.app_log.info(
                    f"Inbound: Received: {data} from {peer_ip}")  # will add custom ports later

                if data.startswith('regtest_'):
                    if not node.is_regnet:
                        send(self.request, "notok")
                        return
                    else:
                        """db_handler._execute(db_handler.c, "SELECT block_hash FROM transactions WHERE block_height= (select max(block_height) from transactions)")
                        block_hash = db_handler.c.fetchone()[0]
                        # feed regnet with current thread db handle. refactor needed.
                        # EGG: unused regnet.conn, regnet.c, regnet.hdd, regnet.h, regnet.hdd2, regnet.h2, regnet.h = db_handler.conn, db_handler.c, db_handler.hdd, db_handler.h, db_handler.hdd2, db_handler.h2, db_handler.h
                        """
                        block_hash = db_handler.last_mining_transaction().to_dict(legacy=True)["block_hash"]
                        # regnet needs a blockhash to generate new chains. only supported regnet_ command for now is regnet_generate.
                        regnet.command(self.request, data, block_hash, node, db_handler)

                if data == 'version':
                    data = receive(self.request)
                    if data not in node.config.version_allow:
                        node.logger.app_log.warning(
                            f"Protocol version mismatch: {data}, should be {node.config.version_allow}")
                        send(self.request, "notok")
                        return
                    else:
                        node.logger.app_log.warning(f"Inbound: Protocol version matched with {peer_ip}: {data}")
                        send(self.request, "ok")
                        node.peers.store_mainnet(peer_ip, data)

                elif data == 'getversion':
                    send(self.request, node.config.version)

                elif data == 'mempool':

                    # receive theirs
                    segments = receive(self.request)
                    node.logger.app_log.info(mp.MEMPOOL.merge(segments, peer_ip, db_handler, size_bypass=False))
                    # improvement possible - pass peer_ip from worker

                    # receive theirs

                    # _execute_param(m, ('SELECT timestamp,address,recipient,amount,signature,public_key,operation,openfield FROM transactions WHERE timeout < ? ORDER BY amount DESC;'), (int(ttime() - 5),))
                    if mp.MEMPOOL.sendable(peer_ip):
                        # Only send the diff
                        mempool_txs = mp.MEMPOOL.tx_to_send(peer_ip, segments)  # EGG_EVO: we suppose we get legacy tuples there.
                        # and note the time
                        mp.MEMPOOL.sent(peer_ip)
                    else:
                        # We already sent not long ago, send empy
                        mempool_txs = []

                    # send own
                    # node.logger.app_log.info("Inbound: Extracted from the mempool: " + str(mempool_txs))
                    # improve: sync based on signatures only

                    # if len(mempool_txs) > 0: same as the other
                    send(self.request, mempool_txs)

                elif data == "hello":
                    if node.is_regnet:
                        node.logger.app_log.info("Inbound: Got hello but I'm in regtest mode, closing.")
                        return

                    send(self.request, "peers")
                    peers_send = node.peers.peer_list_disk_format()
                    send(self.request, peers_send)

                    while node.db_lock.locked():
                        node.sleep()
                    node.logger.app_log.info("Inbound: Sending sync request")

                    send(self.request, "sync")

                elif data == "sendsync":
                    while node.db_lock.locked():
                        node.sleep()

                    while len(node.syncing) >= 3:
                        node.sleep()

                    send(self.request, "sync")

                elif data == "blocksfnd":
                    node.logger.app_log.info(f"Inbound: Client {peer_ip} has the block(s)")  # node should start sending txs in this step

                    # node.logger.app_log.info("Inbound: Combined segments: " + segments)
                    # print peer_ip
                    if node.db_lock.locked():
                        node.logger.app_log.info(f"Skipping sync from {peer_ip}, syncing already in progress")

                    else:
                        node.last_block_timestamp = db_handler.last_block_timestamp()

                        if node.last_block_timestamp < ttime() - 600:
                            # block_req = most_common(consensus_blockheight_list)
                            block_req = node.peers.consensus_most_common
                            node.logger.app_log.warning("Most common block rule triggered")

                        else:
                            # block_req = max(consensus_blockheight_list)
                            block_req = node.peers.consensus_max
                            node.logger.app_log.warning("Longest chain rule triggered")

                        # Nothing guarantees "received_block_height" has been defined before or is up to date.
                        # Should for a pristine client, but can't make sure.
                        # TODO Egg: Add some state here in the flow, at least a flag.
                        if int(received_block_height) >= block_req and int(received_block_height) > node.last_block:
                            try:  # they claim to have the longest chain, things must go smooth or ban
                                node.logger.app_log.warning(f"Confirming to sync from {peer_ip}")
                                node.plugin_manager.execute_action_hook('sync', {'what': 'syncing_from', 'ip': peer_ip})
                                send(self.request, "blockscf")
                                segments = receive(self.request)
                            except:
                                if node.peers.warning(self.request, peer_ip, "Failed to deliver the longest chain"):
                                    node.logger.app_log.info(f"{peer_ip} banned")
                                    break
                            else:
                                digest_block(node, segments, self.request, peer_ip, db_handler)
                        else:
                            node.logger.app_log.warning(f"Rejecting to sync from {peer_ip}")
                            send(self.request, "blocksrj")
                            node.logger.app_log.info(
                                f"Inbound: Distant peer {peer_ip} is at {received_block_height}, should be at least {max(block_req,node.last_block+1)}")
                    send(self.request, "sync")

                elif data == "blockheight":
                    try:
                        received_block_height = int(receive(self.request))  # receive client's last block height
                        node.logger.app_log.info(
                            f"Inbound: Received block height {received_block_height} from {peer_ip} ")

                        # consensus pool 1 (connection from them)
                        consensus_blockheight = received_block_height  # str int to remove leading zeros
                        # consensus_add(peer_ip, consensus_blockheight, self.request)
                        node.peers.consensus_add(peer_ip, consensus_blockheight, self.request, node.hdd_block)
                        # consensus pool 1 (connection from them)

                        # append zeroes to get static length
                        send(self.request, node.hdd_block)
                        # send own block height

                        if received_block_height > node.hdd_block:
                            node.logger.app_log.warning("Inbound: Client {} has higher block {} vs ours {}"
                                                        .format(peer_ip, received_block_height, node.hdd_block))

                            node.logger.app_log.info(f"Inbound: block_hash to send: {node.hdd_hash}")
                            send(self.request, node.hdd_hash)

                            # receive their latest sha_hash
                            # confirm you know that sha_hash or continue receiving

                        elif received_block_height <= node.hdd_block:
                            if received_block_height == node.hdd_block:
                                node.logger.app_log.info(
                                    f"Inbound: We have the same height as {peer_ip} ({received_block_height}), hash will be verified")
                            else:
                                node.logger.app_log.warning(
                                    f"Inbound: We have higher ({node.hdd_block}) block height than {peer_ip} ({received_block_height}), hash will be verified")

                            data = receive(self.request)  # receive client's last block_hash
                            # send all our followup hashes
                            if data == "*":
                                # connection lost, no need to go on, that was banning the node like it forked.
                                node.logger.app_log.warning(f"Inbound: {peer_ip} dropped connection")
                                break
                            node.logger.app_log.info(f"Inbound: Will seek the following block: {data}")

                            client_block = db_handler.block_height_from_hash(data)
                            if client_block is None:
                                node.logger.app_log.warning(f"Inbound: Block {data[:8]} of {peer_ip} not found")
                                if node.config.full_ledger:
                                    send(self.request, "blocknf")  # announce block hash was not found
                                else:
                                    send(self.request, "blocknfhb")  # announce we are on hyperblocks
                                send(self.request, data)

                                if node.peers.warning(self.request, peer_ip, "Forked", 2):
                                    node.logger.app_log.info(f"{peer_ip} banned")
                                    break

                            else:
                                node.logger.app_log.info(f"Inbound: Client is at block {client_block}")  # now check if we have any newer

                                if node.hdd_hash == data or not node.config.egress:
                                    if node.config.egress:
                                        node.logger.app_log.info(f"Inbound: Client {peer_ip} has the latest block")
                                    else:
                                        node.logger.app_log.warning(f"Inbound: Egress disabled for {peer_ip}")

                                    node.sleep()  # reduce CPU usage
                                    send(self.request, "nonewblk")

                                else:

                                    blocks_fetched = db_handler.blocksync(client_block)

                                    node.logger.app_log.info(f"Inbound: Selected {blocks_fetched}")

                                    send(self.request, "blocksfnd")

                                    confirmation = receive(self.request)

                                    if confirmation == "blockscf":
                                        node.logger.app_log.info("Inbound: Client confirmed they want to sync from us")
                                        send(self.request, blocks_fetched)

                                    elif confirmation == "blocksrj":
                                        node.logger.app_log.info(
                                            "Inbound: Client rejected to sync from us because we're don't have the latest block")

                    except Exception as e:
                        node.logger.app_log.warning(f"Inbound: Sync failed {e}")

                elif data == "nonewblk":
                    send(self.request, "sync")

                elif data == "blocknf":
                    block_hash_delete = receive(self.request)
                    # TODO Egg: Same as above, some state to keep here, consensus_blockheight may be undefined or not up to date.
                    if consensus_blockheight == node.peers.consensus_max:
                        blocknf(node, block_hash_delete, peer_ip, db_handler)
                        if node.peers.warning(self.request, peer_ip, "Rollback", 2):
                            node.logger.app_log.info(f"{peer_ip} banned")
                            break
                    node.logger.app_log.info("Inbound: Deletion complete, sending sync request")

                    while node.db_lock.locked():
                        node.sleep()
                    send(self.request, "sync")

                elif data == "blocknfhb": #node announces it's running hyperblocks
                    block_hash_delete = str(receive(self.request))
                    # print peer_ip
                    if consensus_blockheight == node.peers.consensus_max:
                        blocknf(node, block_hash_delete, peer_ip, db_handler, hyperblocks=True)
                        if node.peers.warning(self.request, peer_ip, "Rollback", 2):
                            node.logger.app_log.info(f"{peer_ip} banned")
                            break
                    node.logger.app_log.info("Inbound: Deletion complete, sending sync request")

                    while node.db_lock.locked():
                        node.sleep()
                    send(self.request, "sync")

                elif data == "block":
                    # if (peer_ip in allowed or "any" in allowed):  # from miner
                    if node.peers.is_allowed(peer_ip, data):  # from miner
                        # TODO: rights management could be done one level higher instead of repeating the same check everywhere
                        node.logger.app_log.info(f"Inbound: Received a block from miner {peer_ip}")
                        # receive block
                        segments = receive(self.request)
                        # node.logger.app_log.info("Inbound: Combined mined segments: " + segments)
                        mined = {"timestamp": ttime(), "last": node.last_block, "ip": peer_ip, "miner": "",
                                 "result": False, "reason": ''}
                        try:
                            mined['miner'] = segments[0][-1][1]  # sender, to be consistent with block event.
                        except:
                            # Block is sent by miners/pools, we can drop the connection
                            # If there is a reason not to, use "continue" here and below instead of returns.
                            return  # missing info, bye
                        if node.is_mainnet:
                            if len(node.peers.connection_pool) < 5 and not node.peers.is_whitelisted(peer_ip):
                                reason = "Inbound: Mined block ignored, insufficient connections to the network"
                                mined['reason'] = reason
                                node.plugin_manager.execute_action_hook('mined', mined)
                                node.logger.app_log.info(reason)
                                return
                            elif node.db_lock.locked():
                                reason = "Inbound: Block from miner skipped because we are digesting already"
                                mined['reason'] = reason
                                node.plugin_manager.execute_action_hook('mined', mined)
                                node.logger.app_log.warning(reason)
                                return
                            elif node.last_block >= node.peers.consensus_max - 3:
                                mined['result'] = True
                                node.plugin_manager.execute_action_hook('mined', mined)
                                node.logger.app_log.info("Inbound: Processing block from miner")
                                try:
                                    digest_block(node, segments, self.request, peer_ip, db_handler)
                                except ValueError as e:
                                    node.logger.app_log.warning("Inbound: block {}".format(str(e)))
                                    return
                                except Exception as e:
                                    node.logger.app_log.error("Inbound: Processing block from miner {}".format(e))
                                    return
                                # This new block may change the int(diff). Trigger the hook whether it changed or not.
                                # node.difficulty = difficulty(node, db_handler_instance)
                            else:
                                reason = f"Inbound: Mined block was orphaned because node was not synced, " \
                                         f"we are at block {node.last_block}, " \
                                         f"should be at least {node.peers.consensus_max - 3}"
                                mined['reason'] = reason
                                node.plugin_manager.execute_action_hook('mined', mined)
                                node.logger.app_log.warning(reason)
                        else:
                            # Not mainnet
                            try:
                                digest_block(node, segments, self.request, peer_ip, db_handler)
                            except ValueError as e:
                                node.logger.app_log.warning("Inbound: block {}".format(str(e)))
                                return
                            except Exception as e:
                                node.logger.app_log.error("Inbound: Processing block from miner {}".format(e))
                                return
                    else:
                        receive(self.request)  # receive block, but do nothing about it
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for block command")

                elif data == "blocklast":
                    # Beware: name is misleading: only sends the miner part of the block! (only one transaction)
                    if node.peers.is_allowed(peer_ip, data):
                        send(self.request, db_handler.last_mining_transaction().to_tuple())
                        """
                        db_handler._execute(db_handler.c, "SELECT * FROM transactions "
                                                                           "WHERE reward != 0 "
                                                                           "ORDER BY block_height DESC LIMIT 1;")
                        block_last = db_handler.c.fetchall()[0]
                        send(self.request, block_last)
                        """
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for blocklast command")

                elif data == "blocklastjson":
                    # Beware: name is misleading: only sends the miner part of the block! (only one transaction)
                    # DOC: possible confusion to be emphasized in the ref. doc.
                    if node.peers.is_allowed(peer_ip, data):
                        # DONE: this will come from a db_handler object, because it has to be independent of the underlying db
                        # something like db_handler.get_last_block(), that returns a Block instance.
                        """
                        db_handler._execute(db_handler.c,
                                                    "SELECT * FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")
                        block_last = db_handler.c.fetchall()[0]
                        transaction = Transaction.from_legacy(block_last)
                        """
                        # EGG_EVO: We now have the required clean method we already use in other places.
                        transaction = db_handler.last_mining_transaction()
                        # TODO: previous version left for comparison, will need clean up.
                        # Was response = {"block_height": block_last[0], .....
                        send(self.request, transaction.to_dict(legacy=True))  # send will convert the dict to json.
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for blocklastjson command")

                elif data == "blockget":
                    if node.peers.is_allowed(peer_ip, data):
                        # see blockgetjson below for more comments
                        block_desired = int(receive(self.request))
                        block = db_handler.get_block(block_desired)
                        send(self.request, block.to_listoftuples())
                        """
                        db_handler._execute_param(db_handler.h, "SELECT * FROM transactions WHERE block_height = ?;",
                                                  (block_desired,))
                        block_desired_result = db_handler.h.fetchall()
                        send(self.request, block_desired_result)
                        """
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for blockget command")

                elif data == "blockgetjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        block_desired = int(receive(self.request))
                        # Egg: param comes from the client, so it makes sense to force cast to int as a sanitization precaution

                        # We can't access _execute nor the private cursor from db_handler (it's db dependent, we have no clue on its format.)
                        # only use its public methods. Here, we need one that sends back a Block (ie, list of transactions)
                        # since we then want legacy dict for the tx list, as well factorize the code and ask the block to give it,
                        """
                        # Previous code kept for comparison
                        db_handler._execute_param(db_handler.h, "SELECT * FROM transactions WHERE block_height = ?;",
                                                  (block_desired,))
                        block_desired_result = db_handler.h.fetchall()
                        transaction_list = []
                        for entry in block_desired_result:
                            transaction = Transaction.from_legacy(entry)
                            transaction_dict = transaction.to_dict(legacy=True)
                            # was response = {"block_height": transaction[0], "timestamp": transaction[1], "address": transaction[2],....                            
                            transaction_list.append(transaction_dict)
                        send(self.request, transaction_list)                            
                        """
                        block = db_handler.get_block(block_desired)
                        send(self.request, block.to_listofdicts(legacy=True))
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for blockget command")

                elif data == "mpinsert":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        mempool_insert = receive(self.request)
                        node.logger.app_log.warning("mpinsert command")
                        mpinsert_result = mp.MEMPOOL.merge(mempool_insert, peer_ip, db_handler, size_bypass=True, wait=True)
                        node.logger.app_log.warning(f"mpinsert result: {mpinsert_result}")
                        send(self.request, mpinsert_result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for mpinsert command")

                elif data == "balanceget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = sanitize_address(receive(self.request))  # for which address? force casted because unsafe user input.
                        balanceget_result = db_handler.balance_get_full(balance_address, mp.MEMPOOL)
                        send(self.request, balanceget_result)  # return balance of the address to the client, including mempool
                    else:
                        node.logger.app_log.info("{peer_ip} not whitelisted for balanceget command")

                elif data == "balancegetjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = sanitize_address(receive(self.request))  # for which address
                        balance_dict = db_handler.balance_get_full(balance_address, mp.MEMPOOL, as_dict=True)
                        send(self.request, balance_dict)  # return balance of the address to the client, including mempool
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for balancegetjson command")

                elif data == "balancegethyper":
                    # EGG: What is the reason for these hyper commands? look like they use the same data source anyway as the regular one.
                    # Can tag as deprecated?
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = sanitize_address(receive(self.request))  # for which address
                        balanceget_result =db_handler.balance_get_full(balance_address, mp.MEMPOOL)[0]
                        send(self.request,balanceget_result)  # return balance of the address to the client, including mempool
                        # send(self.request, balance_pre)  # return balance of the address to the client, no mempool
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for balancegethyper command")

                elif data == "balancegethyperjson":
                    # EGG: What is the reason for these hyper commands? look like they use the same data source anyway as the regular one.
                    # Can tag as deprecated?
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = sanitize_address(receive(self.request))  # for which address
                        balance_dict = db_handler.balance_get_full(balance_address, mp.MEMPOOL, as_dict=True)
                        # response = {"balance": balanceget_result[0]}
                        # EGG_EVO: was using yet another format, used the full dict format as above.
                        send(self.request, balance_dict)  # return balance of the address to the client, including mempool
                        # send(self.request, balance_pre)  # return balance of the address to the client, no mempool
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for balancegethyperjson command")

                elif data == "mpgetjson" and node.peers.is_allowed(peer_ip, data):
                    """
                    # mempool_txs = mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)
                    response_list = []
                    for transaction in mempool_txs:
                        response = {"timestamp": transaction[0],
                                    "address": transaction[1],
                                    "recipient": transaction[2],
                                    "amount": transaction[3],
                                    "signature": transaction[4],
                                    "public_key": transaction[5],
                                    "operation": transaction[6],
                                    "openfield": transaction[7]}

                        response_list.append(response)
                    """
                    mempool_txs = mp.MEMPOOL.transactions_to_send()
                    response_list = [transaction.to_dict(legacy=True) for transaction in mempool_txs]
                    send(self.request, response_list)

                elif data == "mpget" and node.peers.is_allowed(peer_ip, data):
                    # mempool_txs = mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)
                    mempool_txs = mp.MEMPOOL.transactions_to_send()
                    response_tuples = [transaction.to_tuple() for transaction in mempool_txs]
                    send(self.request, response_tuples)

                elif data == "mpclear" and peer_ip == "127.0.0.1":  # reserved for localhost
                    mp.MEMPOOL.clear()

                elif data == "keygen":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = wallet_keys.generate()
                        send(self.request, (gen_private_key_readable, gen_public_key_readable, gen_address))
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = (None, None, None)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for keygen command")

                elif data == "keygenjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = wallet_keys.generate()
                        response = {"private_key": gen_private_key_readable,
                                    "public_key": gen_public_key_readable,
                                    "address": gen_address}

                        send(self.request, response)
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = (None, None, None)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for keygen command")

                elif data == "addlist":
                    # Sends back *ALL* transactions for the provided address. May be excessive.
                    if node.peers.is_allowed(peer_ip, data):
                        address = sanitize_address(receive(self.request))  # user input sanitization
                        """
                        db_handler._execute_param(db_handler.h, (
                            "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC"),
                                                  (address_tx_list, address_tx_list,))
                        result = db_handler.h.fetchall()
                        """
                        transactions = db_handler.transactions_for_address(address, limit=0)
                        result = [transaction.to_tuple() for transaction in transactions]
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlist command")

                elif data == "listlimjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        list_limit = int(receive(self.request))
                        """
                        # print(address_tx_list_limit)
                        db_handler._execute_param(db_handler.h, "SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?",
                                                  (list_limit,))
                        result = db_handler.h.fetchall()

                        transaction_list = []
                        for entry in result:
                            transaction = Transaction.from_legacy(entry)
                            transaction_dict = transaction.to_dict(legacy=True)                          
                            transaction_list.append(transaction_dict)
                        send(self.request, transaction_list)
                        """
                        transactions = db_handler.last_n_transactions(list_limit)
                        send(self.request, [transaction.to_dict(legacy=True) for transaction in transactions])

                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for listlimjson command")

                elif data == "listlim":
                    if node.peers.is_allowed(peer_ip, data):
                        list_limit = int(receive(self.request))
                        transactions = db_handler.last_n_transactions(list_limit)
                        send(self.request, [transaction.to_tuple() for transaction in transactions])
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for listlim command")

                elif data == "addlistlim":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = sanitize_address(receive(self.request))
                        address_tx_list_limit = int(receive(self.request))
                        transactions = db_handler.transactions_for_address(address_tx_list, limit=address_tx_list_limit)
                        # EGG_EVO: instead of handling list comprehension at that high level everywhere , better use a "TransactionList" type - like a block, but not the same semantic,
                        # or a helper to factorize all these dup snippets.
                        result = [transaction.to_tuple() for transaction in transactions]
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlistlim command")

                elif data == "addlistlimjson":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = sanitize_address(receive(self.request))
                        address_tx_list_limit = int(receive(self.request))
                        transactions = db_handler.transactions_for_address(address_tx_list, limit=address_tx_list_limit)
                        # EGG_EVO: instead of handling list comprehension at that high level everywhere , better use a "TransactionList" type - like a block, but not the same semantic,
                        # or a helper to factorize all these dup snippets.
                        result = [transaction.to_dict(legacy=True) for transaction in transactions]
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlistlimjson command")

                elif data == "addlistlimmir":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = sanitize_address(receive(self.request))
                        address_tx_list_limit = int(receive(self.request))
                        transactions = db_handler.transactions_for_address(address_tx_list, limit=address_tx_list_limit, mirror=True)
                        result = [transaction.to_tuple() for transaction in transactions]
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlistlimmir command")

                elif data == "addlistlimmirjson":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = sanitize_address(receive(self.request))
                        address_tx_list_limit = int(receive(self.request))
                        transactions = db_handler.transactions_for_address(address_tx_list, limit=address_tx_list_limit, mirror=True)
                        result = [transaction.to_dict(legacy=True) for transaction in transactions]
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlistlimmir command")

                elif data == "aliasget":  # all for a single address, no protection against overlapping
                    if node.peers.is_allowed(peer_ip, data):
                        db_handler.aliases_update()
                        alias_address = sanitize_address(receive(self.request))
                        send(self.request, db_handler.aliasget(alias_address))
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for aliasget command")

                elif data == "aliasesget":  # only gets the first one, for multiple addresses
                    if node.peers.is_allowed(peer_ip, data):
                        db_handler.aliases_update()
                        aliases_request = receive(self.request)
                        results = db_handler.aliasesget(aliases_request)
                        send(self.request, results)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for aliasesget command")

                # Not mandatory, but may help to reindex with minimal sql queries

                elif data == "tokensget":
                    # TODO: to be handled by token/dbhandler modules, with no sql here in node.
                    if node.peers.is_allowed(peer_ip, data):
                        tokens_address = sanitize_address(receive(self.request))
                        tokens_user = db_handler.tokens_user(tokens_address)

                        tokens_list = []
                        for token in tokens_user:
                            token = token[0]
                            db_handler._execute_param(db_handler.index_cursor,
                                                              "SELECT sum(amount) FROM tokens WHERE recipient = ? AND token = ?;",
                                                      (tokens_address,) + (token,))
                            credit = db_handler.index_cursor.fetchone()[0]
                            db_handler._execute_param(db_handler.index_cursor,
                                                              "SELECT sum(amount) FROM tokens WHERE address = ? AND token = ?;",
                                                      (tokens_address,) + (token,))
                            debit = db_handler.index_cursor.fetchone()[0]

                            debit = 0 if debit is None else debit
                            credit = 0 if credit is None else credit

                            balance = str(Decimal(credit) - Decimal(debit))

                            tokens_list.append((token, balance))

                        send(self.request, tokens_list)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for tokensget command")

                elif data == "addfromalias":
                    if node.peers.is_allowed(peer_ip, data):
                        db_handler.aliases_update()
                        alias_address = receive(self.request)
                        # Egg: we could add an optional "update" boolean flag to addfromalias, that would auto prepend aliases_update.
                        # Avoids line above, and avoids doing the update if we finally get no alias
                        address_fetch = db_handler.addfromalias(alias_address)
                        node.logger.app_log.warning(f"Fetched the following alias address: {address_fetch}")
                        send(self.request, address_fetch)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addfromalias command")

                elif data == "pubkeyget":
                    if node.peers.is_allowed(peer_ip, data):
                        pub_key_address = receive(self.request)
                        target_public_key_b64encoded = db_handler.pubkeyget(pub_key_address)
                        # returns as stored in the DB, that is b64 encoded, except for RSA where it's b64 encoded twice.
                        send(self.request, target_public_key_b64encoded)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for pubkeyget command")

                elif data == "aliascheck":
                    if node.peers.is_allowed(peer_ip, data):
                        reg_string = str(receive(self.request))  # sanitize user input
                        """
                        # EGG_EVO these requests could have been huge (no limit).
                        # Moving to mempool and dbhandler to decouple from low level db format.
                        registered_pending = MEMPOOL.fetchone("SELECT timestamp FROM transactions WHERE openfield = ?;", ("alias=" + reg_string,))
                        db_handler._execute_param(db_handler.h, "SELECT timestamp FROM transactions WHERE openfield = ?;", ("alias=" + reg_string,))
                        registered_already = db_handler.h.fetchone()
                        """
                        # Egg: No prior db_handler.aliases_update() here? could be needed
                        registered_pending = mp.MEMPOOL.alias_exists(reg_string)  # this will lookup from mp transactions
                        registered_already = db_handler.alias_exists(reg_string)  # this looks up in alias table, faster.
                        if not registered_already and not registered_pending:
                            send(self.request, "Alias free")
                        else:
                            send(self.request, "Alias registered")
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for aliascheck command")

                elif data == "txsend":
                    """
                    This is most unsafe and should never be used.
                    - node gets the privkey
                    - dup code for assembling and signing the TX
                    TODO: DEPRECATED
                    """
                    # TODO: To remove.
                    if node.peers.is_allowed(peer_ip, data):
                        send(self.request, "txsend is unsafe and deprecated, please don't use.")
                        node.logger.app_log.warning("txsend is unsafe and deprecated, please don't use.")
                        """
                        tx_remote = receive(self.request)

                        # receive data necessary for remote tx construction
                        remote_tx_timestamp = tx_remote[0]
                        remote_tx_privkey = tx_remote[1]
                        remote_tx_recipient = tx_remote[2]
                        remote_tx_amount = tx_remote[3]
                        remote_tx_operation = tx_remote[4]
                        remote_tx_openfield = tx_remote[5]
                        # receive data necessary for remote tx construction

                        # derive remaining data
                        tx_remote_key = RSA.importKey(remote_tx_privkey)
                        remote_tx_pubkey = tx_remote_key.publickey().exportKey().decode("utf-8")

                        remote_tx_pubkey_b64encoded = base64.b64encode(remote_tx_pubkey.encode('utf-8')).decode("utf-8")

                        remote_tx_address = hashlib.sha224(remote_tx_pubkey.encode("utf-8")).hexdigest()
                        # derive remaining data

                        # construct tx
                        remote_tx = (str(remote_tx_timestamp), str(remote_tx_address), str(remote_tx_recipient),
                                     '%.8f' % quantize_eight(remote_tx_amount), str(remote_tx_operation),
                                     str(remote_tx_openfield))  # this is signed

                        remote_hash = SHA.new(str(remote_tx).encode("utf-8"))
                        remote_signer = PKCS1_v1_5.new(tx_remote_key)
                        remote_signature = remote_signer.sign(remote_hash)
                        remote_signature_enc = base64.b64encode(remote_signature).decode("utf-8")
                        # construct tx

                        # insert to mempool, where everything will be verified
                        mempool_data = ((str(remote_tx_timestamp), str(remote_tx_address), str(remote_tx_recipient),
                                         '%.8f' % quantize_eight(remote_tx_amount), str(remote_signature_enc),
                                         str(remote_tx_pubkey_b64encoded), str(remote_tx_operation),
                                         str(remote_tx_openfield)))

                        node.logger.app_log.info(mp.MEMPOOL.merge(mempool_data, peer_ip, db_handler.c, True, True))

                        send(self.request, str(remote_signature_enc))
                        # wipe variables
                        (tx_remote, remote_tx_privkey, tx_remote_key) = (None, None, None)
                        """
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for txsend command")

                # less important methods
                elif data == "addvalidate":
                    if node.peers.is_allowed(peer_ip, data):
                        address_to_validate = receive(self.request)
                        if essentials.address_validate(address_to_validate):
                            result = "valid"
                        else:
                            result = "invalid"
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addvalidate command")

                elif data == "annget":
                    if node.peers.is_allowed(peer_ip):
                        result = db_handler.annget(node.config.genesis)
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for annget command")

                elif data == "annverget":
                    if node.peers.is_allowed(peer_ip):
                        result = db_handler.annverget(node.config.genesis)
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for annget command")

                elif data == "peersget":
                    if node.peers.is_allowed(peer_ip, data):
                        send(self.request, node.peers.peer_list_disk_format())
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for peersget command")

                elif data == "statusget":
                    if node.peers.is_allowed(peer_ip, data):
                        nodes_count = node.peers.consensus_size
                        nodes_list = node.peers.peer_opinion_dict
                        threads_count = threading.active_count()
                        uptime = int(ttime() - node.startup_time)
                        diff = node.difficulty
                        server_timestamp = '%.2f' % ttime()
                        if node.config.reveal_address:
                            revealed_address = node.keys.address
                        else:
                            revealed_address = "private"
                        send(self.request, (
                            revealed_address, nodes_count, nodes_list, threads_count, uptime, node.peers.consensus,
                            node.peers.consensus_percentage, VERSION, diff, server_timestamp))
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for statusget command")

                elif data == "statusjson":
                    # not only sends as an explicit dict, but also embeds extra info
                    if node.peers.is_allowed(peer_ip, data):
                        uptime = int(ttime() - node.startup_time)
                        tempdiff = node.difficulty
                        if node.config.reveal_address:
                            revealed_address = node.keys.address
                        else:
                            revealed_address = "private"
                        status = {"protocolversion": node.config.version,
                                  "address": revealed_address,
                                  "walletversion": VERSION,
                                  "testnet": node.is_testnet,
                                  "blocks": node.hdd_block, "timeoffset": 0,
                                  "connections": node.peers.consensus_size,
                                  "connections_list": node.peers.peer_opinion_dict,
                                  "difficulty": tempdiff[0],
                                  "threads": threading.active_count(),
                                  "uptime": uptime, "consensus": node.peers.consensus,
                                  "consensus_percent": node.peers.consensus_percentage,
                                  "python_version": str(version_info[:3]),
                                  "last_block_ago": node.last_block_ago,
                                  "server_timestamp": '%.2f' % ttime()}
                        if node.is_regnet:
                            status['regnet'] = True
                        send(self.request, status)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for statusjson command")
                elif data[:4] == 'api_':
                    if node.peers.is_allowed(peer_ip, data):
                        try:
                            node.apihandler.dispatch(data, self.request, db_handler, node.peers)
                        except Exception as e:
                            if node.config.debug:
                                raise
                            else:
                                node.logger.app_log.warning(e)

                elif data == "diffget":
                    if node.peers.is_allowed(peer_ip, data):
                        diff = node.difficulty
                        send(self.request, diff)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for diffget command")

                elif data == "portget":
                    if node.peers.is_allowed(peer_ip, data):
                        send(self.request, {"port": node.config.port})
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for portget command")

                elif data == "diffgetjson":
                    if node.peers.is_allowed(peer_ip, data):
                        diff = node.difficulty
                        response = {"difficulty": diff[0],
                                    "diff_dropped": diff[1],
                                    "time_to_generate": diff[2],
                                    "diff_block_previous": diff[3],
                                    "block_time": diff[4],
                                    "hashrate": diff[5],
                                    "diff_adjustment": diff[6],
                                    "block_height": diff[7]}

                        send(self.request, response)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for diffgetjson command")

                elif data == "difflast":
                    if node.peers.is_allowed(peer_ip, data):
                        difflast = db_handler.difflast()

                        send(self.request, difflast)
                    else:
                        node.logger.app_log.info("f{peer_ip} not whitelisted for difflastget command")

                elif data == "difflastjson":
                    if node.peers.is_allowed(peer_ip, data):

                        difflast = db_handler.difflast()
                        response = {"block": difflast[0],
                                    "difficulty": difflast[1]
                                    }
                        send(self.request, response)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for difflastjson command")

                elif data == "stop":
                    if node.peers.is_allowed(peer_ip, data):
                        node.logger.app_log.warning(f"Received stop from {peer_ip}")
                        node.IS_STOPPING = True
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for stop command")

                elif data == "block_height_from_hash":
                    if node.peers.is_allowed(peer_ip, data):
                        hash = receive(self.request)
                        response = db_handler.block_height_from_hash(hash)
                        send(self.request, response)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for block_height_from_hash command")

                elif data == "addpeers":
                    if node.peers.is_allowed(peer_ip, data):
                        data = receive(self.request)
                        # peersync expects a dict encoded as json string, not a straight dict
                        try:
                            res = node.peers.peersync(data)
                        except:
                            node.logger.app_log.warning(f"{peer_ip} sent invalid peers list")
                            raise
                        send(self.request, {"added": res})
                        node.logger.app_log.warning(f"{res} peers added")
                    else:
                        node.logger.app_log.warning(f"{peer_ip} not whitelisted for addpeers")

                else:
                    if data == '*':
                        raise ValueError("Broken pipe")

                    extra = False  # This is the entry point for all extra commands from plugins
                    for prefix, callback in extra_commands.items():
                        if data.startswith(prefix):
                            extra = True
                            callback(data, self.request)

                    if not extra:
                        raise ValueError("Unexpected error, received: " + str(data)[:32] + ' ...')

                if not ttime() <= timer_operation + timeout_operation:
                    timer_operation = ttime()  # reset timer
                # node.sleep()
                # sleep(float(node.config.pause))  # prevent cpu overload
                node.logger.app_log.info(f"Server loop finished for {peer_ip}")

            except Exception as e:
                node.logger.app_log.info(f"Inbound: Lost connection to {peer_ip}")
                node.logger.app_log.info(f"Inbound: {e}")
                # remove from consensus (connection from them)
                node.peers.consensus_remove(peer_ip)
                # remove from consensus (connection from them)
                self.request.close()
                if node.config.debug:
                    if "Socket EOF" not in str(e) and "Broken pipe" not in str(e) and "Socket POLLHUP" not in str(e) and "Bad file descriptor" not in str(e):
                        # raise if debug, but not for innocuous closed pipes.
                        raise  # major debug client
                return

        if not node.peers.version_allowed(peer_ip, node.config.version_allow):
            node.logger.app_log.warning(f"Inbound: Closing connection to old {peer_ip} node: {node.peers.ip_to_mainnet[peer_ip]}")
        return


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    config = Config()  # config.read() is now implicit at instanciation
    logger = Logger()  # is that class really useful?
    logger.app_log = log.log("node.log", config.debug_level, config.terminal_output)
    logger.app_log.warning("Configuration settings loaded")
    # Pre-node tweaks
    # upgrade wallet location after nuitka-required "files" folder introduction
    if os.path.exists("../wallet.der") and not os.path.exists("wallet.der") and "Windows" in platform.system():
        print("Upgrading wallet location")
        os.rename("../wallet.der", "wallet.der")
    # upgrade wallet location after nuitka-required "files" folder introduction

    # Will start node init sequence
    # Node instanciation is now responsible for lots of things that were previously done here or below
    node = Node(digest_block, config,  app_version=VERSION, logger=logger, keys=keys.Keys())
    node.logger.app_log.warning(f"Python version: {node.py_version}")

    try:
        # get the potential extra command prefixes from plugin
        extra_commands = {}  # global var, used by the server part.
        extra_commands = node.plugin_manager.execute_filter_hook('extra_commands_prefixes', extra_commands)
        node.logger.app_log.warning("Extra prefixes: " + ",".join(extra_commands.keys()))

        node.logger.app_log.warning(f"Status: Starting node version {VERSION}")
        node.startup_time = ttime()
        try:
            mp.MEMPOOL = mp.Mempool(node)
            # Until here, we were in single user mode.

            # EGG_EVO: Is this just used once for initial sync?
            db_handler_initial = DbHandler.from_node(node)
            node.node_block_init(db_handler_initial)  # Egg: to be called after single user mode only

            if node.config.tor:
                node.logger.app_log.warning("Status: Not starting a local server to conceal identity on Tor network")
            else:
                # Port 0 means to select an arbitrary unused port
                host, port = "0.0.0.0", int(node.config.port)

                ThreadedTCPServer.allow_reuse_address = True
                ThreadedTCPServer.daemon_threads = True
                ThreadedTCPServer.timeout = 60
                ThreadedTCPServer.request_queue_size = 100

                server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
                ip, node.config.port = server.server_address

                # Start a thread with the server -- that thread will then start one
                # more thread for each request
                server_thread = threading.Thread(target=server.serve_forever)
                server_thread.daemon = True
                server_thread.start()
                node.logger.app_log.warning("Status: Server loop running.")

            # start connection manager
            connection_manager = connectionmanager.ConnectionManager(node, mp.MEMPOOL)
            connection_manager.start()
            # start connection manager

        except Exception as e:
            node.logger.app_log.info(e)
            raise

    except Exception as e:
        node.logger.app_log.info(e)
        raise

    node.logger.app_log.warning("Status: Bismuth loop running.")

    while True:
        if node.IS_STOPPING:
            if not node.db_lock.locked():
                mining_heavy3.mining_close()
                node.logger.app_log.warning("Status: Securely disconnected main processes, "
                                            "subprocess termination in progress.")
                break
        sleep(0.5)
    node.logger.app_log.warning("Status: Clean Stop")
