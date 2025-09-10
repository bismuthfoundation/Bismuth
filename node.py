from utils import blocknf, sequencing_check, sql_trace_callback, bootstrap, check_integrity, balanceget, \
    ledger_check_heights, recompress_ledger

from utils import add_indices, verify


VERSION = "4.5.0.1"

import functools
import glob
import platform
import shutil
import socketserver
import sqlite3
import tarfile
import threading
from sys import version_info

import aliases  # PREFORK_ALIASES
# import aliasesv2 as aliases # POSTFORK_ALIASES

# Bis specific modules
import apihandler
import connectionmanager
import dbhandler
import log
import options
import peershandler
import plugins
# import tokensv2 as tokens  # TODO: unused here
import wallet_keys
from connections import send, receive
from digest import *
from essentials import download_file
from libs import node, logger, keys, client
from fork import Fork

# todo: migrate this to polysign\signer_crw.py
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
import base64
# /todo

fork = Fork()

appname = "Bismuth"
appauthor = "Bismuth Foundation"

# nodes_ban_reset=config.nodes_ban_reset


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # this is a dedicated thread for each client (not ip)
        if node.IS_STOPPING:
            node.logger.app_log.warning("Inbound: Rejected incoming cnx, node is stopping")
            return

        db_handler_instance = dbhandler.DbHandler(node.index_db, node.ledger_path, node.hyper_path, node.ram, node.ledger_ram_file, node.logger, trace_db_calls=node.trace_db_calls)

        client_instance = client.Client()

        try:
            peer_ip = self.request.getpeername()[0]
        except:
            node.logger.app_log.warning("Inbound: Transport endpoint was not connected")
            return

        threading.current_thread().name = f"in_{peer_ip}"
        # if threading.active_count() < node.thread_limit or peer_ip == "127.0.0.1":
        # Always keep a slot for whitelisted (wallet could be there)
        if threading.active_count() < node.thread_limit / 3 * 2 or node.peers.is_whitelisted(peer_ip):  # inbound
            client_instance.connected = True
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

        # TODO: I'd like to call
        """
        node.peers.peersync({peer_ip: node.port})
        so we can save the peers that connected to us. 
        But not ok in current architecture: would delay the command, and we're not even sure it would be saved.
        TODO: Workaround: make sure our external ip and port is present in the peers we announce, or new nodes are likely never to be announced. 
        Warning: needs public ip/port, not local ones!
        """

        timeout_operation = 120  # timeout
        timer_operation = time.time()  # start counting

        while not node.peers.is_banned(peer_ip) and node.peers.version_allowed(peer_ip, node.version_allow) and client_instance.connected:
            try:
                extra = False  # Flag for plugin and regtest_* commands
                # Failsafe
                if self.request == -1:
                    raise ValueError(f"Inbound: Closed socket from {peer_ip}")

                if not time.time() <= timer_operation + timeout_operation:  # return on timeout
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
                        db_handler_instance.execute(db_handler_instance.c, "SELECT block_hash FROM transactions WHERE block_height= (select max(block_height) from transactions)")
                        block_hash = db_handler_instance.c.fetchone()[0]
                        # feed regnet with current thread db handle. refactor needed.
                        regnet.conn, regnet.c, regnet.hdd, regnet.h, regnet.hdd2, regnet.h2, regnet.h = db_handler_instance.conn, db_handler_instance.c, db_handler_instance.hdd, db_handler_instance.h, db_handler_instance.hdd2, db_handler_instance.h2, db_handler_instance.h
                        regnet.command(self.request, data, block_hash, node, db_handler_instance)
                    # Set extra flag or the regtest_* command will thrown an exception
                    extra = True

                if data == 'version':
                    data = receive(self.request)
                    if data not in node.version_allow:
                        node.logger.app_log.warning(
                            f"Protocol version mismatch: {data}, should be {node.version_allow}")
                        send(self.request, "notok")
                        return
                    else:
                        node.logger.app_log.warning(f"Inbound: Protocol version matched with {peer_ip}: {data}")
                        send(self.request, "ok")
                        node.peers.store_mainnet(peer_ip, data)

                elif data == 'getversion':
                    send(self.request, node.version)

                elif data == 'mempool':

                    # receive theirs
                    segments = receive(self.request)
                    node.logger.app_log.info(mp.MEMPOOL.merge(segments, peer_ip, db_handler_instance.c, False))
                    #improvement possible - pass peer_ip from worker

                    # receive theirs

                    # execute_param(m, ('SELECT timestamp,address,recipient,amount,signature,public_key,operation,openfield FROM transactions WHERE timeout < ? ORDER BY amount DESC;'), (int(time.time() - 5),))
                    if mp.MEMPOOL.sendable(peer_ip):
                        # Only send the diff
                        mempool_txs = mp.MEMPOOL.tx_to_send(peer_ip, segments)
                        # and note the time
                        mp.MEMPOOL.sent(peer_ip)
                    else:
                        # We already sent not long ago, send empy
                        mempool_txs = []

                    # send own
                    # node.logger.app_log.info("Inbound: Extracted from the mempool: " + str(mempool_txs))  # improve: sync based on signatures only

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
                        time.sleep(quantize_two(node.pause))
                    node.logger.app_log.info("Inbound: Sending sync request")

                    send(self.request, "sync")

                elif data == "sendsync":
                    while node.db_lock.locked():
                        time.sleep(quantize_two(node.pause))

                    while len(node.syncing) >= 3:
                        time.sleep(int(node.pause))

                    send(self.request, "sync")

                elif data == "blocksfnd":
                    node.logger.app_log.info(f"Inbound: Client {peer_ip} has the block(s)")  # node should start sending txs in this step

                    # node.logger.app_log.info("Inbound: Combined segments: " + segments)
                    # print peer_ip
                    if node.db_lock.locked():
                        node.logger.app_log.info(f"Skipping sync from {peer_ip}, syncing already in progress")

                    else:
                        node.last_block_timestamp = db_handler_instance.last_block_timestamp()

                        if node.last_block_timestamp < time.time() - 600:
                            # block_req = most_common(consensus_blockheight_list)
                            block_req = node.peers.consensus_most_common
                            node.logger.app_log.warning("Most common block rule triggered")

                        else:
                            # block_req = max(consensus_blockheight_list)
                            block_req = node.peers.consensus_max
                            node.logger.app_log.warning("Longest chain rule triggered")

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
                                digest_block(node, segments, self.request, peer_ip, db_handler_instance)
                        else:
                            node.logger.app_log.warning(f"Rejecting to sync from {peer_ip}")
                            send(self.request, "blocksrj")
                            node.logger.app_log.info(
                                f"Inbound: Distant peer {peer_ip} is at {received_block_height}, should be at least {max(block_req,node.last_block+1)}")
                    send(self.request, "sync")

                elif data == "blockheight":
                    try:
                        received_block_height = receive(self.request)  # receive client's last block height
                        node.logger.app_log.info(
                            f"Inbound: Received block height {received_block_height} from {peer_ip} ")

                        # consensus pool 1 (connection from them)
                        consensus_blockheight = int(received_block_height)  # str int to remove leading zeros
                        # consensus_add(peer_ip, consensus_blockheight, self.request)
                        node.peers.consensus_add(peer_ip, consensus_blockheight, self.request, node.hdd_block)
                        # consensus pool 1 (connection from them)

                        # append zeroes to get static length
                        send(self.request, node.hdd_block)
                        # send own block height

                        if int(received_block_height) > node.hdd_block:
                            node.logger.app_log.warning("Inbound: Client has higher block")

                            node.logger.app_log.info(f"Inbound: block_hash to send: {node.hdd_hash}")
                            send(self.request, node.hdd_hash)

                            # receive their latest sha_hash
                            # confirm you know that sha_hash or continue receiving

                        elif int(received_block_height) <= node.hdd_block:
                            if int(received_block_height) == node.hdd_block:
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

                            client_block = db_handler_instance.block_height_from_hash(data)
                            if client_block is None:
                                node.logger.app_log.warning(f"Inbound: Block {data[:8]} of {peer_ip} not found")
                                if node.full_ledger:
                                    send(self.request, "blocknf")  # announce block hash was not found
                                else:
                                    send(self.request, "blocknfhb")  # announce we are on hyperblocks
                                send(self.request, data)

                                if node.peers.warning(self.request, peer_ip, "Forked", 2):
                                    node.logger.app_log.info(f"{peer_ip} banned")
                                    break

                            else:
                                node.logger.app_log.info(f"Inbound: Client is at block {client_block}")  # now check if we have any newer

                                if node.hdd_hash == data or not node.egress:
                                    if not node.egress:
                                        node.logger.app_log.warning(f"Inbound: Egress disabled for {peer_ip}")
                                    else:
                                        node.logger.app_log.info(f"Inbound: Client {peer_ip} has the latest block")

                                    time.sleep(int(node.pause))  # reduce CPU usage
                                    send(self.request, "nonewblk")

                                else:

                                    blocks_fetched = db_handler_instance.blocksync(client_block)

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
                    # print peer_ip
                    if consensus_blockheight == node.peers.consensus_max:
                        blocknf(node, block_hash_delete, peer_ip, db_handler_instance, mp=mp, tokens=tokens)
                        if node.peers.warning(self.request, peer_ip, "Rollback", 2):
                            node.logger.app_log.info(f"{peer_ip} banned")
                            break
                    node.logger.app_log.info("Inbound: Deletion complete, sending sync request")

                    while node.db_lock.locked():
                        time.sleep(node.pause)
                    send(self.request, "sync")

                elif data == "blocknfhb": #node announces it's running hyperblocks
                    block_hash_delete = receive(self.request)
                    # print peer_ip
                    if consensus_blockheight == node.peers.consensus_max:
                        blocknf(node, block_hash_delete, peer_ip, db_handler_instance, hyperblocks=True, mp=mp, tokens=tokens)
                        if node.peers.warning(self.request, peer_ip, "Rollback", 2):
                            node.logger.app_log.info(f"{peer_ip} banned")
                            break
                    node.logger.app_log.info("Inbound: Deletion complete, sending sync request")

                    while node.db_lock.locked():
                        time.sleep(node.pause)
                    send(self.request, "sync")

                elif data == "block":
                    # if (peer_ip in allowed or "any" in allowed):  # from miner
                    if node.peers.is_allowed(peer_ip, data):  # from miner
                        # TODO: rights management could be done one level higher instead of repeating the same check everywhere
                        node.logger.app_log.info(f"Inbound: Received a block from miner {peer_ip}")
                        # receive block
                        segments = receive(self.request)
                        # node.logger.app_log.info("Inbound: Combined mined segments: " + segments)
                        mined = {"timestamp": time.time(), "last": node.last_block, "ip": peer_ip, "miner": "",
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
                                    digest_block(node, segments, self.request, peer_ip, db_handler_instance)
                                except ValueError as e:
                                    node.logger.app_log.warning("Inbound: block {}".format(str(e)))
                                    return
                                except Exception as e:
                                    node.logger.app_log.error("Inbound: Processing block from miner {}".format(e))
                                    return
                                # This new block may change the int(diff). Trigger the hook whether it changed or not.
                                #node.difficulty = difficulty(node, db_handler_instance)
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
                                digest_block(node, segments, self.request, peer_ip, db_handler_instance)
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
                    # if (peer_ip in allowed or "any" in allowed):  # only sends the miner part of the block!
                    if node.peers.is_allowed(peer_ip, data):
                        db_handler_instance.execute(db_handler_instance.c, "SELECT * FROM transactions "
                                                                           "WHERE reward != 0 "
                                                                           "ORDER BY block_height DESC LIMIT 1;")
                        block_last = db_handler_instance.c.fetchall()[0]

                        send(self.request, block_last)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for blocklast command")

                elif data == "blocklastjson":
                    # if (peer_ip in allowed or "any" in allowed):  # only sends the miner part of the block!
                    if node.peers.is_allowed(peer_ip, data):
                        db_handler_instance.execute(db_handler_instance.c,
                                                    "SELECT * FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")
                        block_last = db_handler_instance.c.fetchall()[0]

                        response = {"block_height": block_last[0],
                                    "timestamp": block_last[1],
                                    "address": block_last[2],
                                    "recipient": block_last[3],
                                    "amount": block_last[4],
                                    "signature": block_last[5],
                                    "public_key": block_last[6],
                                    "block_hash": block_last[7],
                                    "fee": block_last[8],
                                    "reward": block_last[9],
                                    "operation": block_last[10],
                                    "nonce": block_last[11]}

                        send(self.request, response)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for blocklastjson command")

                elif data == "blockget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        block_desired = receive(self.request)

                        db_handler_instance.execute_param(db_handler_instance.h, "SELECT * FROM transactions WHERE block_height = ?;",
                                                          (block_desired,))
                        block_desired_result = db_handler_instance.h.fetchall()

                        send(self.request, block_desired_result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for blockget command")

                elif data == "blockgetjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        block_desired = receive(self.request)

                        db_handler_instance.execute_param(db_handler_instance.h, "SELECT * FROM transactions WHERE block_height = ?;",
                                                          (block_desired,))
                        block_desired_result = db_handler_instance.h.fetchall()

                        response_list = []
                        for transaction in block_desired_result:
                            response = {"block_height": transaction[0],
                                        "timestamp": transaction[1],
                                        "address": transaction[2],
                                        "recipient": transaction[3],
                                        "amount": transaction[4],
                                        "signature": transaction[5],
                                        "public_key": transaction[6],
                                        "block_hash": transaction[7],
                                        "fee": transaction[8],
                                        "reward": transaction[9],
                                        "operation": transaction[10],
                                        "openfield": transaction[11]}

                            response_list.append(response)

                        send(self.request, response_list)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for blockget command")

                elif data == "mpinsert":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        mempool_insert = receive(self.request)
                        node.logger.app_log.warning("mpinsert command")
                        mpinsert_result = mp.MEMPOOL.merge(mempool_insert, peer_ip, db_handler_instance.c, True, True)
                        node.logger.app_log.warning(f"mpinsert result: {mpinsert_result}")
                        send(self.request, mpinsert_result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for mpinsert command")

                elif data == "balanceget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = receive(self.request)  # for which address

                        balanceget_result = balanceget(balance_address, db_handler_instance, mp, node)

                        send(self.request,
                                         balanceget_result)  # return balance of the address to the client, including mempool
                        # send(self.request, balance_pre)  # return balance of the address to the client, no mempool
                    else:
                        node.logger.app_log.info("{peer_ip} not whitelisted for balanceget command")

                elif data == "balancegetjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = receive(self.request)  # for which address

                        balanceget_result = balanceget(balance_address, db_handler_instance, mp, node)
                        response = {"balance": balanceget_result[0],
                                    "credit": balanceget_result[1],
                                    "debit": balanceget_result[2],
                                    "fees": balanceget_result[3],
                                    "rewards": balanceget_result[4],
                                    "balance_no_mempool": balanceget_result[5]}

                        send(self.request,
                                         response)  # return balance of the address to the client, including mempool
                        # send(self.request, balance_pre)  # return balance of the address to the client, no mempool
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for balancegetjson command")

                elif data == "balancegethyper":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = receive(self.request)  # for which address

                        balanceget_result = balanceget(balance_address, db_handler_instance, mp, node)[0]

                        send(self.request,
                                         balanceget_result)  # return balance of the address to the client, including mempool
                        # send(self.request, balance_pre)  # return balance of the address to the client, no mempool
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for balancegetjson command")

                elif data == "balancegethyperjson":
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = receive(self.request)  # for which address

                        balanceget_result = balanceget(balance_address, db_handler_instance, mp, node)
                        response = {"balance": balanceget_result[0]}

                        send(self.request,
                                         response)  # return balance of the address to the client, including mempool
                        # send(self.request, balance_pre)  # return balance of the address to the client, no mempool
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for balancegethyperjson command")

                elif data == "mpgetjson" and node.peers.is_allowed(peer_ip, data):
                    mempool_txs = mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)

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

                    # node.logger.app_log.info("Inbound: Extracted from the mempool: " + str(mempool_txs))  # improve: sync based on signatures only

                    # if len(mempool_txs) > 0: #wont sync mempool until we send something, which is bad
                    # send own
                    send(self.request, response_list)

                elif data == "mpget" and node.peers.is_allowed(peer_ip, data):
                    mempool_txs = mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)

                    # node.logger.app_log.info("Inbound: Extracted from the mempool: " + str(mempool_txs))  # improve: sync based on signatures only

                    # if len(mempool_txs) > 0: #wont sync mempool until we send something, which is bad
                    # send own
                    send(self.request, mempool_txs)

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
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        db_handler_instance.execute_param(db_handler_instance.h, (
                            "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC"),
                                                          (address_tx_list, address_tx_list,))
                        result = db_handler_instance.h.fetchall()
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlist command")

                elif data == "listlimjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        list_limit = receive(self.request)
                        # print(address_tx_list_limit)
                        db_handler_instance.execute_param(db_handler_instance.h, "SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?",
                                                          (list_limit,))
                        result = db_handler_instance.h.fetchall()

                        response_list = []
                        for transaction in result:
                            response = {"block_height": transaction[0],
                                        "timestamp": transaction[1],
                                        "address": transaction[2],
                                        "recipient": transaction[3],
                                        "amount": transaction[4],
                                        "signature": transaction[5],
                                        "public_key": transaction[6],
                                        "block_hash": transaction[7],
                                        "fee": transaction[8],
                                        "reward": transaction[9],
                                        "operation": transaction[10],
                                        "openfield": transaction[11]}

                            response_list.append(response)

                        send(self.request, response_list)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for listlimjson command")

                elif data == "listlim":
                    if node.peers.is_allowed(peer_ip, data):
                        list_limit = receive(self.request)
                        # print(address_tx_list_limit)
                        db_handler_instance.execute_param(db_handler_instance.h, "SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?",
                                                          (list_limit,))
                        result = db_handler_instance.h.fetchall()
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for listlim command")

                elif data == "addlistlim":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        address_tx_list_limit = receive(self.request)

                        # print(address_tx_list_limit)
                        db_handler_instance.execute_param(db_handler_instance.h, (
                            "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC LIMIT ?"),
                                                          (address_tx_list, address_tx_list, address_tx_list_limit,))
                        result = db_handler_instance.h.fetchall()
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlistlim command")

                elif data == "addlistlimjson":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        address_tx_list_limit = receive(self.request)

                        # print(address_tx_list_limit)
                        db_handler_instance.execute_param(db_handler_instance.h, (
                            "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC LIMIT ?"),
                                                          (address_tx_list, address_tx_list, address_tx_list_limit,))
                        result = db_handler_instance.h.fetchall()

                        response_list = []
                        for transaction in result:
                            response = {"block_height": transaction[0],
                                        "timestamp": transaction[1],
                                        "address": transaction[2],
                                        "recipient": transaction[3],
                                        "amount": transaction[4],
                                        "signature": transaction[5],
                                        "public_key": transaction[6],
                                        "block_hash": transaction[7],
                                        "fee": transaction[8],
                                        "reward": transaction[9],
                                        "operation": transaction[10],
                                        "openfield": transaction[11]}

                            response_list.append(response)

                        send(self.request, response_list)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlistlimjson command")

                elif data == "addlistlimmir":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        address_tx_list_limit = receive(self.request)

                        # print(address_tx_list_limit)
                        db_handler_instance.execute_param(db_handler_instance.h, (
                            "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) AND block_height < 1 ORDER BY block_height ASC LIMIT ?"),
                                                          (address_tx_list, address_tx_list, address_tx_list_limit,))
                        result = db_handler_instance.h.fetchall()
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlistlimmir command")

                elif data == "addlistlimmirjson":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        address_tx_list_limit = receive(self.request)

                        # print(address_tx_list_limit)
                        db_handler_instance.execute_param(db_handler_instance.h, (
                            "SELECT * FROM transactions WHERE (address = ? OR recipient = ?) AND block_height < 1 ORDER BY block_height ASC LIMIT ?"),
                                                          (address_tx_list, address_tx_list, address_tx_list_limit,))
                        result = db_handler_instance.h.fetchall()

                        response_list = []
                        for transaction in result:
                            response = {"block_height": transaction[0],
                                        "timestamp": transaction[1],
                                        "address": transaction[2],
                                        "recipient": transaction[3],
                                        "amount": transaction[4],
                                        "signature": transaction[5],
                                        "public_key": transaction[6],
                                        "block_hash": transaction[7],
                                        "fee": transaction[8],
                                        "reward": transaction[9],
                                        "operation": transaction[10],
                                        "openfield": transaction[11]}

                            response_list.append(response)

                        send(self.request, response_list)
                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addlistlimmir command")

                elif data == "aliasget":  # all for a single address, no protection against overlapping
                    if node.peers.is_allowed(peer_ip, data):
                        aliases.aliases_update(node, db_handler_instance)

                        alias_address = receive(self.request)
                        result = db_handler_instance.aliasget(alias_address)

                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for aliasget command")

                elif data == "aliasesget":  # only gets the first one, for multiple addresses
                    if node.peers.is_allowed(peer_ip, data):
                        aliases.aliases_update(node, db_handler_instance)
                        aliases_request = receive(self.request)
                        results = db_handler_instance.aliasesget(aliases_request)
                        send(self.request, results)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for aliasesget command")

                # Not mandatory, but may help to reindex with minimal sql queries

                elif data == "tokensget":
                    # TODO: to be handled by token modules, with no sql here in node.
                    if node.peers.is_allowed(peer_ip, data):

                        tokens_address = receive(self.request)
                        tokens_user = db_handler_instance.tokens_user(tokens_address)

                        tokens_list = []
                        for token in tokens_user:
                            token = token[0]
                            db_handler_instance.execute_param(db_handler_instance.index_cursor,
                                                              "SELECT sum(amount) FROM tokens WHERE recipient = ? AND token = ?;",
                                                              (tokens_address,) + (token,))
                            credit = db_handler_instance.index_cursor.fetchone()[0]
                            db_handler_instance.execute_param(db_handler_instance.index_cursor,
                                                              "SELECT sum(amount) FROM tokens WHERE address = ? AND token = ?;",
                                                              (tokens_address,) + (token,))
                            debit = db_handler_instance.index_cursor.fetchone()[0]

                            debit = 0 if debit is None else debit
                            credit = 0 if credit is None else credit

                            balance = str(Decimal(credit) - Decimal(debit))

                            tokens_list.append((token, balance))

                        send(self.request, tokens_list)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for tokensget command")

                elif data == "addfromalias":
                    if node.peers.is_allowed(peer_ip, data):

                        aliases.aliases_update(node, db_handler_instance)

                        alias_address = receive(self.request)
                        address_fetch = db_handler_instance.addfromalias(alias_address)
                        node.logger.app_log.warning(f"Fetched the following alias address: {address_fetch}")
                        send(self.request, address_fetch)

                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for addfromalias command")

                elif data == "pubkeyget":
                    if node.peers.is_allowed(peer_ip, data):
                        pub_key_address = receive(self.request)
                        target_public_key_b64encoded = db_handler_instance.pubkeyget(pub_key_address)
                        # returns as stored in the DB, that is b64 encoded, except for RSA where it's b64 encoded twice.
                        send(self.request, target_public_key_b64encoded)

                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for pubkeyget command")

                elif data == "aliascheck":
                    if node.peers.is_allowed(peer_ip, data):
                        reg_string = receive(self.request)

                        registered_pending = mp.MEMPOOL.fetchone(
                            "SELECT timestamp FROM transactions WHERE openfield = ?;",
                            ("alias=" + reg_string,))

                        db_handler_instance.execute_param(db_handler_instance.h, "SELECT timestamp FROM transactions WHERE openfield = ?;", ("alias=" + reg_string,) )
                        registered_already = db_handler_instance.h.fetchone()

                        if registered_already is None and registered_pending is None:
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
                    if node.peers.is_allowed(peer_ip, data):
                        node.logger.app_log.warning("txsend is unsafe and deprecated, please don't use.")
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

                        node.logger.app_log.info(mp.MEMPOOL.merge(mempool_data, peer_ip, db_handler_instance.c, True, True))

                        send(self.request, str(remote_signature_enc))
                        # wipe variables
                        (tx_remote, remote_tx_privkey, tx_remote_key) = (None, None, None)
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

                        # with open(peerlist, "r") as peer_list:
                        #    peers_file = peer_list.read()

                        result = db_handler_instance.annget(node)

                        send(self.request, result)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for annget command")

                elif data == "annverget":
                    if node.peers.is_allowed(peer_ip):
                        result = db_handler_instance.annverget(node)
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
                        uptime = int(time.time() - node.startup_time)
                        diff = node.difficulty
                        server_timestamp = '%.2f' % time.time()
                        if node.reveal_address:
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
                        uptime = int(time.time() - node.startup_time)
                        tempdiff = node.difficulty
                        if node.reveal_address:
                            revealed_address = node.keys.address
                        else:
                            revealed_address = "private"
                        status = {"protocolversion": node.version,
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
                                  "server_timestamp": '%.2f' % time.time()}
                        if node.is_regnet:
                            status['regnet'] = True
                        send(self.request, status)
                    else:
                        node.logger.app_log.info(f"{peer_ip} not whitelisted for statusjson command")
                elif data[:4] == 'api_':
                    if node.peers.is_allowed(peer_ip, data):
                        try:
                            node.apihandler.dispatch(data, self.request, db_handler_instance, node.peers)
                        except Exception as e:
                            if node.debug:
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
                        send(self.request, {"port": node.port})
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
                        difflast = db_handler_instance.difflast()

                        send(self.request, difflast)
                    else:
                        node.logger.app_log.info("f{peer_ip} not whitelisted for difflastget command")

                elif data == "difflastjson":
                    if node.peers.is_allowed(peer_ip, data):

                        difflast = db_handler_instance.difflast()
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
                        response = db_handler_instance.block_height_from_hash(hash)
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

                    # This is the entry point for all extra commands from plugins
                    for prefix, callback in extra_commands.items():
                        if data.startswith(prefix):
                            extra = True
                            callback(data, self.request)

                    if not extra:
                        raise ValueError("Unexpected error, received: " + str(data)[:32] + ' ...')

                if not time.time() <= timer_operation + timeout_operation:
                    timer_operation = time.time()  # reset timer
                # time.sleep(float(node.pause))  # prevent cpu overload
                node.logger.app_log.info(f"Server loop finished for {peer_ip}")

            except Exception as e:

                node.logger.app_log.info(f"Inbound: Lost connection to {peer_ip}")
                node.logger.app_log.info(f"Inbound: {e}")

                # remove from consensus (connection from them)
                node.peers.consensus_remove(peer_ip)
                # remove from consensus (connection from them)
                self.request.close()

                if node.debug:
                    raise  # major debug client
                else:
                    return

        if not node.peers.version_allowed(peer_ip, node.version_allow):
            node.logger.app_log.warning(f"Inbound: Closing connection to old {peer_ip} node: {node.peers.ip_to_mainnet[peer_ip]}")
        return


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


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


def node_block_init(database, node):
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


def load_keys(node):
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


if __name__ == "__main__":
    # classes
    node = node.Node()
    node.logger = logger.Logger()
    node.keys = keys.Keys()

    node.is_testnet = False
    # regnet takes over testnet
    node.is_regnet = False
    # if it's not testnet, nor regnet, it's mainnet
    node.is_mainnet = True

    config = options.Get()
    config.read()
    # classes

    node.app_version = VERSION
    # TODO: we could just loop over config items, and assign them to node.
    # or just do node.config = config
    # and use node.config.port... aso

    # TODO: Simplify. Just do node.config = config, then use node.config.required_option
    node.version = config.version
    node.debug_level = config.debug_level
    node.port = config.port
    node.verify = config.verify
    node.thread_limit = config.thread_limit
    node.rebuild_db = config.rebuild_db
    node.debug = config.debug
    node.debug_level = config.debug_level
    node.pause = config.pause
    node.ledger_path = config.ledger_path
    node.hyper_path = config.hyper_path
    node.hyper_recompress = config.hyper_recompress
    node.tor = config.tor
    node.ram = config.ram
    node.version_allow = config.version_allow
    node.reveal_address = config.reveal_address
    node.terminal_output = config.terminal_output
    node.egress = config.egress
    node.genesis = config.genesis
    node.accept_peers = config.accept_peers
    node.full_ledger = config.full_ledger
    node.trace_db_calls = config.trace_db_calls
    node.heavy3_path = config.heavy3_path
    node.old_sqlite = config.old_sqlite
    node.heavy = config.heavy

    node.logger.app_log = log.log("node.log", node.debug_level, node.terminal_output)
    node.logger.app_log.warning("Configuration settings loaded")
    node.logger.app_log.warning(f"Python version: {node.py_version}")

    # upgrade wallet location after nuitka-required "files" folder introduction
    if os.path.exists("../wallet.der") and not os.path.exists("wallet.der") and "Windows" in platform.system():
        print("Upgrading wallet location")
        os.rename("../wallet.der", "wallet.der")
    # upgrade wallet location after nuitka-required "files" folder introduction

    if not node.full_ledger and os.path.exists(node.ledger_path) and node.is_mainnet:
        os.remove(node.ledger_path)
        node.logger.app_log.warning("Removed full ledger for hyperblock mode")
    if not node.full_ledger:
        node.logger.app_log.warning("Cloning hyperblocks to ledger file")
        shutil.copy(node.hyper_path, node.ledger_path)  # hacked to remove all the endless checks
    try:
        # create a plugin manager, load all plugin modules and init
        node.plugin_manager = plugins.PluginManager(app_log=node.logger.app_log, config=config, init=True)
        # get the potential extra command prefixes from plugin
        extra_commands = {}  # global var, used by the server part.
        extra_commands = node.plugin_manager.execute_filter_hook('extra_commands_prefixes', extra_commands)
        print("Extra prefixes: ", ",".join(extra_commands.keys()))

        setup_net_type(node, regnet=False)
        load_keys(node)

        # needed for docker logs
        node.logger.app_log.warning(f"Checking Heavy3 file, can take up to 5 minutes...")
        mining_heavy3.mining_open(node.heavy3_path)
        node.logger.app_log.warning(f"Heavy3 file Ok!")

        node.logger.app_log.warning(f"Status: Starting node version {VERSION}")
        node.startup_time = time.time()
        try:

            node.peers = peershandler.Peers(node.logger.app_log, config=config, node=node)

            # print(peers.peer_list_old_format())
            # sys.exit()

            node.apihandler = apihandler.ApiHandler(node.logger.app_log, config)
            mp.MEMPOOL = mp.Mempool(node.logger.app_log, config, node.db_lock, node.is_testnet, trace_db_calls=node.trace_db_calls)

            check_integrity(node.hyper_path, node)
            #PLACEHOLDER FOR FRESH HYPERBLOCK BUILDER

            # if node.rebuild_db: #does nothing
            #    db_maintenance(init_database)

            # db_manager = db_looper.DbManager(node.logger.app_log)
            # db_manager.start()

            db_handler_initial = dbhandler.DbHandler(node.index_db, node.ledger_path, node.hyper_path, node.ram, node.ledger_ram_file, node.logger, trace_db_calls=node.trace_db_calls)

            ledger_check_heights(node, db_handler_initial)


            if node.recompress:
                #todo: do not close database and move files, swap tables instead
                db_handler_initial.close()
                recompress_ledger(node)
                db_handler_initial = dbhandler.DbHandler(node.index_db, node.ledger_path, node.hyper_path, node.ram, node.ledger_ram_file, node.logger, trace_db_calls=node.trace_db_calls)

            ram_init(db_handler_initial, node)
            node_block_init(db_handler_initial, node)
            initial_db_check(node)

            if not node.is_regnet:
                sequencing_check(db_handler_initial, node=node)

            if node.verify:
                verify(db_handler_initial, node=node)

            add_indices(db_handler_initial, node=node)

            # TODO: until here, we are in single user mode.
            # All the above goes into a "bootup" function, with methods from single_user module only.

            if not node.tor:
                # Port 0 means to select an arbitrary unused port
                host, port = "0.0.0.0", int(node.port)

                ThreadedTCPServer.allow_reuse_address = True
                ThreadedTCPServer.daemon_threads = True
                ThreadedTCPServer.timeout = 60
                ThreadedTCPServer.request_queue_size = 100

                server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
                ip, node.port = server.server_address

                # Start a thread with the server -- that thread will then start one
                # more thread for each request

                server_thread = threading.Thread(target=server.serve_forever)
                server_thread.daemon = True
                server_thread.start()

                node.logger.app_log.warning("Status: Server loop running.")

            else:
                node.logger.app_log.warning("Status: Not starting a local server to conceal identity on Tor network")

            # start connection manager
            connection_manager = connectionmanager.ConnectionManager(node, mp)
            connection_manager.start()
            # start connection manager

        except Exception as e:
            node.logger.app_log.info(e)
            raise

    except Exception as e:
        node.logger.app_log.info(e)
        raise

    import signal

    try:
        node.logger.app_log.warning("Status: Bismuth loop running.")


        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            node.logger.app_log.warning("Status: Received interrupt signal, shutting down...")
            node.IS_STOPPING = True


        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

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
        # Wait for clean shutdown
        while node.db_lock.locked():
            time.sleep(0.5)
        mining_heavy3.mining_close()

    node.logger.app_log.warning("Status: Clean Stop")