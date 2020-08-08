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


import platform
import socketserver
import threading
from sys import version_info, argv, exc_info
import os
from time import time as ttime, sleep
from decimal import Decimal
from tornado.log import enable_pretty_logging
# moved to DbHandler
# import aliases  # PREFORK_ALIASES
# import future.aliasesv2 as aliases # POSTFORK_ALIASES

# Bis specific modules
from libs.connections import send, receive
from libs.digest import digest_block
from libs.digestv2 import digest_block_v2
from bismuthcore.helpers import sanitize_address
from bismuthcore.transaction import Transaction
from libs import keys, client, mempool as mp, regnet, log, essentials
from libs.nodebackgroundthread import NodeBackgroundThread
from libs.logger import Logger
from libs.node import Node
from libs.config import Config
from libs.dbhandler import DbHandler
from libs.deprecated import rsa_key_generate

VERSION = "5.0.23-evo"  # Experimental db-evolution branch


appname = "Bismuth"
appauthor = "Bismuth Foundation"


# TODO: this requestHandler to be renamed and moved into a file of its own.
# Then check what can be factorized between it and clientworker.py
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
                        continue

                if data == 'version':
                    data = receive(self.request)
                    if data not in node.config.version_allow:
                        node.logger.peers_log.warning(
                            f"Protocol version mismatch: {data}, should be {node.config.version_allow}")
                        send(self.request, "notok")
                        return
                    else:
                        node.logger.peers_log.info(f"Inbound: Protocol version matched with {peer_ip}: {data}")
                        send(self.request, "ok")
                        node.peers.store_mainnet(peer_ip, data)

                elif data == 'getversion':
                    send(self.request, node.config.version)

                elif data == 'mempool':
                    # receive theirs
                    segments = receive(self.request)
                    node.logger.mempool_log.info(mp.MEMPOOL.merge(segments, peer_ip, db_handler, size_bypass=False))
                    # improvement possible - pass peer_ip from worker
                    # receive theirs
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
                        node.logger.dev_log.error("Inbound: Got hello but I'm in regtest mode, closing.")
                        return
                    send(self.request, "peers")
                    peers_send = node.peers.peer_list_disk_format()
                    send(self.request, peers_send)
                    while node.db_lock.locked():
                        node.sleep()
                    node.logger.peers_log.info("Inbound: Sending sync request")

                    send(self.request, "sync")

                elif data == "sendsync":
                    while node.db_lock.locked():
                        node.sleep()
                    while len(node.syncing) >= 3:
                        node.sleep()
                    send(self.request, "sync")

                elif data == "blocksfnd":
                    node.logger.peers_log.info(f"Inbound: Client {peer_ip} has the block(s)")  # node should start sending txs in this step
                    # node.logger.app_log.info("Inbound: Combined segments: " + segments)
                    if node.db_lock.locked():
                        node.logger.app_log.info(f"Skipping sync from {peer_ip}, syncing already in progress")
                    else:
                        node.last_block_timestamp = db_handler.last_block_timestamp()
                        if node.last_block_timestamp < ttime() - 600:
                            # block_req = most_common(consensus_blockheight_list)
                            block_req = node.peers.consensus_most_common
                            node.logger.consensus_log.info("Most common block rule triggered")
                        else:
                            # block_req = max(consensus_blockheight_list)
                            block_req = node.peers.consensus_max
                            node.logger.consensus_log.info("Longest chain rule triggered")
                        # Nothing guarantees "received_block_height" has been defined before or is up to date.
                        # Should for a pristine client, but can't make sure.
                        # TODO Egg: Add some state here in the flow, at least a flag.
                        if int(received_block_height) >= block_req and int(received_block_height) > node.last_block:
                            try:  # they claim to have the longest chain, things must go smooth or ban
                                node.logger.consensus_log.warning(f"Confirming to sync from {peer_ip}")
                                node.plugin_manager.execute_action_hook('sync', {'what': 'syncing_from', 'ip': peer_ip})
                                send(self.request, "blockscf")
                                segments = receive(self.request)
                            except:
                                if node.peers.warning(self.request, peer_ip, "Failed to deliver the longest chain"):
                                    node.logger.peers_log.info(f"{peer_ip} banned")
                                    break
                            else:
                                if node.config.legacy_db:
                                    digest_block(node, segments, self.request, peer_ip, db_handler)
                                else:
                                    digest_block_v2(node, segments, self.request, peer_ip, db_handler)
                        else:
                            node.logger.consensus_log.warning(f"Rejecting to sync from {peer_ip}")
                            send(self.request, "blocksrj")
                            node.logger.consensus_log.info(
                                f"Inbound: Distant peer {peer_ip} is at {received_block_height}, "
                                f"should be at least {max(block_req,node.last_block+1)}")
                    send(self.request, "sync")

                elif data == "blockheight":
                    try:
                        received_block_height = int(receive(self.request))  # receive client's last block height
                        node.logger.peers_log.info(
                            f"Inbound: Received block height {received_block_height} from {peer_ip} ")
                        consensus_blockheight = received_block_height  # str int to remove leading zeros
                        node.peers.consensus_add(peer_ip, consensus_blockheight, self.request, node.hdd_block)
                        send(self.request, node.hdd_block)
                        # send own block height
                        if received_block_height > node.hdd_block:
                            node.logger.consensus_log.warning("Inbound: Client {} has higher block {} vs ours {}"
                                                        .format(peer_ip, received_block_height, node.hdd_block))
                            node.logger.consensus_log.info(f"Inbound: block_hash to send: {node.hdd_hash}")
                            send(self.request, node.hdd_hash)
                            # receive their latest sha_hash
                            # confirm you know that sha_hash or continue receiving

                        elif received_block_height <= node.hdd_block:
                            if received_block_height == node.hdd_block:
                                node.logger.consensus_log.info(
                                    f"Inbound: We have the same height as {peer_ip} ({received_block_height}), hash will be verified")
                            else:
                                node.logger.consensus_log.warning(
                                    f"Inbound: We have higher ({node.hdd_block}) block height than {peer_ip} ({received_block_height}), hash will be verified")

                            data = receive(self.request)  # receive client's last block_hash
                            # send all our followup hashes
                            if data == "*":
                                # connection lost, no need to go on, that was banning the node like it forked.
                                node.logger.peers_log.warning(f"Inbound: {peer_ip} dropped connection")
                                break
                            node.logger.consensus_log.info(f"Inbound: Will seek the following block: {data}")

                            client_block = db_handler.block_height_from_hash(data)
                            if client_block is None:
                                node.logger.consensus_log.warning(f"Inbound: Block {data[:8]} of {peer_ip} not found")
                                if node.config.full_ledger:
                                    send(self.request, "blocknf")  # announce block hash was not found
                                else:
                                    send(self.request, "blocknfhb")  # announce we are on hyperblocks
                                send(self.request, data)

                                if node.peers.warning(self.request, peer_ip, "Forked", 2):
                                    node.logger.peers_log.info(f"{peer_ip} banned")
                                    break

                            else:
                                node.logger.consensus_log.info(f"Inbound: Client is at block {client_block}")
                                # now check if we have any newer
                                if node.hdd_hash == data or not node.config.egress:
                                    if node.config.egress:
                                        node.logger.consensus_log.info(f"Inbound: Client {peer_ip} has the latest block")
                                    else:
                                        node.logger.consensus_log.warning(f"Inbound: Egress disabled for {peer_ip}")
                                    node.sleep()  # reduce CPU usage
                                    send(self.request, "nonewblk")

                                else:
                                    blocks_fetched = db_handler.blocksync(client_block)
                                    node.logger.consensus_log.info(f"Inbound: Selected {blocks_fetched}")
                                    send(self.request, "blocksfnd")
                                    confirmation = receive(self.request)
                                    if confirmation == "blockscf":
                                        node.logger.peers_log.info("Inbound: Client confirmed they want to sync from us")
                                        send(self.request, blocks_fetched)
                                    elif confirmation == "blocksrj":
                                        node.logger.peers_log.info(
                                            "Inbound: Client rejected to sync from us because we don't have the latest block")

                    except Exception as e:
                        node.logger.consensus_log.warning(f"Inbound: Sync failed {e}")
                        exc_type, exc_obj, exc_tb = exc_info()
                        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                        node.logger.app_log.warning("{} {} {}".format(exc_type, fname, exc_tb.tb_lineno))

                elif data == "nonewblk":
                    send(self.request, "sync")

                elif data == "blocknf":
                    block_hash_delete = receive(self.request)
                    # TODO Egg: Same as above, some state to keep here, consensus_blockheight may be undefined or not up to date.
                    if consensus_blockheight == node.peers.consensus_max:
                        node.blocknf(block_hash_delete, peer_ip, db_handler)
                        if node.peers.warning(self.request, peer_ip, "Rollback", 2):
                            node.logger.peers_log.warning(f"{peer_ip} banned")
                            break
                    node.logger.consensus_log.info("Inbound: Deletion complete, sending sync request")
                    while node.db_lock.locked():
                        node.sleep()
                    send(self.request, "sync")

                elif data == "blocknfhb":  # node announces it's running hyperblocks
                    block_hash_delete = str(receive(self.request))
                    # print peer_ip
                    if consensus_blockheight == node.peers.consensus_max:
                        node.blocknf(block_hash_delete, peer_ip, db_handler, hyperblocks=True)
                        if node.peers.warning(self.request, peer_ip, "Rollback", 2):
                            node.logger.peers_log.warning(f"{peer_ip} banned")
                            break
                    node.logger.consensus_log.info("Inbound: Deletion complete, sending sync request")
                    while node.db_lock.locked():
                        node.sleep()
                    send(self.request, "sync")

                elif data == "block":
                    # if (peer_ip in allowed or "any" in allowed):  # from miner
                    if node.peers.is_allowed(peer_ip, data):  # from miner
                        # TODO: rights management could be done one level higher instead of repeating the same check everywhere
                        node.logger.consensus_log.warning(f"Inbound: Received a block from miner {peer_ip}")
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
                                node.logger.consensus_log.warning(reason)
                                return
                            elif node.last_block >= node.peers.consensus_max - 3:
                                mined['result'] = True
                                node.plugin_manager.execute_action_hook('mined', mined)
                                node.logger.consensus_log.info("Inbound: Processing block from miner")
                                try:
                                    if node.config.legacy_db:
                                        digest_block(node, segments, self.request, peer_ip, db_handler)
                                    else:
                                        digest_block_v2(node, segments, self.request, peer_ip, db_handler)
                                except ValueError as e:
                                    node.logger.consensus_log.warning("Inbound: block {}".format(str(e)))
                                    return
                                except Exception as e:
                                    node.logger.consensus_log.error("Inbound: Processing block from miner {}".format(e))
                                    return
                                # This new block may change the int(diff). Trigger the hook whether it changed or not.
                                # node.difficulty = difficulty(node, db_handler_instance)
                            else:
                                reason = f"Inbound: Mined block was orphaned because node was not synced, " \
                                         f"we are at block {node.last_block}, " \
                                         f"should be at least {node.peers.consensus_max - 3}"
                                mined['reason'] = reason
                                node.plugin_manager.execute_action_hook('mined', mined)
                                node.logger.consensus_log.warning(reason)
                        else:
                            # Not mainnet
                            try:
                                if node.config.legacy_db:
                                    digest_block(node, segments, self.request, peer_ip, db_handler)
                                else:
                                    digest_block_v2(node, segments, self.request, peer_ip, db_handler)
                            except ValueError as e:
                                node.logger.consensus_log.warning("Inbound: block {}".format(str(e)))
                                return
                            except Exception as e:
                                node.logger.consensus_log.error("Inbound: Processing block from miner {}".format(e))
                                return
                    else:
                        receive(self.request)  # receive block, but do nothing about it

                elif data == "blocklast":
                    # Beware: name is misleading: only sends the miner part of the block! (only one transaction)
                    if node.peers.is_allowed(peer_ip, data):
                        send(self.request, db_handler.last_mining_transaction().to_tuple())

                elif data == "blocklastjson":
                    # Beware: name is misleading: only sends the miner part of the block! (only one transaction)
                    # DOC: possible confusion to be emphasized in the ref. doc.
                    if node.peers.is_allowed(peer_ip, data):
                        transaction = db_handler.last_mining_transaction()
                        # Was response = {"block_height": block_last[0], .....
                        send(self.request, transaction.to_dict(legacy=True))  # send will convert the dict to json.

                elif data == "blockget":
                    if node.peers.is_allowed(peer_ip, data):
                        # see blockgetjson below for more comments
                        block_desired = int(receive(self.request))
                        block = db_handler.get_block(block_desired)
                        send(self.request, block.to_listoftuples())

                elif data == "blockgetjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if node.peers.is_allowed(peer_ip, data):
                        block_desired = int(receive(self.request))
                        # Egg: param comes from the client, so it makes sense to force cast to int as a sanitization precaution
                        block = db_handler.get_block(block_desired)
                        send(self.request, block.to_listofdicts(legacy=True))

                elif data == "mpinsert":
                    if node.peers.is_allowed(peer_ip, data):
                        mempool_insert = receive(self.request)
                        node.logger.mempool_log.warning("mpinsert command")
                        mpinsert_result = mp.MEMPOOL.merge(mempool_insert, peer_ip, db_handler, size_bypass=True, wait=True)
                        node.logger.mempool_log.warning(f"mpinsert result: {mpinsert_result}")
                        send(self.request, mpinsert_result)

                elif data == "balanceget":
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = sanitize_address(receive(self.request))  # for which address? force casted because unsafe user input.
                        balanceget_result = db_handler.balance_get_full(balance_address, mp.MEMPOOL)
                        send(self.request, balanceget_result)  # return balance of the address to the client, including mempool

                elif data == "balancegetjson":
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = sanitize_address(receive(self.request))  # for which address
                        balance_dict = db_handler.balance_get_full(balance_address, mp.MEMPOOL, as_dict=True)
                        send(self.request, balance_dict)  # return balance of the address to the client, including mempool

                elif data == "balancegethyper":
                    # EGG: What is the reason for these hyper commands? look like they use the same data source anyway as the regular one.
                    node.logger.peers_log.warning(f"{peer_ip} {data} command is deprecated")
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = sanitize_address(receive(self.request))  # for which address
                        balanceget_result =db_handler.balance_get_full(balance_address, mp.MEMPOOL)[0]
                        send(self.request,balanceget_result)  # return balance of the address to the client, including mempool

                elif data == "balancegethyperjson":
                    # EGG: What is the reason for these hyper commands? look like they use the same data source anyway as the regular one.
                    node.logger.peers_log.warning(f"{peer_ip} {data} command is deprecated")
                    if node.peers.is_allowed(peer_ip, data):
                        balance_address = sanitize_address(receive(self.request))  # for which address
                        balance_dict = db_handler.balance_get_full(balance_address, mp.MEMPOOL, as_dict=True)
                        send(self.request, balance_dict)  # return balance of the address to the client, including mempool

                elif data == "mpgetjson":
                    if node.peers.is_allowed(peer_ip, data):
                        mempool_txs = mp.MEMPOOL.transactions_to_send()
                        # EGG_EVO: Partial conversion. MP still uses legacy format so far.
                        response_list = [Transaction.from_legacymempool(transaction).to_dict(legacy=True)
                                         for transaction in mempool_txs]
                        send(self.request, response_list)

                elif data == "mpget":
                    if node.peers.is_allowed(peer_ip, data):
                        # mempool_txs = mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)
                        mempool_txs = mp.MEMPOOL.transactions_to_send()
                        # EGG_EVO: Partial conversion. MP still uses legacy format so far.
                        # response_tuples = [transaction.to_tuple() for transaction in mempool_txs]
                        send(self.request, mempool_txs)

                elif data == "mpclear":  # since we are in elif, no compound conditions.
                    if peer_ip == "127.0.0.1":  # reserved for localhost
                        mp.MEMPOOL.clear()

                elif data == "keygen":
                    if node.peers.is_allowed(peer_ip, data):
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = rsa_key_generate()
                        node.logger.dev_log.warning("keygen is unsafe and deprecated, please don't use.")
                        send(self.request, (gen_private_key_readable, gen_public_key_readable, gen_address))
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = (None, None, None)

                elif data == "keygenjson":
                    if node.peers.is_allowed(peer_ip, data):
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = rsa_key_generate()
                        response = {"private_key": gen_private_key_readable,
                                    "public_key": gen_public_key_readable,
                                    "address": gen_address}
                        node.logger.dev_log.warning("keygenjson is unsafe and deprecated, please don't use.")
                        send(self.request, response)
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = (None, None, None)

                elif data == "addlist":
                    # Sends back *ALL* transactions for the provided address. May be excessive.
                    if node.peers.is_allowed(peer_ip, data):
                        address = sanitize_address(receive(self.request))  # user input sanitization
                        transactions = db_handler.transactions_for_address(address, limit=0)
                        result = [transaction.to_tuple() for transaction in transactions]
                        send(self.request, result)

                elif data == "listlimjson":
                    if node.peers.is_allowed(peer_ip, data):
                        list_limit = int(receive(self.request))
                        transactions = db_handler.last_n_transactions(list_limit)
                        send(self.request, [transaction.to_dict(legacy=True) for transaction in transactions])

                elif data == "listlim":
                    if node.peers.is_allowed(peer_ip, data):
                        list_limit = int(receive(self.request))
                        transactions = db_handler.last_n_transactions(list_limit)
                        send(self.request, [transaction.to_tuple() for transaction in transactions])

                elif data == "addlistlim":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = sanitize_address(receive(self.request))
                        address_tx_list_limit = int(receive(self.request))
                        transactions = db_handler.transactions_for_address(address_tx_list, limit=address_tx_list_limit)
                        # EGG_EVO: instead of handling list comprehension at that high level everywhere , better use a "TransactionList" type - like a block, but not the same semantic,
                        # or a helper to factorize all these dup snippets.
                        result = [transaction.to_tuple() for transaction in transactions]
                        send(self.request, result)

                elif data == "addlistlimjson":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = sanitize_address(receive(self.request))
                        address_tx_list_limit = int(receive(self.request))
                        transactions = db_handler.transactions_for_address(address_tx_list, limit=address_tx_list_limit)
                        # EGG_EVO: instead of handling list comprehension at that high level everywhere , better use a "TransactionList" type - like a block, but not the same semantic,
                        # or a helper to factorize all these dup snippets.
                        result = [transaction.to_dict(legacy=True) for transaction in transactions]
                        send(self.request, result)

                elif data == "addlistlimmir":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = sanitize_address(receive(self.request))
                        address_tx_list_limit = int(receive(self.request))
                        transactions = db_handler.transactions_for_address(address_tx_list, limit=address_tx_list_limit, mirror=True)
                        result = [transaction.to_tuple() for transaction in transactions]
                        send(self.request, result)

                elif data == "addlistlimmirjson":
                    if node.peers.is_allowed(peer_ip, data):
                        address_tx_list = sanitize_address(receive(self.request))
                        address_tx_list_limit = int(receive(self.request))
                        transactions = db_handler.transactions_for_address(address_tx_list, limit=address_tx_list_limit, mirror=True)
                        result = [transaction.to_dict(legacy=True) for transaction in transactions]
                        send(self.request, result)

                elif data == "aliasget":  # all for a single address, no protection against overlapping
                    if node.peers.is_allowed(peer_ip, data):
                        db_handler.aliases_update()
                        alias_address = sanitize_address(receive(self.request))
                        send(self.request, db_handler.aliasget(alias_address))

                elif data == "aliasesget":  # only gets the first one, for multiple addresses
                    if node.peers.is_allowed(peer_ip, data):
                        db_handler.aliases_update()
                        aliases_request = receive(self.request)
                        results = db_handler.aliasesget(aliases_request)
                        send(self.request, results)

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

                elif data == "addfromalias":
                    if node.peers.is_allowed(peer_ip, data):
                        db_handler.aliases_update()
                        alias_address = receive(self.request)
                        # Egg: we could add an optional "update" boolean flag to addfromalias, that would auto prepend aliases_update.
                        # Avoids line above, and avoids doing the update if we finally get no alias
                        address_fetch = db_handler.addfromalias(alias_address)
                        node.logger.peers_log.info(f"Fetched the following alias address: {address_fetch}")
                        send(self.request, address_fetch)

                elif data == "pubkeyget":
                    if node.peers.is_allowed(peer_ip, data):
                        pub_key_address = receive(self.request)
                        target_public_key_b64encoded = db_handler.pubkeyget(pub_key_address)
                        # returns as stored in the DB, that is b64 encoded, except for RSA where it's b64 encoded twice.
                        send(self.request, target_public_key_b64encoded)

                elif data == "aliascheck":
                    if node.peers.is_allowed(peer_ip, data):
                        reg_string = str(receive(self.request))  # sanitize user input
                        # Egg: No prior db_handler.aliases_update() here? could be needed
                        registered_pending = mp.MEMPOOL.alias_exists(reg_string)  # this will lookup from mp transactions
                        registered_already = db_handler.alias_exists(reg_string)  # this looks up in alias table, faster.
                        if not registered_already and not registered_pending:
                            send(self.request, "Alias free")
                        else:
                            send(self.request, "Alias registered")

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
                        node.logger.dev_log.warning("txsend is unsafe and deprecated, please don't use.")

                # less important methods
                elif data == "addvalidate":
                    if node.peers.is_allowed(peer_ip, data):
                        address_to_validate = receive(self.request)
                        if essentials.address_validate(address_to_validate):
                            result = "valid"
                        else:
                            result = "invalid"
                        send(self.request, result)

                elif data == "annget":
                    if node.peers.is_allowed(peer_ip):
                        result = db_handler.annget(node.config.genesis)
                        send(self.request, result)

                elif data == "annverget":
                    if node.peers.is_allowed(peer_ip):
                        result = db_handler.annverget(node.config.genesis)
                        send(self.request, result)

                elif data == "peersget":
                    if node.peers.is_allowed(peer_ip, data):
                        send(self.request, node.peers.peer_list_disk_format())

                elif data == "statusget":
                    if node.peers.is_allowed(peer_ip, data):
                        nodes_count = node.peers.consensus_size
                        nodes_list = node.peers.peer_opinion_dict
                        threads_count = threading.active_count()
                        uptime = int(ttime() - node.startup_time)
                        diff = node.difficulty
                        print(diff)
                        server_timestamp = '%.2f' % ttime()
                        if node.config.reveal_address:
                            revealed_address = node.keys.address
                        else:
                            revealed_address = "private"
                        send(self.request, (
                            revealed_address, nodes_count, nodes_list, threads_count, uptime, node.peers.consensus,
                            node.peers.consensus_percentage, VERSION, diff, server_timestamp))

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

                elif data == "portget":
                    if node.peers.is_allowed(peer_ip, data):
                        send(self.request, {"port": node.config.port})

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

                elif data == "difflast":
                    if node.peers.is_allowed(peer_ip, data):
                        difflast = db_handler.difflast()
                        send(self.request, difflast)

                elif data == "difflastjson":
                    if node.peers.is_allowed(peer_ip, data):
                        difflast = db_handler.difflast()
                        response = {"block": difflast[0],
                                    "difficulty": difflast[1]
                                    }
                        send(self.request, response)

                elif data == "stop":
                    if node.peers.is_allowed(peer_ip, data):
                        node.logger.app_log.warning(f"Received stop from {peer_ip}")
                        node.IS_STOPPING = True

                elif data == "block_height_from_hash":
                    if node.peers.is_allowed(peer_ip, data):
                        ahash = receive(self.request)
                        response = db_handler.block_height_from_hash(ahash)
                        send(self.request, response)

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
    datadir = "./datadir"  # Default datadir if empty
    force_regnet = False
    test_v2 = False
    if len(argv) > 1:
        _, datadir = argv
        if "regnet" == datadir:
            force_regnet = True
            datadir = "./datadir"
        elif "V2" == datadir:
            test_v2 = True
            datadir = "./datadir"
        elif not os.path.isdir(datadir):
            print("No such '{}' dir. Using default".format(datadir))
            datadir = "./datadir"  # Default datadir if empty
    print("Using", datadir, "data dir")
    wait = 10
    if force_regnet:
        wait = 0
    if test_v2:
        config = Config(datadir=datadir, wait=wait, force_v2=True, force_regnet=force_regnet)
    else:
        config = Config(datadir=datadir, wait=wait, force_legacy=True, force_regnet=force_regnet)
    # config.read() is now implicit at instanciation
    logger = Logger()  # is that class really useful?
    enable_pretty_logging()
    app_log = log.log("node.log", config.debug_level, config.terminal_output)
    logger.set_app_log(app_log)
    logger.app_log.warning("Configuration settings loaded")
    # Pre-node tweaks
    # upgrade wallet location after nuitka-required "files" folder introduction
    wallet_file_name = config.get_wallet_path()
    # EGG: Is this still needed with datadir?
    if os.path.exists("../wallet.der") and not os.path.exists(wallet_file_name) and "Windows" in platform.system():
        print("Upgrading wallet location")
        os.rename("../wallet.der", wallet_file_name)
    # upgrade wallet location after nuitka-required "files" folder introduction

    # Will start node init sequence
    # Node instanciation is now responsible for lots of things that were previously done here or below
    if config.legacy_db:
        node = Node(digest_block, config, app_version=VERSION, logger=logger, keys=keys.Keys())
    else:
        node = Node(digest_block_v2, config, app_version=VERSION, logger=logger, keys=keys.Keys())

    node.logger.app_log.warning(f"Python version: {node.py_version}")

    try:
        # get the potential extra command prefixes from plugin
        extra_commands = {}  # global var, used by the server part.
        extra_commands = node.plugin_manager.execute_filter_hook('extra_commands_prefixes', extra_commands)
        node.logger.app_log.warning("Extra prefixes: " + ",".join(extra_commands.keys()))

        node.logger.app_log.warning(f"Status: Starting node version {VERSION} on port {node.config.port}")
        node.startup_time = ttime()
        try:
            mp.MEMPOOL = mp.Mempool(node)
            # print("MEMPOOL initialized")
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

            background_thread = NodeBackgroundThread(node, mp.MEMPOOL)
            background_thread.start()

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
                node.logger.app_log.warning("Status: Securely disconnected main processes, "
                                            "subprocess termination in progress.")
                break
        sleep(0.5)
    node.logger.app_log.warning("Status: Clean Stop")
