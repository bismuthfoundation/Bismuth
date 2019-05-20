from node import blocknf, digest_block
import sys
import threading
from libs import node, logger, keys, client
import time
import dbhandler
import socks
from connections import send, receive
from decimal import *
from quantizer import *
import mempool as mp
from difficulty import *
from libs import client

def sendsync(sdef, peer_ip, status, provider, node):
    """ Save peer_ip to peerlist and send `sendsync`

    :param sdef: socket object
    :param peer_ip: IP of peer synchronization has been completed with
    :param status: Status synchronization was completed in/as
    :param provider: Provided a valid block

    Log the synchronization status
    Save peer IP to peers list if applicable
    Wait for database to unlock
    Send `sendsync` command via socket `sdef`

    returns None
    """

    node.logger.app_log.info(f"Outbound: Synchronization with {peer_ip} finished after: {status}, sending new sync request")

    if provider:
        node.logger.app_log.info(f"Outbound: Saving peer {peer_ip}")
        node.peers.peer_dump(node.peerfile, peer_ip)

    time.sleep(Decimal(node.pause))
    while node.db_lock.locked():
        if node.IS_STOPPING:
            return
        time.sleep(Decimal(node.pause))

    send(sdef, "sendsync")

def worker(host, port, node):
    logger = node.logger

    this_client = f"{host}:{port}"

    if node.IS_STOPPING:
        return

    dict_ip = {'ip': host}
    node.plugin_manager.execute_filter_hook('peer_ip', dict_ip)
    client_instance_worker = client.Client()

    if node.peers.is_banned(host) or dict_ip['ip'] == 'banned':
        client_instance_worker.banned = True
        node.logger.app_log.warning(f"IP {host} is banned, won't connect")
        return

    timeout_operation = 60  # timeout
    timer_operation = time.time()  # start counting

    try:

        s = socks.socksocket()

        if node.tor:
            s.setproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
        # s.setblocking(0)
        s.connect((host, port))
        node.logger.app_log.info(f"Outbound: Connected to {this_client}")
        client_instance_worker.connected = True

        # communication starter

        send(s, "version")
        send(s, node.version)

        data = receive(s)

        if data == "ok":
            node.logger.app_log.info(f"Outbound: Node protocol version of {this_client} matches our client")
        else:
            raise ValueError(f"Outbound: Node protocol version of {this_client} mismatch")

        send(s, "getversion")
        peer_version = receive(s)
        if peer_version not in node.version_allow:
            raise ValueError(f"Outbound: Incompatible peer version {peer_version} from {this_client}")

        send(s, "hello")

        # communication starter

    except Exception as e:
        node.logger.app_log.info(f"Could not connect to {this_client}: {e}")
        return  # can return here, because no lists are affected yet

    node.peers.store_mainnet(host, peer_version)
    try:
        peer_ip = s.getpeername()[0]
    except:
        # Should not happen, extra safety
        node.logger.app_log.warning("Outbound: Transport endpoint was not connected")
        return

    if this_client not in node.peers.connection_pool:
        node.peers.append_client(this_client)
        node.logger.app_log.info(f"Connected to {this_client}")
        node.logger.app_log.info(f"Current active pool: {node.peers.connection_pool}")

    if not client_instance_worker.banned and node.peers.version_allowed(host, node.version_allow) and not node.IS_STOPPING:
        db_handler_instance = dbhandler.DbHandler(node.index_db, node.ledger_path, node.hyper_path, node.ram, node.ledger_ram_file, logger)

    try:
        while not client_instance_worker.banned and node.peers.version_allowed(host, node.version_allow) and not node.IS_STOPPING:

            #ensure_good_peer_version(host)

            data = receive(s)  # receive data, one and the only root point
            # print(data)

            if data == "peers":
                subdata = receive(s)
                node.peers.peersync(subdata)

            elif data == "sync":
                if not time.time() <= timer_operation + timeout_operation:
                    timer_operation = time.time()  # reset timer

                try:
                    while len(node.syncing) >= 3:
                        if node.IS_STOPPING:
                            return
                        time.sleep(int(node.pause))

                    node.syncing.append(peer_ip)
                    # sync start

                    # send block height, receive block height
                    send(s, "blockheight")

                    db_handler_instance.execute(db_handler_instance.c, 'SELECT max(block_height) FROM transactions')
                    db_block_height = db_handler_instance.c.fetchone()[0]

                    node.logger.app_log.info(f"Outbound: Sending block height to compare: {db_block_height}")
                    # append zeroes to get static length
                    send(s, db_block_height)

                    received_block_height = receive(s)  # receive node's block height
                    node.logger.app_log.info(
                        f"Outbound: Node {peer_ip} is at block height: {received_block_height}")

                    if int(received_block_height) < db_block_height:
                        node.logger.app_log.warning(
                            f"Outbound: We have a higher block ({db_block_height}) than {peer_ip} ({received_block_height}), sending")

                        data = receive(s)  # receive client's last block_hash

                        # send all our followup hashes
                        node.logger.app_log.info(f"Outbound: Will seek the following block: {data}")

                        # consensus pool 2 (active connection)
                        consensus_blockheight = int(received_block_height)
                        node.peers.consensus_add(peer_ip, consensus_blockheight, s, node.last_block)
                        # consensus pool 2 (active connection)

                        try:
                            db_handler_instance.execute_param(db_handler_instance.h, "SELECT block_height FROM transactions WHERE block_hash = ?;",
                                                              (data,))
                            client_block = db_handler_instance.h.fetchone()[0]
                        except Exception:
                            node.logger.app_log.warning(f"Outbound: Block {data[:8]} of {peer_ip} not found")
                            if node.full_ledger:
                                send(s, "blocknf")
                            else:
                                send(s, "blocknfhb")
                            send(s, data)

                        else:

                            node.logger.app_log.info(
                                f"Outbound: Node is at block {client_block}")  # now check if we have any newer

                            db_handler_instance.execute(db_handler_instance.h,
                                                        'SELECT block_hash FROM transactions ORDER BY block_height DESC LIMIT 1')
                            db_block_hash = db_handler_instance.h.fetchone()[0]  # get latest block_hash

                            if db_block_hash == data or not node.egress:
                                if not node.egress:
                                    node.logger.app_log.warning(f"Outbound: Egress disabled for {peer_ip}")
                                    time.sleep(int(node.pause))  # reduce CPU usage
                                else:
                                    node.logger.app_log.info(f"Outbound: Node {peer_ip} has the latest block")
                                    # TODO: this is unlikely to happen due to conditions above, consider removing
                                send(s, "nonewblk")

                            else:
                                blocks_fetched = []
                                while sys.getsizeof(
                                        str(blocks_fetched)) < 500000:  # limited size based on txs in blocks
                                    # db_handler.execute_param(db_handler.h, ("SELECT block_height, timestamp,address,recipient,amount,signature,public_key,keep,openfield FROM transactions WHERE block_height > ? AND block_height <= ?;"),(str(int(client_block)),) + (str(int(client_block + 1)),))
                                    db_handler_instance.execute_param(db_handler_instance.h, (
                                        "SELECT timestamp,address,recipient,amount,signature,public_key,operation,openfield FROM transactions WHERE block_height > ? AND block_height <= ?;"),
                                                                      (str(int(client_block)), str(int(client_block + 1)),))
                                    result = db_handler_instance.h.fetchall()
                                    if not result:
                                        break
                                    blocks_fetched.extend([result])
                                    client_block = int(client_block) + 1

                                # blocks_send = [[l[1:] for l in group] for _, group in groupby(blocks_fetched, key=itemgetter(0))]  # remove block number

                                node.logger.app_log.info(f"Outbound: Selected {blocks_fetched}")

                                send(s, "blocksfnd")

                                confirmation = receive(s)

                                if confirmation == "blockscf":
                                    node.logger.app_log.info("Outbound: Client confirmed they want to sync from us")
                                    send(s, blocks_fetched)

                                elif confirmation == "blocksrj":
                                    node.logger.app_log.info(
                                        "Outbound: Client rejected to sync from us because we're dont have the latest block")



                    elif int(received_block_height) >= db_block_height:
                        if int(received_block_height) == db_block_height:
                            node.logger.app_log.info(f"Outbound: We have the same block as {peer_ip} ({received_block_height}), hash will be verified")
                        else:
                            node.logger.app_log.warning(f"Outbound: We have a lower block ({db_block_height}) than {peer_ip} ({received_block_height}), hash will be verified")

                        db_handler_instance.execute(db_handler_instance.c, 'SELECT block_hash FROM transactions ORDER BY block_height DESC LIMIT 1')
                        db_block_hash = db_handler_instance.c.fetchone()[0]  # get latest block_hash

                        node.logger.app_log.info(f"Outbound: block_hash to send: {db_block_hash}")
                        send(s, db_block_hash)

                        #ensure_good_peer_version(host)

                        # consensus pool 2 (active connection)
                        consensus_blockheight = int(received_block_height)  # str int to remove leading zeros
                        node.peers.consensus_add(peer_ip, consensus_blockheight, s, node.last_block)
                        # consensus pool 2 (active connection)

                except Exception as e:
                    node.logger.app_log.info(f"Outbound: Sync failed {e}")
                finally:
                    node.syncing.remove(peer_ip)


            elif data == "blocknfhb":  # one of the possible outcomes
                block_hash_delete = receive(s)
                # print peer_ip
                # if max(consensus_blockheight_list) == int(received_block_height):
                if int(received_block_height) == node.peers.consensus_max:

                    blocknf(node, block_hash_delete, peer_ip, db_handler_instance, hyperblocks=True)

                    if node.peers.warning(s, peer_ip, "Rollback", 2):
                        raise ValueError(f"{peer_ip} is banned")

                sendsync(s, peer_ip, "Block not found", False, node)

            elif data == "blocknf":  # one of the possible outcomes
                block_hash_delete = receive(s)
                # print peer_ip
                # if max(consensus_blockheight_list) == int(received_block_height):
                if int(received_block_height) == node.peers.consensus_max:

                    blocknf(node, block_hash_delete, peer_ip, db_handler_instance)

                    if node.peers.warning(s, peer_ip, "Rollback", 2):
                        raise ValueError(f"{peer_ip} is banned")

                sendsync(s, peer_ip, "Block not found", False, node)

            elif data == "blocksfnd":
                node.logger.app_log.info(f"Outbound: Node {peer_ip} has the block(s)")  # node should start sending txs in this step

                # node.logger.app_log.info("Inbound: Combined segments: " + segments)
                # print peer_ip
                if node.db_lock.locked():
                    node.logger.app_log.warning(f"Skipping sync from {peer_ip}, syncing already in progress")

                else:
                    db_handler_instance.execute(db_handler_instance.c,
                                                "SELECT timestamp FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")  # or it takes the first
                    node.last_block_timestamp = quantize_two(db_handler_instance.c.fetchone()[0])

                    if int(node.last_block_timestamp) < (time.time() - 600):
                        block_req = node.peers.consensus_most_common
                        node.logger.app_log.warning("Most common block rule triggered")

                    else:
                        block_req = node.peers.consensus_max
                        node.logger.app_log.warning("Longest chain rule triggered")

                    #ensure_good_peer_version(host)

                    if int(received_block_height) >= block_req:
                        try:  # they claim to have the longest chain, things must go smooth or ban
                            node.logger.app_log.warning(f"Confirming to sync from {peer_ip}")

                            send(s, "blockscf")
                            segments = receive(s)
                            #ensure_good_peer_version(host)

                        except:
                            if node.peers.warning(s, peer_ip, "Failed to deliver the longest chain", 2):
                                raise ValueError(f"{peer_ip} is banned")

                        else:
                            digest_block(node, segments, s, peer_ip, db_handler_instance)
                            # receive theirs
                    else:
                        send(s, "blocksrj")
                        node.logger.app_log.warning(f"Inbound: Distant peer {peer_ip} is at {received_block_height}, should be at least {block_req}")

                sendsync(s, peer_ip, "Block found", True, node)

                # block_hash validation end

            elif data == "nonewblk":
                # send and receive mempool
                if mp.MEMPOOL.sendable(peer_ip):
                    mempool_txs = mp.MEMPOOL.tx_to_send(peer_ip)
                    # node.logger.app_log.info("Outbound: Extracted from the mempool: " + str(mempool_txs))  # improve: sync based on signatures only
                    # if len(mempool_txs) > 0: #wont sync mempool until we send something, which is bad
                    # send own
                    send(s, "mempool")
                    send(s, mempool_txs)
                    # send own
                    # receive theirs
                    segments = receive(s)
                    node.logger.app_log.info(mp.MEMPOOL.merge(segments, peer_ip, db_handler_instance.c, True))
                    # receive theirs
                    # Tell the mempool we just send our pool to a peer
                    mp.MEMPOOL.sent(peer_ip)
                sendsync(s, peer_ip, "No new block", True, node)

            elif data == "hyperlane":
                pass

            else:
                if data == '*':
                    raise ValueError("Broken pipe")
                raise ValueError(f"Unexpected error, received: {str(data)[:32]}")

    except Exception as e:
        """
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        """

        db_handler_instance.close()

        # remove from active pool
        node.peers.remove_client(this_client)
        node.logger.app_log.warning(f"Outbound: Disconnected from {this_client}: {e}")
        # remove from active pool

        # remove from consensus 2
        node.peers.consensus_remove(peer_ip)
        # remove from consensus 2

        node.logger.app_log.info(f"Connection to {this_client} terminated due to {e}")
        node.logger.app_log.info(f"---thread {threading.currentThread()} ended---")

        # properly end the connection
        s.close()
        # properly end the connection
        if node.debug:
            raise  # major debug client
        else:
            node.logger.app_log.info(f"Ending thread, because {e}")
            return





    if not node.peers.version_allowed(host, node.version_allow):
        node.logger.app_log.warning(f"Outbound: Ending thread, because {host} has too old a version: {node.peers.ip_to_mainnet[host]}")
