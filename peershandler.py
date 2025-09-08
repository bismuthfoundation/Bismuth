"""
Peers handler module for Bismuth nodes
@EggPoolNet
Optimized version
"""

import json
import os
import random
import shutil
import sys
import threading
from time import time
from collections import defaultdict, Counter
from typing import Dict, Optional, Tuple, Set

import socks

import connections
import regnet
from essentials import most_common_dict, percentage_in

__version__ = "0.0.19"


class Peers:
    """The peers manager. A thread safe peers manager"""

    __slots__ = ('app_log','config','logstats','node','peersync_lock','startup_time','reset_time','warning_list','stats',
                 'connection_pool','peer_opinion_dict','consensus_percentage','consensus',
                 'tried','peer_dict','peerfile','suggested_peerfile','banlist','whitelist','ban_threshold',
                 'ip_to_mainnet', 'peers', 'accept_peers', 'peerlist_updated', '_warning_counts',
                 '_connection_pool_set', '_c_class_cache', '_peer_dict_cache', '_cache_timestamp')

    def __init__(self, app_log, config=None, logstats=True, node=None):
        self.app_log = app_log
        self.config = config
        self.logstats = logstats
        self.peersync_lock = threading.Lock()
        self.startup_time = time()
        self.reset_time = self.startup_time
        self.warning_list = []
        self.stats = []
        self.peer_opinion_dict = {}
        self.consensus_percentage = 0
        self.consensus = None
        self.tried = {}
        self.peer_dict = {}
        self.ip_to_mainnet = {}
        self.connection_pool = []

        # Optimization: Add set for O(1) connection pool lookups
        self._connection_pool_set = set()
        # Optimization: Use Counter for warning counts
        self._warning_counts = Counter()
        # Optimization: Cache for C-class calculations
        self._c_class_cache = {}
        # Optimization: Cache for peer_dict operations
        self._peer_dict_cache = None
        self._cache_timestamp = 0

        # We store them apart from the initial config, could diverge somehow later on.
        self.banlist = config.banlist
        self.whitelist = config.whitelist
        self.ban_threshold = config.ban_threshold
        self.accept_peers = config.accept_peers

        self.peerfile = "peers.txt"
        self.suggested_peerfile = "suggested_peers.txt"
        self.peerlist_updated = False

        self.node = node

        if self.is_testnet:  # overwrite for testnet
            self.peerfile = "peers_test.txt"
            self.suggested_peerfile = "suggested_peers_test.txt"

        if self.is_regnet:  # regnet won't use any peer, won't connect. Kept for compatibility
            self.peerfile = regnet.REGNET_PEERS
            self.suggested_peerfile = regnet.REGNET_SUGGESTED_PEERS

    @property
    def is_testnet(self):
        """Helper to check if testnet or not. Only one place to change variable names and test"""
        if self.config.regnet:
            # regnet takes over testnet
            return False
        if self.config.testnet:
            return True
        return "testnet" in self.config.version

    @property
    def is_regnet(self):
        """Helper to check if regnet or not. Only one place to change variable names and test"""
        if self.config.regnet:
            # regnet takes over testnet
            return True
        return "regnet" in self.config.version

    def dict_shuffle(self, dictinary):
        l = list(dictinary.items())
        random.shuffle(l)
        return dict(l)

    def status_dict(self):
        """Returns a status as a dict"""
        status = {"version": self.config.VERSION, "stats": self.stats}
        return status

    def store_mainnet(self, ip, version):
        """Stores the mainnet version of a peer. Can't change unless reconnects"""
        self.ip_to_mainnet[ip] = version

    def forget_mainnet(self, ip):
        """Peers disconnected, forget his mainnet version"""
        self.ip_to_mainnet.pop(ip, None)

    def version_allowed(self, ip, version_allow):
        """
        If we don't know the version for this ip, allow.
        If we know, check
        """
        if ip not in self.ip_to_mainnet:
            return True
        return self.ip_to_mainnet[ip] in version_allow

    def peers_test(self, file, peerdict: dict, strict=True):
        """Validates then adds a peer to the peer list on disk"""
        # Optimization: Early exit and batch processing
        self.peerlist_updated = False
        try:
            with open(file, "r") as peer_file:
                peers_pairs = json.load(peer_file)

            # Optimization: Pre-filter peers to test
            peers_to_test = [(ip, port) for ip, port in peerdict.items()
                            if ip not in peers_pairs]

            if not peers_to_test:
                self.app_log.warning(f"{file} peerlist update skipped, no new peers")
                return

            # Batch test peers
            for ip, port in peers_to_test:
                if self.node.IS_STOPPING:
                    return

                try:
                    self.app_log.info(f"Testing connectivity to: {ip}:{port}")
                    s = socks.socksocket()
                    try:
                        s.settimeout(5)
                        if self.config.tor:
                            s.setproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
                        if strict:
                            s.connect((ip, int(port)))
                            connections.send(s, "getversion")
                            versiongot = connections.receive(s, timeout=1)
                            if versiongot == "*":
                                raise ValueError("peer busy")
                            if versiongot not in self.config.version_allow:
                                raise ValueError(f"cannot save {ip}, incompatible protocol version {versiongot} "
                                               f"not in {self.config.version_allow}")
                            self.app_log.info(f"Inbound: Distant peer {ip}:{port} responding: {versiongot}")
                        else:
                            s.connect((ip, int(port)))
                    finally:
                        try:
                            s.close()
                        except:
                            pass
                    peers_pairs[ip] = port
                    self.app_log.info(f"Inbound: Peer {ip}:{port} saved to peers")
                    self.peerlist_updated = True

                except Exception as e:
                    self.app_log.info(f"Inbound: Distant peer not connectible ({e})")

            if self.peerlist_updated:
                self.app_log.warning(f"{file} peerlist updated ({len(peers_pairs)}) total")
                # Optimization: Use atomic write
                with open(f"{file}.tmp", "w") as peer_file:
                    json.dump(peers_pairs, peer_file)
                shutil.move(f"{file}.tmp", file)

        except Exception as e:
            self.app_log.info(f"Error reading {file}: '{e}'")

    def append_client(self, client):
        """
        :param client: a string "ip:port"
        :return:
        """
        self.connection_pool.append(client)
        self._connection_pool_set.add(client)  # Optimization: maintain set
        self.del_try(client)

    def remove_client(self, client):
        if client in self._connection_pool_set:  # Optimization: O(1) lookup
            try:
                self.app_log.info(f"Will remove {client} from active pool")
                self.connection_pool.remove(client)
                self._connection_pool_set.discard(client)  # Optimization: maintain set
            except:
                raise

    def unban(self, peer_ip):
        """Removes the peer_ip from the warning list"""
        if peer_ip in self._warning_counts:  # Optimization: use Counter
            del self._warning_counts[peer_ip]
            # Also clean from warning_list for compatibility
            self.warning_list = [ip for ip in self.warning_list if ip != peer_ip]
            self.app_log.warning(f"Removed a warning for {peer_ip}")

    def warning(self, sdef, ip, reason, count):
        """Adds a weighted warning to a peer."""
        if ip not in self.whitelist:
            # Optimization: Use Counter instead of list
            self._warning_counts[ip] += count
            # Maintain warning_list for compatibility
            for _ in range(count):
                self.warning_list.append(ip)

            current_warnings = self._warning_counts[ip]
            self.app_log.warning(f"Added {count} warning(s) to {ip}: {reason} "
                               f"({current_warnings} / {self.ban_threshold})")

            if current_warnings >= self.ban_threshold:
                self.banlist.append(ip)
                self.app_log.warning(f"{ip} is banned: {reason}")
                return True
            else:
                return False

    def peers_get(self, peer_file=''):
        """Returns a peer_file from disk as a dict {ip:port}"""
        peer_dict = {}
        try:
            if not peer_file:
                peer_file = self.peerfile
            if not os.path.exists(peer_file):
                with open(peer_file, "w") as fp:
                    self.app_log.warning("Peer file created")
                    fp.write("{}")
            else:
                with open(peer_file, "r") as fp:
                    peer_dict = json.load(fp)
        except Exception as e:
            self.app_log.warning(f"Error peers_get {e} reading {peer_file}")
        return peer_dict

    def peer_list_disk_format(self):
        """Returns a peerfile as is, simple text format or json, as it is on disk"""
        with open(self.peerfile, "r") as peer_list:
            peers = peer_list.read()
        return peers

    @property
    def consensus_most_common(self):
        """Consensus vote"""
        try:
            return most_common_dict(self.peer_opinion_dict)
        except:
            return 0

    @property
    def consensus_max(self):
        try:
            return max(self.peer_opinion_dict.values())
        except:
            return 0

    @property
    def consensus_size(self):
        """Number of nodes in consensus"""
        return len(self.peer_opinion_dict)

    def is_allowed(self, peer_ip, command=''):
        """Tells if the given peer is allowed for that command"""
        # Optimization: Early returns for common cases
        if command == 'block' and self.is_whitelisted(peer_ip):
            return True
        if command == 'portget':
            return True
        if command in ('stop', 'addpeers'):
            return peer_ip == '127.0.0.1'
        return peer_ip in self.config.allowed or "any" in self.config.allowed

    def is_whitelisted(self, peer_ip, command=''):
        return peer_ip in self.whitelist or peer_ip == "127.0.0.1"

    def is_banned(self, peer_ip) -> bool:
        return peer_ip in self.banlist

    def dict_validate(self, json_dict: str) -> str:
        """temporary fix for broken peerlists"""
        if json_dict.count("}") > 1:
            result = json_dict.split("}")[0] + "}"
        else:
            result = json_dict
        return result

    def peersync(self, subdata: str) -> int:
        """Got a peers list from a peer, process. From worker().
        returns the number of added peers, -1 if it was locked or not accepting new peers
        subdata is a dict, { 'ip': 'port'}"""
        if not self.config.accept_peers:
            return -1
        if self.peersync_lock.locked():
            self.app_log.info("Outbound: Peer sync occupied")
            return -1

        # Type enforcement
        if type(subdata) == dict:
            self.app_log.warning("Enforced expected type for peersync subdata")
            subdata = json.dumps(subdata)

        with self.peersync_lock:
            try:
                total_added = 0
                subdata = self.dict_validate(subdata)
                data_dict = json.loads(subdata)

                self.app_log.info(f"Received {len(data_dict)} peers.")

                # Optimization: Batch process new peers
                new_peers = {ip: port for ip, port in data_dict.items()
                           if ip not in self.peer_dict}

                for ip, port in new_peers.items():
                    self.app_log.info(f"Outbound: {ip}:{port} is a new peer, saving if connectible")
                    try:
                        s_purge = socks.socksocket()
                        s_purge.settimeout(5)
                        if self.config.tor:
                            s_purge.setproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
                        s_purge.connect((ip, int(port)))
                        s_purge.close()

                        if ip not in self.peer_dict:
                            total_added += 1
                            self.peer_dict[ip] = port
                            self.app_log.info(f"Inbound: Peer {ip}:{port} saved to local peers")
                    except:
                        self.app_log.info("Not connectible")
            except Exception as e:
                self.app_log.warning(e)
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                raise
        return total_added

    def consensus_add(self, peer_ip, consensus_blockheight, sdef, last_block):
        # Optimization: Early exit for too old blocks
        too_old = last_block - 720

        if peer_ip not in self.peer_opinion_dict and consensus_blockheight < too_old:
            self.app_log.warning(f"{peer_ip} received block too old ({consensus_blockheight}) for consensus")
            return

        try:
            self.app_log.info(f"Updating {peer_ip} in consensus")
            self.peer_opinion_dict[peer_ip] = consensus_blockheight

            self.consensus = most_common_dict(self.peer_opinion_dict)
            self.consensus_percentage = percentage_in(self.peer_opinion_dict[peer_ip],
                                                     self.peer_opinion_dict.values())

            if (int(consensus_blockheight) > int(self.consensus) + 30 and
                self.consensus_percentage > 50 and
                len(self.peer_opinion_dict) > 10):
                if self.warning(sdef, peer_ip, f"Consensus deviation too high, {peer_ip} banned", 10):
                    return

        except Exception as e:
            self.app_log.warning(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            raise

    def consensus_remove(self, peer_ip):
        if peer_ip in self.peer_opinion_dict:
            try:
                self.app_log.info(f"Will remove {peer_ip} from consensus pool {self.peer_opinion_dict}")
                self.peer_opinion_dict.pop(peer_ip)
            except:
                raise

    def can_connect_to(self, host, port):
        """
        Tells if we can connect to this host
        :param host:
        :param port:
        :return:
        """
        # Optimization: Early exits for common cases
        if host in self.banlist:
            return False

        host_port = f"{host}:{port}"

        # Optimization: Use set for O(1) lookup
        if host_port in self._connection_pool_set:
            return False

        # Check timeout
        tries, timeout = self.tried.get(host_port, (0, 0))
        if timeout > time():
            return False

        if self.is_whitelisted(host):
            return True

        # Optimization: Cache C-class extraction
        if host not in self._c_class_cache:
            self._c_class_cache[host] = '.'.join(host.split('.')[:-1]) + '.'
        c_class = self._c_class_cache[host]

        # Optimization: Use generator expression for efficiency
        matching_count = sum(1 for ip_port in self._connection_pool_set if c_class in ip_port)

        if matching_count >= 2:
            self.app_log.warning(f"Ignoring {host_port} since we already have 2 ips of that C Class in our pool.")
            return False

        return True

    def add_try(self, host, port):
        """
        Add the host to the tried dict with matching timeout depending on its state.
        :param host:
        :param port:
        :return:
        """
        host_port = f"{host}:{port}"
        tries, _ = self.tried.get(host_port, (0, 0))

        # Optimization: Use lookup table for delays
        delay_map = {0: 30, 1: 5*60, 2: 15*60}
        delay = delay_map.get(tries, 30*60)

        tries = min(tries + 1, 3)
        self.tried[host_port] = (tries, time() + delay)
        self.app_log.info(f"Set timeout {delay} try {tries} for {host_port}")

    def del_try(self, host, port=None):
        """
        Remove the peer from tried list. To be called when we successfully connected.
        :param host: an ip as a string, or an "ip:port" string
        :param port: optional, port as an int
        :return:
        """
        try:
            host_port = f"{host}:{port}" if port else host
            self.tried.pop(host_port, None)  # Optimization: Use pop with default
        except Exception as e:
            print(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

    def reset_tried(self):
        """
        Remove the older timeouts from the tried list.
        Keep the recent ones or we end up trying the first ones again and again
        """
        limit = time() + 12*60
        # Optimization: Dict comprehension instead of multiple deletions
        self.tried = {client: data for client, data in self.tried.items()
                     if data[1] <= limit}

    def client_loop(self, node, this_target):
        """Manager loop called every 30 sec. Handles maintenance"""
        try:
            # Optimization: Cache peer_dict for iteration
            current_peers = dict(self.dict_shuffle(self.peer_dict))

            for host, value in current_peers.items():
                port = int(value)

                if self.is_testnet:
                    port = 2829

                if threading.active_count() / 3 < self.config.thread_limit and self.can_connect_to(host, port):
                    self.app_log.info(f"Will attempt to connect to {host}:{port}")
                    self.add_try(host, port)
                    t = threading.Thread(target=this_target, args=(host, port, node),
                                        name=f"out_{host}_{port}")
                    self.app_log.info(f"---Starting a client thread {threading.currentThread()} ---")
                    t.daemon = True
                    t.start()

            # Optimization: Use cached values for repeated checks
            pool_size = len(self._connection_pool_set)
            time_since_start = time() - self.startup_time

            if len(self.peer_dict) < 6 and time_since_start > 30:
                self.app_log.warning("Not enough peers in consensus, joining in peers suggested by other nodes")
                self.peer_dict.update(self.peers_get(self.suggested_peerfile))

            if pool_size < self.config.nodes_ban_reset and time_since_start > 15:
                self.app_log.warning(f"Only {pool_size} connections active, resetting banlist")
                self.banlist[:] = self.config.banlist
                self.warning_list.clear()
                self._warning_counts.clear()

            if pool_size < 10:
                self.app_log.warning(f"Only {pool_size} connections active, resetting the connection history")
                self.reset_tried()

            ban_size = len(self.banlist)
            if (self.config.nodes_ban_reset <= ban_size and
                pool_size <= ban_size and
                (time() - self.reset_time) > 600):
                self.app_log.warning(f"Less active connections ({pool_size}) than banlist ({ban_size}), "
                                   f"resetting banlist and tried list")
                self.banlist[:] = self.config.banlist
                self.warning_list.clear()
                self._warning_counts.clear()
                self.reset_tried()
                self.reset_time = time()

            self.app_log.warning("Status: Testing peers")
            self.peer_dict.update(self.peers_get(self.peerfile))

            # Testing peers
            self.peers_test(self.suggested_peerfile, self.peer_dict, strict=False)
            self.peers_test(self.peerfile, self.peer_dict, strict=True)

        except Exception as e:
            self.app_log.warning(f"Status: peers client loop skipped due to error: {e}")

    def status_log(self):
        """Prints the peers part of the node status"""
        if self.banlist:
            self.app_log.warning(f"Status: Banlist: {self.banlist}")
            self.app_log.warning(f"Status: Banlist Count : {len(self.banlist)}")
        if self.whitelist:
            self.app_log.warning(f"Status: Whitelist: {self.whitelist}")

        self.app_log.warning(f"Status: Known Peers: {len(self.peer_dict)}")
        self.app_log.info(f"Status: Tried: {self.tried}")
        self.app_log.info(f"Status: Tried Count: {len(self.tried)}")
        self.app_log.info(f"Status: List of Outbound connections: {self.connection_pool}")
        self.app_log.warning(f"Status: Number of Outbound connections: {len(self.connection_pool)}")
        if self.consensus:
            self.app_log.warning(f"Status: Consensus height: {self.consensus} = {self.consensus_percentage}%")
            self.app_log.warning(f"Status: Last block opinion: {self.peer_opinion_dict}")
            self.app_log.warning(f"Status: Total number of nodes: {len(self.peer_opinion_dict)}")