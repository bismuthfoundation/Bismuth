"""
Peers handler module for Bismuth nodes
@EggPoolNet
"""

import json
import os
import shutil
import sys
import threading
from time import time
from typing import TYPE_CHECKING

import socks

from libs import connections
from libs.clientworker import client_worker
from libs.essentials import most_common_dict, percentage_in
from libs.helpers import dict_shuffle

if TYPE_CHECKING:
    from libs.node import Node

__version__ = "0.0.25"


class Peers:
    """The peers manager. A thread safe peers manager"""

    __slots__ = ('app_log', 'config', 'logstats', 'node', 'peersync_lock', 'startup_time', 'reset_time', 'warning_list',
                 'stats', 'connection_pool', 'peer_opinion_dict', 'consensus_percentage', 'consensus',
                 'tried', 'peer_dict', 'peerfile', 'suggested_peerfile', 'banlist', 'whitelist', 'ban_threshold',
                 'ip_to_mainnet', 'peers', 'accept_peers', 'peerlist_updated', 'peers_log', 'status_log')

    def __init__(self, node: "Node", logstats: bool =True):
        self.app_log = node.logger.app_log
        self.peers_log = node.logger.peers_log
        self.status_log = node.logger.status_log
        self.config = node.config
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
        # We store them apart from the initial config, could diverge somehow later on.
        self.banlist = node.config.banlist
        self.whitelist = node.config.whitelist
        self.ban_threshold = node.config.ban_threshold
        self.accept_peers = node.config.accept_peers
        self.node = node
        self.peerfile = node.peerfile
        self.suggested_peerfile = node.peerfile_suggested
        self.peerlist_updated = False

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

    def status_dict(self) -> dict:
        """Returns a status as a dict"""
        status = {"version": self.config.VERSION, "stats": self.stats}
        return status

    def store_mainnet(self, ip: str, version: str) -> None:
        """Stores the mainnet version of a peer. Can't change unless reconnects"""
        self.ip_to_mainnet[ip] = version

    def forget_mainnet(self, ip: str) -> None:
        """Peers disconnected, forget his mainnet version"""
        self.ip_to_mainnet.pop(ip, None)

    def version_allowed(self, ip: str, version_allow: str) -> bool:
        """
        If we don't know the version for this ip, allow.
        If we know, check
        """
        if ip not in self.ip_to_mainnet:
            return True
        return self.ip_to_mainnet[ip] in version_allow

    def peers_test(self, file: str, peerdict: dict, strict: bool=True) -> None:
        """Validates then adds a peer to the peer list on disk"""
        # called by Sync, should not be an issue, but check if needs to be thread safe or not.
        # also called by self.client_loop, which is to be reworked
        # Egg: Needs to be thread safe.
        self.peerlist_updated = False
        try:
            with open(file, "r") as peer_file:
                peers_pairs = json.load(peer_file)
            # TODO: rework, because this takes too much time and freezes the status thread.
            # to be done in a dedicated thread, with one peer per xx seconds, not all at once, and added properties.
            for ip, port in dict(peerdict).items():
                # I do create a new dict copy above, because logs showed that the dict can change while iterating
                if self.node.IS_STOPPING:
                    # Early exit if stopping
                    return
                try:
                    if ip not in peers_pairs:
                        self.peers_log.debug(f"Testing connectivity to: {ip}:{port}")
                        s = socks.socksocket()
                        try:
                            # connect timeout
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
                                self.peers_log.debug(f"Inbound: Distant peer {ip}:{port} responding: {versiongot}")
                            else:
                                s.connect((ip, int(port)))
                        finally:
                            # properly end the connection in all cases
                            try:
                                s.close()
                            except Exception:
                                pass
                        peers_pairs[ip] = port
                        self.peers_log.debug(f"Inbound: Peer {ip}:{port} saved to peers")
                        self.peerlist_updated = True
                    else:
                        self.peers_log.debug("Distant peer {ip}:{port} already in peers")

                except Exception as e:
                    # exception for a single peer - This is not an error, it's ok to have unreachable peers.
                    self.peers_log.debug(f"Inbound: Distant peer {ip}:{port} not connectible ({e})")

            if self.peerlist_updated:
                self.peers_log.info(f"{file} peerlist updated ({len(peers_pairs)}) total")  # the whole dict is saved
                with open(f"{file}.tmp", "w") as peer_file:
                    json.dump(peers_pairs, peer_file)
                shutil.move(f"{file}.tmp", file)
            else:
                self.peers_log.debug(f"{file} peerlist update skipped, no changes")

        except Exception as e:
            # Exception for the file itself.
            self.peers_log.error(f"Error reading {file}: '{e}'")

    def append_client(self, client: str) -> None:
        """
        :param client: a string "ip:port"
        :return:
        """
        # TODO: thread safe?
        self.connection_pool.append(client)
        self.del_try(client)

    def remove_client(self, client: str) -> None:
        # TODO: thread safe?
        if client in self.connection_pool:
            try:
                self.peers_log.info(f"Will remove {client} from active pool")
                self.connection_pool.remove(client)
            except Exception:
                raise

    def unban(self, peer_ip: str) -> None:
        """Removes the peer_ip from the warning list"""
        # TODO: Not thread safe atm. Should use a thread aware list or some lock
        if peer_ip in self.warning_list:
            self.warning_list.remove(peer_ip)
            self.peers_log.info(f"Removed a warning for {peer_ip}")

    def warning(self, sdef, ip: str, reason: str, count: int) -> bool:
        """Adds a weighted warning to a peer.
        Returns whether the peer ends up banned or not."""
        # TODO: Not thread safe atm. Should use a thread aware list or some lock
        if ip not in self.whitelist:
            # TODO: use a dict instead of several occurrences in a list
            for x in range(count):
                self.warning_list.append(ip)
            self.peers_log.info(f"Added {count} warning(s) to {ip}: {reason} "
                                f"({self.warning_list.count(ip)} / {self.ban_threshold})")
            if self.warning_list.count(ip) >= self.ban_threshold:
                self.banlist.append(ip)
                self.peers_log.warning(f"{ip} is banned: {reason}")
                return True
            else:
                return False

    def peers_get(self, peer_file: str='') -> dict:
        """Returns a peer_file from disk as a dict {ip:port}"""
        peer_dict = {}
        try:
            if not peer_file:
                peer_file = self.peerfile
            if not os.path.exists(peer_file):
                with open(peer_file, "w") as fp:
                    # was "a": append would risk adding stuff to a file create in the mean time.
                    self.peers_log.info("Peer file created")
                    fp.write("{}")  # empty dict. An empty string is not json valid.
            else:
                with open(peer_file, "r") as fp:
                    peer_dict = json.load(fp)
        except Exception as e:
            self.peers_log.error(f"Error peers_get {e} reading {peer_file}")
        return peer_dict

    def peer_list_disk_format(self):
        """Returns a peerfile as is, simple text format or json, as it is on disk"""
        # TODO: caching and format to handle here
        with open(self.peerfile, "r") as peer_list:
            peers = peer_list.read()
        return peers

    @property
    def consensus_most_common(self):
        """Consensus vote"""
        try:
            return most_common_dict(self.peer_opinion_dict)
        except Exception:
            # no consensus yet
            return 0

    @property
    def consensus_max(self) -> int:
        try:
            return max(self.peer_opinion_dict.values())
        except Exception:
            # no consensus yet
            return 0

    @property
    def consensus_size(self) -> int:
        """Number of nodes in consensus"""
        return len(self.peer_opinion_dict)

    def is_allowed(self, peer_ip: str, command: str='', silent: bool=False) -> bool:
        """Tells if the given peer is allowed for that command"""
        # TODO: more granularity here later
        # Always allow whitelisted ip to post as block
        if 'block' == command and self.is_whitelisted(peer_ip):
            return True
        # always allowed commands, only required and non cpu intensive.
        if command in ('portget',):
            return True
        # only allow local host for "stop" and addpeers command
        if command in ('stop', 'addpeers'):
            if peer_ip == '127.0.0.1':
                return True
        if self.config.allowed is True:
            return True
        if "any" in self.config.allowed or "any" == self.config.allowed:
            return True
        if peer_ip in self.config.allowed:
            return True
        self.peers_log.warning(f"{peer_ip} not whitelisted for {command} command")
        return False

    def is_whitelisted(self, peer_ip: str, command: str='') -> bool:
        # TODO: could be handled later on via "allowed" and rights.
        return peer_ip in self.whitelist or "127.0.0.1" == peer_ip

    def is_banned(self, peer_ip: str) -> bool:
        return peer_ip in self.banlist

    def dict_validate(self, json_dict: str) -> str:
        """temporary fix for broken peerlists"""
        if json_dict.count("}") > 1:
            result = json_dict.split("}")[0] + "}"
        else:
            result = json_dict
        return result

    def peersync(self, subdata: str, host: str="") -> int:
        """Got a peers list from a peer, process. From worker().
        returns the number of added peers, -1 if it was locked or not accepting new peers
        subdata is a dict, { 'ip': 'port'}
        host is only used for logging."""
        # early exit to reduce future levels
        if not self.config.accept_peers:
            return -1
        if self.peersync_lock.locked():
            # TODO: means we will lose those peers forever.
            # Not critical in practice, but better buffer and keep track of recently tested peers.
            self.peers_log.debug("Outbound: Peer sync occupied")
            return -1
        # Temp fix: subdata is typed str, but we have a dict sometimes.
        if type(subdata) == dict:
            # Enforce expected type.
            self.peers_log.debug("Enforced expected type for peersync subdata")
            subdata = json.dumps(subdata)
        with self.peersync_lock:
            try:
                total_added = 0

                subdata = self.dict_validate(subdata)
                data_dict = json.loads(subdata)

                self.peers_log.info(f"Received {len(data_dict)} peers from {host}.")
                # Simplified the log, every peers then has a ok or ko status anyway.
                for ip, port in data_dict.items():
                    if ip not in self.peer_dict:
                        self.peers_log.debug(f"Outbound: {ip}:{port} is a new peer, saving if connectible")
                        try:
                            s_purge = socks.socksocket()
                            s_purge.settimeout(5)
                            if self.config.tor:
                                s_purge.setproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
                            s_purge.connect((ip, int(port)))  # save a new peer file with only active nodes
                            s_purge.close()
                            # This only adds to our local dict, does not force save.
                            if ip not in self.peer_dict:
                                total_added += 1
                                self.peer_dict[ip] = port
                                self.peers_log.debug(f"Inbound: Peer {ip}:{port} saved to local peers")
                        except Exception:
                            self.peers_log.debug(f" {ip}:{port} is not connectible")
                    else:
                        self.peers_log.debug(f"Outbound: {ip}:{port} is not a new peer")
            except Exception as e:
                self.peers_log.warning(e)
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                raise
        return total_added

    def consensus_add(self, peer_ip: str, consensus_blockheight: int, sdef, last_block: int) -> None:
        # obviously too old blocks, we have half a day worth of validated blocks after them
        # no ban, they can (should) be syncing but they can't possibly be in consensus list.
        too_old = last_block - 720
        try:
            if peer_ip not in self.peer_opinion_dict:
                if consensus_blockheight < too_old:
                    self.peers_log.warning(f"{peer_ip} received block too old ({consensus_blockheight}) for consensus")
                    return

            self.peers_log.debug(f"Updating {peer_ip} in consensus")
            self.peer_opinion_dict[peer_ip] = consensus_blockheight

            self.consensus = most_common_dict(self.peer_opinion_dict)
            self.consensus_percentage = percentage_in(self.peer_opinion_dict[peer_ip], self.peer_opinion_dict.values())

            if int(consensus_blockheight) > int(self.consensus) + 30 and self.consensus_percentage > 50 \
                    and len(self.peer_opinion_dict) > 10:
                self.warning(sdef, peer_ip, f"Consensus deviation too high, {peer_ip} banned", 10)

        except Exception as e:
            self.peers_log.warning(e, )
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            raise

    def consensus_remove(self, peer_ip: str) -> None:
        if peer_ip in self.peer_opinion_dict:
            self.peers_log.debug(f"Will remove {peer_ip} from consensus pool {self.peer_opinion_dict}")
            self.peer_opinion_dict.pop(peer_ip)

    def can_connect_to(self, host: str, port: int) -> bool:
        """
        Tells if we can connect to this host
        :param host:
        :param port:
        :return:
        """
        if host in self.banlist:
            return False  # Banned IP
        host_port = f"{host}:{port}"
        if host_port in self.connection_pool:
            return False  # Already connected to
        try:
            tries, timeout = self.tried[host_port]
        except Exception:
            tries, timeout = 0, 0  # unknown host for now, never tried.
        if timeout > time():
            self.peers_log.info(f"Ignoring {host_port} because of timeout {time()-timeout:0.0f} remaining")
            return False  # We tried before, timeout is not expired.
        if self.is_whitelisted(host):
            return True  # whitelisted peers are always connectible, without variability condition.
        # variability test.
        c_class = '.'.join(host.split('.')[:-1]) + '.'
        matching = [ip_port for ip_port in self.connection_pool if c_class in ip_port]
        # If we already have 2 peers from that C ip class in our connection pool, ignore.
        if len(matching) >= 2:
            # Temp debug
            self.peers_log.warning(f"Ignoring {host_port} since we already have 2 ips of that C Class in our pool.")
            return False
        # Else we can
        return True

    def add_try(self, host: str, port: int) -> None:
        """
        Add the host to the tried dict with matching timeout depending on its state.
        :param host:
        :param port:
        :return:
        """
        host_port = f"{host}:{port}"
        try:
            tries, timeout = self.tried[host_port]
        except Exception:
            tries, timeout = 0, 0
        if tries <= 0:  # First time can be temp, retry again
            delay = 30
        elif tries == 1:  # second time, give it 5 minutes
            delay = 5*60
        elif tries == 2:  # third time, give it 15 minutes
            delay = 15 * 60
        else:  # 30 minutes before trying again
            delay = 30*60
        tries += 1
        if tries > 3:
            tries = 3
        self.tried[host_port] = (tries, time() + delay)
        # Temp
        self.peers_log.info(f"Set timeout {delay} try {tries} for {host_port}")

    def del_try(self, host: str, port=None) -> None:
        """
        Remove the peer from tried list. To be called when we successfully connected.
        :param host: an ip as a string, or an "ip:port" string
        :param port: optional, port as an int
        :return:
        """
        try:
            if port:
                host_port = f"{host}:{port}"
            else:
                host_port = host
            if host_port in self.tried:
                del self.tried[host_port]
        except Exception as e:
            print(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

    def reset_tried(self) -> None:
        """
        Remove the older timeouts from the tried list.
        Keep the recent ones or we end up trying the first ones again and again
        """
        limit = time() + 12*60  # matches 2.5 tries :)
        remove = [client for client in self.tried if self.tried[client][1] > limit]
        for client in remove:
            del self.tried[client]

    def client_loop(self, node: "Node") -> None:
        """Manager loop called every 30 sec. Handles maintenance"""
        try:
            for key, value in dict(dict_shuffle(self.peer_dict)).items():
                # Important: The dict() above is not an error nor a cast,
                # it's to make a copy of the dict and avoid "dictionary changed size during iteration"
                host = key
                port = int(value)

                if self.is_testnet:
                    port = 2829
                if threading.active_count() / 3 < self.config.thread_limit and self.can_connect_to(host, port):
                    self.peers_log.info(f"Will attempt to connect to {host}:{port}")
                    self.add_try(host, port)
                    t = threading.Thread(target=client_worker, args=(host, port, node), name=f"out_{host}_{port}")
                    self.peers_log.debug(f"---Starting a client thread {threading.currentThread()} ---")
                    t.daemon = True
                    t.start()

            if len(self.peer_dict) < 6 and int(time() - self.startup_time) > 30:
                # join in random peers after x seconds
                self.peers_log.warning("Not enough peers in consensus, joining in peers suggested by other nodes")
                self.peer_dict.update(self.peers_get(self.suggested_peerfile))

            if len(self.connection_pool) < self.config.nodes_ban_reset and int(time() - self.startup_time) > 15:
                # do not reset before 30 secs have passed
                self.peers_log.warning(f"Only {len(self.connection_pool)} connections active, resetting banlist")
                del self.banlist[:]
                self.banlist.extend(self.config.banlist)  # reset to config version
                del self.warning_list[:]

            if len(self.connection_pool) < 10:
                self.peers_log.warning(f"Only {len(self.connection_pool)} connections active, "
                                       f"resetting the connection history")
                # TODO: only reset large timeouts, or we end up trying the sames over and over if we never get to 10.
                # self.
                self.reset_tried()

            if self.config.nodes_ban_reset <= len(self.banlist) and len(self.connection_pool) <= len(self.banlist) \
                    and (time() - self.reset_time) > 60 * 10:
                # do not reset too often. 10 minutes here
                self.peers_log.warning(f"Less active connections ({len(self.connection_pool)}) "
                                       f"than banlist ({len(self.banlist)}), resetting banlist and tried list")
                del self.banlist[:]
                self.banlist.extend(self.config.banlist)  # reset to config version
                del self.warning_list[:]
                self.reset_tried()
                self.reset_time = time()

            self.status_log.debug("Testing peers")
            self.peer_dict.update(self.peers_get(self.peerfile))

            # TODO: this is not OK. client_loop is called every 30 sec and should NOT contain any lengthy calls.
            self.peers_test(self.suggested_peerfile, self.peer_dict, strict=False)
            self.peers_test(self.peerfile, self.peer_dict, strict=True)

        except Exception as e:
            self.peers_log.warning(f"Peers client loop skipped due to error: {e}")
            # raise
            """We do not want to raise here, since the rest of the calling method would be skipped also.
            It's ok to skip this part only
            The calling method has other important subsequent calls that have to be done.
            """

    def print_status_log(self) -> None:
        """Prints the peers part of the node status"""
        # TODO: Aggregate to use less lines
        banlist_len = 0
        whitelist_len = 0

        if self.banlist:
            # self.status_log.info(f"Peers: Banlist Count: {len(self.banlist)}")
            banlist_len = len(self.banlist)
            self.status_log.debug(f"Peers: Banlist: {self.banlist}")
        if self.whitelist:
            # self.status_log.info(f"Peers: Whitelist Count: {len(self.whitelist)}")
            whitelist_len = len(self.whitelist)
            self.status_log.debug(f"Peers: Whitelist: {self.whitelist}")

        self.status_log.info(f"Peers count: {len(self.peer_dict)} - banlist {banlist_len} - whitelist {whitelist_len}")
        self.status_log.debug(f"Known Peers: {self.peer_dict}")

        self.status_log.info(f"Tried PeersCount: {len(self.tried)} - outbound {len(self.connection_pool)}")
        self.status_log.debug(f"Tried peers: {self.tried}")
        self.status_log.debug(f"Peers: List of Outbound connections: {self.connection_pool}")
        if self.consensus:  # once the consensus is filled
            self.status_log.info(f"Consensus height: {self.consensus} = {self.consensus_percentage:0.2f}% "
                                 f"- {len(self.peer_opinion_dict)} Nodes ")
            self.status_log.debug(f"Last block opinion: {self.peer_opinion_dict}")
